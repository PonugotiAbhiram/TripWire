const net = require('net');

const activeBans = new Map();
let sweepInterval = null;
const blockCounters = new Map();

function normalizeIp(ip) {
  if (!ip || typeof ip !== 'string' || net.isIP(ip) === 0) return null;
  let normalized = ip;
  if (normalized.startsWith('::ffff:')) {
    normalized = normalized.substring(7);
  }
  if (net.isIPv6(normalized)) {
    normalized = normalized.toLowerCase();
  }
  return normalized;
}

function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function canBan(ip) {
  const norm = normalizeIp(ip);
  if (!norm) return { ok: false, reason: 'Invalid IP address' };

  if (norm === '0.0.0.0' || norm === '::') {
    return { ok: false, reason: 'Cannot ban wildcard address' };
  }

  const whitelist = (process.env.WHITELIST || '').split(',').map(s => s.trim()).filter(Boolean);
  if (whitelist.includes(norm)) {
    return { ok: false, reason: 'IP is in whitelist' };
  }

  let isLoopback = false;
  let isPrivate = false;
  let isLinkLocal = false;
  let isMulticast = false;

  if (net.isIPv4(norm)) {
    const longIp = ipToLong(norm);
    if (((longIp & 0xFF000000) >>> 0) === 0x7F000000) isLoopback = true; // 127.0.0.0/8
    if (((longIp & 0xFF000000) >>> 0) === 0x0A000000) isPrivate = true; // 10.0.0.0/8
    if (((longIp & 0xFFF00000) >>> 0) === 0xAC100000) isPrivate = true; // 172.16.0.0/12
    if (((longIp & 0xFFFF0000) >>> 0) === 0xC0A80000) isPrivate = true; // 192.168.0.0/16
    if (((longIp & 0xFFFF0000) >>> 0) === 0xA9FE0000) isLinkLocal = true; // 169.254.0.0/16
    if (((longIp & 0xF0000000) >>> 0) === 0xE0000000) isMulticast = true; // 224.0.0.0/4
  } else {
    if (norm === '::1') isLoopback = true;
    if (norm.startsWith('fe80:')) isLinkLocal = true;
    if (norm.startsWith('ff')) isMulticast = true;
    // IPv6 private (ULA) fc00::/7
    if (norm.startsWith('fc') || norm.startsWith('fd')) isPrivate = true;
  }

  if (isLinkLocal) return { ok: false, reason: 'Cannot ban link-local address' };
  if (isMulticast) return { ok: false, reason: 'Cannot ban multicast address' };

  if ((isLoopback || isPrivate) && process.env.ALLOW_LOCAL_BAN !== '1') {
    return { ok: false, reason: 'Cannot ban loopback or private range without ALLOW_LOCAL_BAN=1' };
  }

  return { ok: true, reason: null };
}

function isBanned(ip) {
  const norm = normalizeIp(ip);
  if (!norm) return false;
  const ban = activeBans.get(norm);
  if (!ban) return false;
  if (Date.now() >= ban.expires_at) {
    return false;
  }
  return true;
}

function loadBans(db) {
  const rows = db.prepare('SELECT ip, reason, created_at, expires_at FROM bans WHERE active = 1').all();
  const now = Date.now();
  for (const row of rows) {
    const expiresMs = new Date(row.expires_at).getTime();
    if (expiresMs > now) {
      activeBans.set(row.ip, {
        reason: row.reason,
        created_at: new Date(row.created_at).getTime(),
        expires_at: expiresMs
      });
    } else {
      db.prepare('UPDATE bans SET active = 0 WHERE ip = ?').run(row.ip);
    }
  }

  if (!sweepInterval) {
    sweepInterval = setInterval(() => sweepBans(db), 60000);
    sweepInterval.unref();
  }
}

function sweepBans(db) {
  const now = Date.now();
  for (const [ip, ban] of activeBans.entries()) {
    if (now >= ban.expires_at) {
      activeBans.delete(ip);
      db.prepare('UPDATE bans SET active = 0 WHERE ip = ?').run(ip);
    }
  }
}

function addBan(db, ip, reason, hours = 24) {
  const norm = normalizeIp(ip);
  if (!norm) throw new Error('Invalid IP');
  
  const check = canBan(norm);
  if (!check.ok) throw new Error(check.reason);

  if (reason && reason.length > 200) {
    throw new Error('Reason cannot exceed 200 characters');
  }
  const safeReason = reason || 'No reason';
  let parsedHours = parseInt(hours, 10);
  if (isNaN(parsedHours) || parsedHours < 1 || parsedHours > 720) {
    throw new Error('Hours must be between 1 and 720');
  }

  const nowMs = Date.now();
  const expiresMs = nowMs + parsedHours * 60 * 60 * 1000;
  const createdStr = new Date(nowMs).toISOString();
  const expiresStr = new Date(expiresMs).toISOString();

  const stmt = db.prepare('INSERT OR REPLACE INTO bans (ip, reason, created_at, expires_at, active) VALUES (?, ?, ?, ?, 1)');
  stmt.run(norm, safeReason, createdStr, expiresStr);

  activeBans.set(norm, {
    reason: safeReason,
    created_at: nowMs,
    expires_at: expiresMs
  });
}

function removeBan(db, ip) {
  const norm = normalizeIp(ip);
  if (!norm) return false;
  const stmt = db.prepare('UPDATE bans SET active = 0 WHERE ip = ?');
  const res = stmt.run(norm);
  if (res.changes > 0 || activeBans.has(norm)) {
    activeBans.delete(norm);
    return true;
  }
  return false;
}

function listBans(db) {
  return db.prepare('SELECT ip, reason, created_at, expires_at FROM bans WHERE active = 1 ORDER BY created_at DESC LIMIT 200').all();
}

function __testClearMap() {
  activeBans.clear();
  blockCounters.clear();
  if (sweepInterval) {
    clearInterval(sweepInterval);
    sweepInterval = null;
  }
}

function checkAndBlock(ip, socketOrReq, protocol, port, db) {
  const norm = normalizeIp(ip);
  if (!norm || !isBanned(norm)) return false;

  if (socketOrReq.destroy) {
    socketOrReq.destroy();
  } else if (socketOrReq.socket && socketOrReq.socket.destroy) {
    socketOrReq.socket.destroy();
  }

  const key = `${norm}_${protocol}_${port}`;
  const now = Date.now();
  let state = blockCounters.get(key) || { lastLog: 0, count: 0 };
  state.count++;

  if (now - state.lastLog >= 60000) {
    const detail = state.count > 1 ? `Dropped ${state.count} blocked connections` : '';
    const isoTime = new Date(now).toISOString();
    db.prepare(`
      INSERT INTO events (timestamp, source_ip, protocol, port, method, path)
      VALUES (?, ?, ?, ?, 'BLOCKED', ?)
    `).run(isoTime, norm, protocol, port, detail);
    
    state.lastLog = now;
    state.count = 0;
  }
  
  blockCounters.set(key, state);
  return true;
}

module.exports = {
  normalizeIp,
  canBan,
  isBanned,
  addBan,
  removeBan,
  listBans,
  loadBans,
  sweepBans,
  checkAndBlock,
  __testClearMap
};
