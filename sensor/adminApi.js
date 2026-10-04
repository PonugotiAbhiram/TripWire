/**
 * sensor/adminApi.js
 * 
 * Admin API Server (Port 3000 - Local Only)
 * ----------------------------------------
 * Provides administrative REST endpoints to view captured attack logs,
 * attacker threat assessments, IP timelines, and global security metrics.
 * 
 * Bound strictly to 127.0.0.1.
 */

const express = require('express');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');
const analyzer = require('./analyzer');
const severity = require('./severity');
const createRateLimiter = require('./rateLimit');
const bans = require('./bans');

const app = express();

app.disable('x-powered-by');
app.use(express.json());

// 1. Password hashing setup
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
let startupHash = null;
const passwordSalt = crypto.randomBytes(16);
if (ADMIN_PASSWORD && ADMIN_PASSWORD.length >= 12) {
  startupHash = crypto.scryptSync(ADMIN_PASSWORD, passwordSalt, 64);
}

// 2. Host Header Check
app.use((req, res, next) => {
  const host = req.headers.host || '';
  const allowedHosts = ['127.0.0.1:3000', 'localhost:3000'];
  if (process.env.ADMIN_ALLOWED_HOSTS) {
    allowedHosts.push(...process.env.ADMIN_ALLOWED_HOSTS.split(',').map(s => s.trim()));
  }
  if (!allowedHosts.includes(host)) {
    return res.status(400).json({ error: 'invalid host' });
  }
  next();
});

// 3. Origin Check for POST
app.use((req, res, next) => {
  if (req.method === 'POST') {
    const origin = req.headers.origin;
    if (origin) {
      let originHost = '';
      try { originHost = new URL(origin).host; } catch (e) {}
      if (originHost !== req.headers.host) {
        return res.status(403).json({ error: 'invalid origin' });
      }
    }
  }
  next();
});

// 4. Session Parsing
const sessions = new Map();
const SESSION_IDLE_TIMEOUT = 30 * 60 * 1000;
const SESSION_MAX_LIFETIME = 8 * 60 * 60 * 1000;
const limiter = createRateLimiter();

function parseCookies(cookieStr) {
  const cookies = {};
  if (!cookieStr) return cookies;
  cookieStr.split(';').forEach(c => {
    const parts = c.split('=');
    if (parts.length >= 2) {
      cookies[parts.shift().trim()] = decodeURI(parts.join('='));
    }
  });
  return cookies;
}

app.use((req, res, next) => {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.tw_session;
  req.session = null;
  req.sessionToken = token;
  
  if (token && sessions.has(token)) {
    const sess = sessions.get(token);
    const now = Date.now();
    if (now - sess.lastSeen > SESSION_IDLE_TIMEOUT || now - sess.createdAt > SESSION_MAX_LIFETIME) {
      sessions.delete(token);
    } else {
      sess.lastSeen = now;
      req.session = sess;
    }
  }
  next();
});

// 5. Apply headers
app.use('/api', (req, res, next) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use((req, res, next) => {
  if (!req.path.startsWith('/api')) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
  }
  next();
});

// 6. Login/Logout/Session endpoints
app.post('/api/login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (limiter.isBlocked(ip)) {
    return res.status(429).set('Retry-After', '900').json({ error: 'too many attempts' });
  }

  const { password } = req.body;
  if (!password || typeof password !== 'string') {
    limiter.addFail(ip);
    console.log(`[!] Failed admin login from ${ip}`);
    return res.status(401).json({ error: 'invalid password' });
  }

  const attemptHash = crypto.scryptSync(password, passwordSalt, 64);
  if (!startupHash || !crypto.timingSafeEqual(attemptHash, startupHash)) {
    limiter.addFail(ip);
    console.log(`[!] Failed admin login from ${ip}`);
    return res.status(401).json({ error: 'invalid password' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const csrf = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { createdAt: Date.now(), lastSeen: Date.now(), csrf });
  
  let cookieHeader = `tw_session=${token}; HttpOnly; SameSite=Strict; Path=/`;
  if (process.env.COOKIE_SECURE === '1') cookieHeader += '; Secure';
  res.setHeader('Set-Cookie', cookieHeader);
  res.json({ ok: true, csrf });
});

app.post('/api/logout', (req, res) => {
  if (!req.session) return res.status(401).json({ error: 'login required' });
  const csrfHeader = req.headers['x-csrf-token'];
  if (csrfHeader !== req.session.csrf) {
    return res.status(403).json({ error: 'invalid csrf' });
  }
  sessions.delete(req.sessionToken);
  res.setHeader('Set-Cookie', 'tw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/session', (req, res) => {
  if (req.session) {
    res.json({ loggedIn: true, csrf: req.session.csrf });
  } else {
    res.status(401).json({ error: 'not logged in' });
  }
});

// 7. Auth Enforcement
app.use('/api', (req, res, next) => {
  if (!req.session) return res.status(401).json({ error: 'login required' });
  next();
});

app.use((req, res, next) => {
  if (!req.path.startsWith('/api')) {
    const publicFiles = ['/login.html', '/login.js', '/style.css'];
    if (!publicFiles.includes(req.path) && !req.session) {
      return res.redirect(302, '/login.html');
    }
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Prepared SQL statement for GET /api/events
const getLatestEventsStmt = db.prepare(`
  SELECT 
    id, timestamp, source_ip, protocol, port, method, path,
    user_agent, username, password, raw_headers
  FROM events
  ORDER BY id DESC
  LIMIT 100
`);

let cachedAttackersData = null;
let attackersCacheTime = 0;
let cachedStatsData = null;
let statsCacheTime = 0;

function getAttackersCached() {
  const now = Date.now();
  if (cachedAttackersData && (now - attackersCacheTime < 5000)) return cachedAttackersData;

  const recentIps = analyzer.listIps(100);
  const attackers = recentIps.map(ipObj => {
    const assessment = severity.getAssessment(ipObj.source_ip);
    return {
      ip: ipObj.source_ip,
      banned: bans.isBanned(ipObj.source_ip),
      level: assessment ? assessment.level : 'None',
      score: assessment ? assessment.score : 0,
      summary: assessment ? assessment.summary : 'No attack behavior detected',
      labels: assessment ? assessment.labels : [],
      tool_hints: assessment ? assessment.tool_hints : [],
      total_events: ipObj.total_events,
      first_seen: ipObj.first_seen,
      last_seen: ipObj.last_seen
    };
  });

  attackers.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return (b.last_seen || '').localeCompare(a.last_seen || '');
  });

  cachedAttackersData = attackers;
  attackersCacheTime = now;
  return cachedAttackersData;
}

app.get('/api/events', (req, res) => {
  try {
    const rows = getLatestEventsStmt.all();
    const events = rows.map(row => {
      let parsedHeaders = row.raw_headers;
      if (typeof row.raw_headers === 'string') {
        try { parsedHeaders = JSON.parse(row.raw_headers); } catch {}
      }
      return { ...row, raw_headers: parsedHeaders };
    });
    res.json(events);
  } catch (err) {
    console.error('[ADMIN API ERROR]', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

app.get('/api/attackers', (req, res) => {
  try {
    res.json(getAttackersCached());
  } catch (err) {
    console.error('[ADMIN API ERROR]', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

app.get('/api/attackers/:ip', (req, res) => {
  try {
    const ip = req.params.ip;
    if (net.isIP(ip) === 0) return res.status(400).json({ error: 'invalid ip' });

    const profile = analyzer.getProfile(ip);
    if (!profile) return res.status(404).json({ error: 'unknown ip' });

    const assessment = severity.getAssessment(ip);
    const timeline = analyzer.getTimeline(ip, 200);
    const banned = bans.isBanned(ip);
    res.json({ profile, assessment, timeline, banned });
  } catch (err) {
    console.error('[ADMIN API ERROR]', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

app.get('/api/stats', (req, res) => {
  try {
    const now = Date.now();
    if (cachedStatsData && (now - statsCacheTime < 5000)) return res.json(cachedStatsData);

    const attackers = getAttackersCached();
    const levels = { High: 0, Medium: 0, Low: 0, None: 0 };
    for (const a of attackers) {
      if (a.level in levels) levels[a.level]++;
    }

    const twentyFourHoursAgoIso = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    const stats = {
      total_events: analyzer.getTotalEvents(),
      unique_ips: analyzer.getUniqueIps(),
      top_passwords: analyzer.getTopPasswords(10),
      top_usernames: analyzer.getTopUsernames(10),
      events_per_protocol: analyzer.getEventsPerProtocol(),
      events_per_hour: analyzer.getEventsPerHour(twentyFourHoursAgoIso),
      levels
    };

    cachedStatsData = stats;
    statsCacheTime = now;
    res.json(stats);
  } catch (err) {
    console.error('[ADMIN API ERROR]', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

app.get('/api/bans', (req, res) => {
  try {
    res.json(bans.listBans(db));
  } catch (err) {
    res.status(500).json({ error: 'internal error' });
  }
});

app.post('/api/bans', (req, res) => {
  const csrfHeader = req.headers['x-csrf-token'];
  if (csrfHeader !== req.session.csrf) return res.status(403).json({ error: 'invalid csrf' });

  const { ip, reason, hours } = req.body;
  if (!ip) return res.status(400).json({ error: 'missing ip' });

  try {
    const check = bans.canBan(ip);
    if (!check.ok) {
      if (check.reason === 'Invalid IP address') return res.status(400).json({ error: 'invalid ip' });
      return res.status(403).json({ error: 'this address can never be banned' });
    }

    bans.addBan(db, ip, reason, hours);
    console.log(`Banned ${bans.normalizeIp(ip)} for ${hours || 24} hours: ${reason || 'No reason'}`);
    res.status(201).json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/bans/:ip/unban', (req, res) => {
  const csrfHeader = req.headers['x-csrf-token'];
  if (csrfHeader !== req.session.csrf) return res.status(403).json({ error: 'invalid csrf' });

  const ip = req.params.ip;
  if (bans.removeBan(db, ip)) {
    console.log(`Unbanned ${bans.normalizeIp(ip)}`);
    res.json({ ok: true });
  } else {
    res.status(404).json({ error: 'ban not found' });
  }
});

module.exports = app;
