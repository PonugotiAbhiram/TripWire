/**
 * sensor/reporter.js
 * 
 * Event Reporter Module
 * ---------------------
 * This is the ONLY module in the system responsible for saving or forwarding event logs.
 * It sanitizes attacker input, enforces safety limits (truncating strings & headers),
 * and executes parameterized SQL inserts into the database.
 * 
 * In future steps, this function can be easily modified to POST events to a remote API.
 */

const fs = require('fs');
const path = require('path');
const db = require('./db');
const { createLimiter } = require('./eventLimiter');

function parseEnv(name, def, min) {
  if (process.env[name] !== undefined) {
    const val = parseInt(process.env[name], 10);
    if (!isNaN(val) && val >= min) return val;
    console.warn(`[WARNING] Invalid ${name} '${process.env[name]}', falling back to default ${def}`);
  }
  return def;
}

const EVENT_RATE_PER_IP = parseEnv('EVENT_RATE_PER_IP', 50, 1);
const EVENT_RATE_GLOBAL = parseEnv('EVENT_RATE_GLOBAL', 300, 1);
const MIN_FREE_DISK_MB = parseEnv('MIN_FREE_DISK_MB', 500, 1);
console.log(`[REPORTER] Active limits: EVENT_RATE_PER_IP=${EVENT_RATE_PER_IP}, EVENT_RATE_GLOBAL=${EVENT_RATE_GLOBAL}, MIN_FREE_DISK_MB=${MIN_FREE_DISK_MB}`);

const limiter = createLimiter({
  perIpPerSec: EVENT_RATE_PER_IP,
  globalPerSec: EVENT_RATE_GLOBAL,
  maxIps: 10000
});

let diskLowCount = 0;
let rateIpCount = 0;
let rateGlobalCount = 0;
let write_errors = 0;
let lastDiskCheck = 0;
let isDiskLow = false;
let lastDiskWarning = 0;

let statfsSyncImpl = fs.statfsSync;
function __setStatfsSync(impl) { statfsSyncImpl = impl; }

function __getMetrics() {
  return {
    rows_total: db.getApproximateCount ? db.getApproximateCount() : 0,
    max_rows: db.MAX_EVENT_ROWS || 500000,
    dropped_events: {
      rate_ip: rateIpCount,
      rate_global: rateGlobalCount,
      cap: db.getCapDropped ? db.getCapDropped() : 0,
      disk_low: diskLowCount,
      write_errors: write_errors
    }
  };
}

function checkDiskSpace() {
  const now = Date.now();
  if (now - lastDiskCheck < 10000) return isDiskLow;
  lastDiskCheck = now;
  try {
    const dbDir = path.join(__dirname, '..');
    const stats = statfsSyncImpl(dbDir);
    const freeMb = (stats.bavail * stats.bsize) / (1024 * 1024);
    isDiskLow = freeMb < MIN_FREE_DISK_MB;
    if (isDiskLow && now - lastDiskWarning > 60000) {
      console.warn(`[WARNING] Low disk space! Free: ${freeMb.toFixed(2)} MB (Minimum: ${MIN_FREE_DISK_MB} MB)`);
      lastDiskWarning = now;
    }
  } catch (e) {
    isDiskLow = false;
  }
  return isDiskLow;
}

const rateLimitDrops = new Map();
let otherDroppedCount = 0;
let lastOtherFlush = 0;

function flushRateLimit(ip, protocol, port) {
  const key = `${ip}_${protocol}_${port}`;
  const state = rateLimitDrops.get(key);
  if (!state || state.count === 0) return;
  try {
    const timestamp = new Date().toISOString();
    const detail = `dropped ${state.count} events`;
    insertEventStmt.run(timestamp, ip, protocol, port, 'RATE_LIMITED', detail, null, null, null, '{}');
  } catch (e) {
    write_errors++;
  }
  rateLimitDrops.delete(key);
}

function flushMultipleDrops() {
  if (otherDroppedCount > 0) {
    try {
      insertEventStmt.run(new Date().toISOString(), 'multiple', 'multi', 0, 'RATE_LIMITED', `dropped ${otherDroppedCount} events`, null, null, null, '{}');
    } catch(e) {
      write_errors++;
    }
    otherDroppedCount = 0;
  }
}

const reporterInterval = setInterval(() => {
  const now = Date.now();
  let wroteRow = false;

  if (otherDroppedCount > 0 && now - lastOtherFlush >= 60000) {
    flushMultipleDrops();
    lastOtherFlush = now;
    wroteRow = true;
  }

  if (!wroteRow) {
    for (const [key, state] of rateLimitDrops.entries()) {
      if (now - state.firstDrop >= 60000) {
        flushRateLimit(state.ip, state.protocol, state.port);
        break; // max 1 summary row per second globally
      }
    }
  }
}, 1000);
if (reporterInterval.unref) reporterInterval.unref();

/**
 * Helper function to safely convert any value to a string and truncate it.
 * @param {any} val - Value to truncate
 * @param {number} maxLen - Maximum allowed length
 * @returns {string|null} Truncated string or null
 */
function sanitizeString(val, maxLen = 500) {
  if (val === undefined || val === null) return null;
  const str = String(val);
  return str.length > maxLen ? str.substring(0, maxLen) : str;
}

/**
 * Helper to process, cap, and sanitize HTTP headers into a safe JSON string.
 * @param {object} headers - Raw Express request headers (req.headers)
 * @returns {string} Safe JSON string representing up to 30 headers
 */
function sanitizeHeaders(headers) {
  if (!headers || typeof headers !== 'object') {
    return '{}';
  }

  const sanitized = {};
  // Cap total header count at 30
  const headerKeys = Object.keys(headers).slice(0, 30);

  for (const key of headerKeys) {
    const safeKey = sanitizeString(key, 200);
    const val = headers[key];
    // Handle array headers (e.g. set-cookie) or standard string headers
    const valStr = Array.isArray(val) ? val.join(', ') : String(val);
    sanitized[safeKey] = sanitizeString(valStr, 200);
  }

  return JSON.stringify(sanitized);
}

// Prepared SQL statement for efficient and safe execution (prevents SQL injection)
const insertEventStmt = db.prepare(`
  INSERT INTO events (
    timestamp, source_ip, protocol, port, method, path,
    user_agent, username, password, raw_headers
  ) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
  )
`);

/**
 * Main report function called by fake doors and middleware.
 * @param {object} event - The raw event object captured from a request
 */
function reportEvent(event) {
  try {
    const sourceIp = sanitizeString(event.source_ip, 500) || '0.0.0.0';
    const protocol = sanitizeString(event.protocol, 500) || 'http';
    const port = Number.isInteger(event.port) ? event.port : 8080;

    if (checkDiskSpace()) {
      diskLowCount++;
      return;
    }

    const allowRes = limiter.allow(sourceIp);
    if (!allowRes.ok) {
      if (allowRes.reason === 'rate_global') rateGlobalCount++;
      else rateIpCount++;

      const key = `${sourceIp}_${protocol}_${port}`;
      let state = rateLimitDrops.get(key);
      if (!state) {
        if (rateLimitDrops.size >= 10000) {
          const firstKey = rateLimitDrops.keys().next().value;
          const firstState = rateLimitDrops.get(firstKey);
          if (firstState) otherDroppedCount += firstState.count;
          rateLimitDrops.delete(firstKey);
        }
        state = { count: 0, firstDrop: Date.now(), ip: sourceIp, protocol, port };
        rateLimitDrops.set(key, state);
      }
      state.count++;
      return;
    }

    // 1. Enforce ISO 8601 UTC timestamp format
    const timestamp = event.timestamp || new Date().toISOString();

    // 2. Sanitize and truncate all fields to 500 characters maximum

    const method = sanitizeString(event.method, 500) || 'UNKNOWN';
    const path = sanitizeString(event.path, 500) || '/';
    const userAgent = sanitizeString(event.user_agent, 500);
    const username = sanitizeString(event.username, 500);
    const password = sanitizeString(event.password, 500);

    // 3. Process headers: max 30 keys, 200 chars per value, JSON stringified
    let rawHeadersJson;
    if (typeof event.raw_headers === 'string') {
      try {
        // If raw_headers is already a JSON string, parse it to sanitize structure
        const parsed = JSON.parse(event.raw_headers);
        rawHeadersJson = sanitizeHeaders(parsed);
      } catch {
        rawHeadersJson = sanitizeHeaders({ raw: event.raw_headers });
      }
    } else {
      rawHeadersJson = sanitizeHeaders(event.raw_headers);
    }

    // 4. Insert into database using parameterized query
    insertEventStmt.run(
      timestamp,
      sourceIp,
      protocol,
      port,
      method,
      path,
      userAgent,
      username,
      password,
      rawHeadersJson
    );

    if (process.env.TRIPWIRE_VERBOSE === '1') {
      const printStr = (s) => (s || '').replace(/[\x00-\x1F\x7F]/g, '').substring(0, 80);
      let logLine = `[LOGGED EVENT] ${method} ${printStr(path)} from ${sourceIp}`;
      const vUser = printStr(username);
      const vUA = printStr(userAgent);
      if (vUser) logLine += ` user:${vUser}`;
      if (vUA) logLine += ` ua:${vUA}`;
      console.log(logLine);
    }
  } catch (err) {
    // Catch-all block so a database error never crashes the honeypot sensor
    console.error('[REPORTER ERROR] Failed to store event:', err.message);
  }
}

module.exports = {
  reportEvent,
  getMetrics: __getMetrics,
  __setStatfsSync,
  __limiter: limiter,
  __flushRateLimit: flushRateLimit,
  __rateLimitDrops: rateLimitDrops,
  __testClearDrops: () => rateLimitDrops.clear(),
  __testForceFlushMultiple: flushMultipleDrops,
  __testResetDiskCache: () => { lastDiskCheck = 0; }
};
