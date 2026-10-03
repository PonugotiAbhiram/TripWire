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

const db = require('./db');

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
    // 1. Enforce ISO 8601 UTC timestamp format
    const timestamp = event.timestamp || new Date().toISOString();

    // 2. Sanitize and truncate all fields to 500 characters maximum
    const sourceIp = sanitizeString(event.source_ip, 500) || '0.0.0.0';
    const protocol = sanitizeString(event.protocol, 500) || 'http';
    const port = Number.isInteger(event.port) ? event.port : 8080;
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

    console.log(`[LOGGED EVENT] ${method} ${path} from ${sourceIp}`);
  } catch (err) {
    // Catch-all block so a database error never crashes the honeypot sensor
    console.error('[REPORTER ERROR] Failed to store event:', err.message);
  }
}

module.exports = {
  reportEvent
};
