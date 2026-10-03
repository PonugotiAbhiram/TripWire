/**
 * sensor/analyzer.js
 * 
 * IP Event Profile Analyzer
 * -------------------------
 * Provides analytical queries against the TripWire SQLite database.
 * Reuses the existing db connection from `sensor/db.js`.
 */

const net = require('net');
const db = require('./db');

/**
 * Lists all source IPs stored in the database with basic summary metrics.
 * 
 * @param {number} limit - Maximum number of IPs to return (default 100)
 * @returns {Array<{source_ip: string, total_events: number, first_seen: string, last_seen: string}>}
 */
function listIps(limit = 100) {
  const parsedLimit = Math.max(1, parseInt(limit, 10) || 100);
  const stmt = db.prepare(`
    SELECT 
      source_ip,
      COUNT(*) AS total_events,
      MIN(timestamp) AS first_seen,
      MAX(timestamp) AS last_seen
    FROM events
    GROUP BY source_ip
    ORDER BY last_seen DESC
    LIMIT ?
  `);
  
  return stmt.all(parsedLimit);
}

/**
 * Compiles a detailed security activity profile for a specific IP address.
 * 
 * @param {string} ip - Source IP address to profile
 * @returns {object|null} Profile object or null if IP is invalid or has no recorded events
 */
function getProfile(ip) {
  if (!ip || typeof ip !== 'string' || net.isIP(ip) === 0) {
    return null;
  }

  // 1. Overview summary metrics
  const summaryStmt = db.prepare(`
    SELECT 
      COUNT(*) AS total_events,
      MIN(timestamp) AS first_seen,
      MAX(timestamp) AS last_seen
    FROM events
    WHERE source_ip = ?
  `);
  const summary = summaryStmt.get(ip);

  if (!summary || !summary.total_events || summary.total_events === 0) {
    return null;
  }

  // 2. Breakdown by protocol (http, telnet, ftp, ssh)
  const protoStmt = db.prepare(`
    SELECT protocol, COUNT(*) AS count
    FROM events
    WHERE source_ip = ?
    GROUP BY protocol
  `);
  const protoRows = protoStmt.all(ip);
  const by_protocol = { http: 0, telnet: 0, ftp: 0, ssh: 0 };
  for (const row of protoRows) {
    if (row.protocol in by_protocol) {
      by_protocol[row.protocol] = row.count;
    } else {
      by_protocol[row.protocol] = row.count;
    }
  }

  // 3. Ports touched (all events)
  const portsTouchedStmt = db.prepare(`
    SELECT DISTINCT port
    FROM events
    WHERE source_ip = ?
    ORDER BY port ASC
  `);
  const ports_touched = portsTouchedStmt.all(ip).map(r => r.port);

  // 4. Doors connected (CONNECT method events)
  const doorsConnectedStmt = db.prepare(`
    SELECT DISTINCT port
    FROM events
    WHERE source_ip = ? AND method = 'CONNECT'
    ORDER BY port ASC
  `);
  const doors_connected = doorsConnectedStmt.all(ip).map(r => r.port);

  // 5. Login attempts count (LOGIN_ATTEMPT or POST logins)
  const loginAttemptsStmt = db.prepare(`
    SELECT COUNT(*) AS count
    FROM events
    WHERE source_ip = ?
      AND (
        method = 'LOGIN_ATTEMPT'
        OR (protocol = 'http' AND method = 'POST' AND path IN ('/login', '/wp-login.php', '/'))
      )
  `);
  const login_attempts = loginAttemptsStmt.get(ip).count;

  // 6. Distinct usernames count & Top 5 usernames
  const distinctUsernamesStmt = db.prepare(`
    SELECT COUNT(DISTINCT username) AS count
    FROM events
    WHERE source_ip = ? AND username IS NOT NULL AND username != ''
  `);
  const distinct_usernames = distinctUsernamesStmt.get(ip).count;

  const topUsernamesStmt = db.prepare(`
    SELECT username, COUNT(*) AS count
    FROM events
    WHERE source_ip = ? AND username IS NOT NULL AND username != ''
    GROUP BY username
    ORDER BY count DESC, username ASC
    LIMIT 5
  `);
  const top_usernames = topUsernamesStmt.all(ip);

  // 7. Distinct passwords count & Top 5 passwords
  const distinctPasswordsStmt = db.prepare(`
    SELECT COUNT(DISTINCT password) AS count
    FROM events
    WHERE source_ip = ? AND password IS NOT NULL AND password != ''
  `);
  const distinct_passwords = distinctPasswordsStmt.get(ip).count;

  const topPasswordsStmt = db.prepare(`
    SELECT password, COUNT(*) AS count
    FROM events
    WHERE source_ip = ? AND password IS NOT NULL AND password != ''
    GROUP BY password
    ORDER BY count DESC, password ASC
    LIMIT 5
  `);
  const top_passwords = topPasswordsStmt.all(ip);

  // 8. Top 10 HTTP paths probed (GET requests only, excluding /favicon.ico, /, /login)
  const pathsProbedStmt = db.prepare(`
    SELECT path, COUNT(*) AS count
    FROM events
    WHERE source_ip = ?
      AND protocol = 'http'
      AND method = 'GET'
      AND path NOT IN ('/favicon.ico', '/', '/login')
      AND path != ''
    GROUP BY path
    ORDER BY count DESC, path ASC
    LIMIT 10
  `);
  const paths_probed = pathsProbedStmt.all(ip);

  // 9. Top 5 User Agents
  const userAgentsStmt = db.prepare(`
    SELECT user_agent, COUNT(*) AS count
    FROM events
    WHERE source_ip = ? AND user_agent IS NOT NULL AND user_agent != ''
    GROUP BY user_agent
    ORDER BY count DESC, user_agent ASC
    LIMIT 5
  `);
  const user_agents = userAgentsStmt.all(ip);

  // 10. SSH Version strings (distinct path values of SSH COMMAND events)
  const sshVersionsStmt = db.prepare(`
    SELECT DISTINCT path
    FROM events
    WHERE source_ip = ?
      AND protocol = 'ssh'
      AND method = 'COMMAND'
      AND path IS NOT NULL
      AND path != ''
    LIMIT 10
  `);
  const ssh_versions = sshVersionsStmt.all(ip).map(r => r.path);

  return {
    ip,
    first_seen: summary.first_seen,
    last_seen: summary.last_seen,
    total_events: summary.total_events,
    by_protocol,
    ports_touched,
    doors_connected,
    login_attempts,
    distinct_usernames,
    top_usernames,
    distinct_passwords,
    top_passwords,
    paths_probed,
    user_agents,
    ssh_versions
  };
}

module.exports = {
  listIps,
  getProfile
};
