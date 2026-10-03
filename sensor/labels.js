/**
 * sensor/labels.js
 * 
 * Attack Label Classifier Module
 * --------------------------------
 * Analyzes event streams to classify attacker behavior (port scans, brute force,
 * web probing) using sliding time windows and pattern detection.
 */

const net = require('net');
const db = require('./db');

// Centralized configurable detection thresholds and bait paths
const CONFIG = {
  port_scan: { distinctPorts: 3, windowSeconds: 10 },
  brute_force: { attempts: 5, windowSeconds: 60 },
  web_probe: { distinctPaths: 3 },
  baitPaths: [
    '/admin', '/wp-login.php', '/.env', '/phpmyadmin', '/config.php',
    '/wp-admin', '/.git/config', '/backup.sql', '/shell', '/cgi-bin'
  ]
};

// Tool hint detection keywords (case-insensitive)
const HINT_KEYWORDS = [
  'curl', 'python', 'libssh', 'paramiko', 'go-http', 'nmap', 'TripWire-Demo-Attacker'
];

/**
 * Normalizes HTTP paths by stripping query parameters and converting to lower case.
 * @param {string|null} rawPath 
 * @returns {string}
 */
function normalizePath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') return '';
  return rawPath.split('?')[0].toLowerCase();
}

/**
 * Pure function to compute security labels, plain-English reasons, and tool hints
 * from an array of event objects sorted by timestamp.
 * 
 * @param {Array<object>} events - Raw event objects from the events table
 * @returns {{ labels: Array<string>, reasons: Array<string>, tool_hints: Array<string> }}
 */
function computeLabels(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return { labels: [], reasons: [], tool_hints: [] };
  }

  const labels = [];
  const reasons = [];
  const toolHintsSet = new Set();

  // Parse timestamps safely to milliseconds, filtering out invalid dates
  const parsedEvents = events
    .map(e => ({
      ...e,
      tsMs: e.timestamp ? Date.parse(e.timestamp) : NaN
    }))
    .filter(e => !isNaN(e.tsMs));

  // --- 1. Port Scan Detection (Sliding Window <= 10 seconds) ---
  const connectEvents = parsedEvents.filter(e => e.method === 'CONNECT');
  let maxScanPorts = 0;
  let maxScanSpanSec = 0;

  for (let i = 0; i < connectEvents.length; i++) {
    for (let j = i; j < connectEvents.length; j++) {
      const spanMs = connectEvents[j].tsMs - connectEvents[i].tsMs;
      if (spanMs <= CONFIG.port_scan.windowSeconds * 1000) {
        const portsSet = new Set();
        for (let k = i; k <= j; k++) {
          if (connectEvents[k].port !== undefined && connectEvents[k].port !== null) {
            portsSet.add(connectEvents[k].port);
          }
        }
        const distinctCount = portsSet.size;
        const currentSpanSec = spanMs / 1000;

        if (distinctCount >= CONFIG.port_scan.distinctPorts) {
          if (distinctCount > maxScanPorts || (distinctCount === maxScanPorts && currentSpanSec < maxScanSpanSec)) {
            maxScanPorts = distinctCount;
            maxScanSpanSec = currentSpanSec;
          }
        }
      } else {
        break; // Timestamps are sorted ASC
      }
    }
  }

  if (maxScanPorts >= CONFIG.port_scan.distinctPorts) {
    labels.push('port_scan');
    reasons.push(`touched ${maxScanPorts} doors in ${maxScanSpanSec.toFixed(1)}s`);
  }

  // --- 2. Brute Force Detection (Sliding Window <= 60 seconds) ---
  const isLoginAttempt = (e) => {
    if (!e) return false;
    if (e.method === 'LOGIN_ATTEMPT') return true;
    if (e.protocol === 'http' && e.method === 'POST') {
      const clean = normalizePath(e.path);
      return clean === '/login' || clean === '/wp-login.php' || clean === '/';
    }
    return false;
  };

  const loginEvents = parsedEvents.filter(isLoginAttempt);
  let maxBruteAttempts = 0;
  let maxBruteSpanSec = 0;

  for (let i = 0; i < loginEvents.length; i++) {
    for (let j = i; j < loginEvents.length; j++) {
      const spanMs = loginEvents[j].tsMs - loginEvents[i].tsMs;
      if (spanMs <= CONFIG.brute_force.windowSeconds * 1000) {
        const attemptsCount = j - i + 1;
        const currentSpanSec = spanMs / 1000;

        if (attemptsCount >= CONFIG.brute_force.attempts) {
          if (attemptsCount > maxBruteAttempts || (attemptsCount === maxBruteAttempts && currentSpanSec < maxBruteSpanSec)) {
            maxBruteAttempts = attemptsCount;
            maxBruteSpanSec = currentSpanSec;
          }
        }
      } else {
        break;
      }
    }
  }

  if (maxBruteAttempts >= CONFIG.brute_force.attempts) {
    labels.push('brute_force');
    reasons.push(`tried ${maxBruteAttempts} passwords in ${maxBruteSpanSec.toFixed(1)}s`);
  }

  // --- 3. Web Probe Detection (Distinct Bait Paths requested by HTTP GET) ---
  const baitPathsSet = new Set(CONFIG.baitPaths.map(p => p.toLowerCase()));
  const probedBaitPaths = new Set();

  for (const e of parsedEvents) {
    if (e.protocol === 'http' && e.method === 'GET' && e.path) {
      const clean = normalizePath(e.path);
      if (clean !== '/favicon.ico' && baitPathsSet.has(clean)) {
        probedBaitPaths.add(clean);
      }
    }
  }

  if (probedBaitPaths.size >= CONFIG.web_probe.distinctPaths) {
    labels.push('web_probe');
    reasons.push(`probed ${probedBaitPaths.size} bait paths`);
  }

  // --- 4. Tool Hint Detection ---
  for (const e of parsedEvents) {
    const userAgentLower = (e.user_agent || '').toLowerCase();
    const sshCmdLower = (e.protocol === 'ssh' && e.method === 'COMMAND' && e.path ? e.path : '').toLowerCase();

    for (const keyword of HINT_KEYWORDS) {
      const kwLower = keyword.toLowerCase();
      if (userAgentLower.includes(kwLower) || sshCmdLower.includes(kwLower)) {
        toolHintsSet.add(keyword);
      }
    }
  }

  return {
    labels,
    reasons,
    tool_hints: Array.from(toolHintsSet)
  };
}

/**
 * Loads events for a specific IP from SQLite database and computes labels.
 * 
 * @param {string} ip - Source IP address
 * @returns {object|null} Label results object or null if IP is invalid
 */
function getLabels(ip) {
  if (!ip || typeof ip !== 'string' || net.isIP(ip) === 0) {
    return null;
  }

  const stmt = db.prepare(`
    SELECT * FROM events
    WHERE source_ip = ?
    ORDER BY timestamp ASC, id ASC
    LIMIT 5000
  `);

  const events = stmt.all(ip);
  return computeLabels(events);
}

module.exports = {
  CONFIG,
  computeLabels,
  getLabels
};
