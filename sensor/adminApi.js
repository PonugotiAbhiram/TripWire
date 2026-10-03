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
const db = require('./db');
const analyzer = require('./analyzer');
const severity = require('./severity');

const app = express();

// Disable X-Powered-By header
app.disable('x-powered-by');

// Apply security and JSON headers ONLY on /api routes
app.use('/api', (req, res, next) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// Prepared SQL statement for GET /api/events (100 most recent events)
const getLatestEventsStmt = db.prepare(`
  SELECT 
    id, timestamp, source_ip, protocol, port, method, path,
    user_agent, username, password, raw_headers
  FROM events
  ORDER BY id DESC
  LIMIT 100
`);

// In-memory cache variables (5 second TTL)
let cachedAttackersData = null;
let attackersCacheTime = 0;

let cachedStatsData = null;
let statsCacheTime = 0;

/**
 * Shared cached function to compute threat assessments for the 100 most recent IPs.
 * Feeds both /api/attackers and /api/stats (prevents duplicate getAssessment calls).
 * 
 * @returns {Array<object>} Sorted array of attacker profiles
 */
function getAttackersCached() {
  const now = Date.now();
  if (cachedAttackersData && (now - attackersCacheTime < 5000)) {
    return cachedAttackersData;
  }

  const recentIps = analyzer.listIps(100);
  const attackers = recentIps.map(ipObj => {
    const assessment = severity.getAssessment(ipObj.source_ip);
    return {
      ip: ipObj.source_ip,
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

  // Sort by score DESC, then last_seen DESC
  attackers.sort((a, b) => {
    if (b.score !== a.score) {
      return b.score - a.score;
    }
    return (b.last_seen || '').localeCompare(a.last_seen || '');
  });

  cachedAttackersData = attackers;
  attackersCacheTime = now;
  return cachedAttackersData;
}

/**
 * GET /api/events
 * Returns array of the 100 latest logged events.
 */
app.get('/api/events', (req, res) => {
  try {
    const rows = getLatestEventsStmt.all();

    const events = rows.map(row => {
      let parsedHeaders = row.raw_headers;
      if (typeof row.raw_headers === 'string') {
        try {
          parsedHeaders = JSON.parse(row.raw_headers);
        } catch {
          parsedHeaders = row.raw_headers;
        }
      }
      return {
        ...row,
        raw_headers: parsedHeaders
      };
    });

    res.json(events);
  } catch (err) {
    console.error('[ADMIN API ERROR]', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

/**
 * GET /api/attackers
 * Returns 100 most recent attackers with threat assessments, sorted by score DESC.
 */
app.get('/api/attackers', (req, res) => {
  try {
    const attackers = getAttackersCached();
    res.json(attackers);
  } catch (err) {
    console.error('[ADMIN API ERROR]', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

/**
 * GET /api/attackers/:ip
 * Returns detailed profile, assessment, and timeline for a specific IP.
 */
app.get('/api/attackers/:ip', (req, res) => {
  try {
    const ip = req.params.ip;

    if (net.isIP(ip) === 0) {
      return res.status(400).json({ error: 'invalid ip' });
    }

    const profile = analyzer.getProfile(ip);
    if (!profile) {
      return res.status(404).json({ error: 'unknown ip' });
    }

    const assessment = severity.getAssessment(ip);
    const timeline = analyzer.getTimeline(ip, 200);

    res.json({
      profile,
      assessment,
      timeline
    });
  } catch (err) {
    console.error('[ADMIN API ERROR]', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

/**
 * GET /api/stats
 * Returns global honeypot stats including total events, unique IPs, top passwords/usernames,
 * events per protocol, events per hour (last 24h), and threat level distribution.
 */
app.get('/api/stats', (req, res) => {
  try {
    const now = Date.now();
    if (cachedStatsData && (now - statsCacheTime < 5000)) {
      return res.json(cachedStatsData);
    }

    const attackers = getAttackersCached();
    const levels = { High: 0, Medium: 0, Low: 0, None: 0 };
    for (const a of attackers) {
      if (a.level in levels) {
        levels[a.level]++;
      }
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

module.exports = app;
