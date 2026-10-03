/**
 * sensor/adminApi.js
 * 
 * Admin API Server (Port 3000 - Local Only)
 * ----------------------------------------
 * Provides an administrative REST endpoint to view captured attack logs.
 * This server is strictly bound to 127.0.0.1 so it cannot be accessed from the network.
 */

const express = require('express');
const db = require('./db');

const app = express();

// Disable X-Powered-By header
app.disable('x-powered-by');

// Prepared SQL statement to fetch the 100 most recent events, newest first
const getLatestEventsStmt = db.prepare(`
  SELECT 
    id, timestamp, source_ip, protocol, port, method, path,
    user_agent, username, password, raw_headers
  FROM events
  ORDER BY id DESC
  LIMIT 100
`);

/**
 * GET /api/events
 * Returns array of the 100 latest logged events.
 */
app.get('/api/events', (req, res) => {
  try {
    const rows = getLatestEventsStmt.all();

    // Parse the raw_headers JSON string back into a JS object for clean API response output
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
    res.status(500).json({ error: 'Failed to fetch event logs' });
  }
});

module.exports = app;
