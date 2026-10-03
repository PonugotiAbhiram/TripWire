/**
 * sensor/db.js
 * 
 * Database Setup & Connection
 * ----------------------------
 * This module manages the connection to our SQLite database.
 * It uses `better-sqlite3` if installed, or automatically falls back to Node.js 22+'s
 * built-in synchronous SQLite engine (`node:sqlite`).
 */

const path = require('path');

// Store the database file in the project root directory
const dbPath = path.join(__dirname, '..', 'tripwire.db');

let db;

try {
  // Try loading better-sqlite3 first
  const Database = require('better-sqlite3');
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
} catch (e) {
  // Fallback to Node.js built-in `node:sqlite` (supported in Node 22+)
  console.log('[DB] Note: Using Node.js built-in `node:sqlite` engine.');
  const { DatabaseSync } = require('node:sqlite');
  db = new DatabaseSync(dbPath);
  db.pragma = function (pragmaStr) {
    this.exec(`PRAGMA ${pragmaStr};`);
  };
  db.pragma('journal_mode = WAL');
}

// Create the `events` table if it does not already exist
const createTableQuery = `
  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    user_agent TEXT,
    username TEXT,
    password TEXT,
    raw_headers TEXT
  );
`;

db.exec(createTableQuery);

// Create indexes on source_ip and timestamp to speed up common queries
db.exec(`CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);`);

module.exports = db;
