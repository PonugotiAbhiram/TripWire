/**
 * sensor/db.js
 * 
 * Database Setup & Connection
 * ----------------------------
 * This module manages the connection to our SQLite database.
 * It uses Node.js 22+'s built-in synchronous SQLite engine (node:sqlite).
 */

const path = require('path');

// Store the database file in the project root directory, unless overridden for tests
const dbPath = process.env.TEST_DB_PATH || path.join(__dirname, '..', 'tripwire.db');

const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(dbPath);

// Backwards compatibility wrapper for PRAGMA statements
db.pragma = function (pragmaStr) {
  this.exec(`PRAGMA ${pragmaStr};`);
};

db.pragma('journal_mode = WAL');
db.pragma('journal_size_limit = 16777216'); // 16MB WAL limit

function parseEnv(name, def, min) {
  if (process.env[name] !== undefined) {
    const val = parseInt(process.env[name], 10);
    if (!isNaN(val) && val >= min) return val;
    console.warn(`[WARNING] Invalid ${name} '${process.env[name]}', falling back to default ${def}`);
  }
  return def;
}
const MAX_EVENT_ROWS = parseEnv('MAX_EVENT_ROWS', 500000, 100);
const CLEANUP_BATCH = parseEnv('CLEANUP_BATCH', 5000, 10);
console.log(`[DB] Active limits: MAX_EVENT_ROWS=${MAX_EVENT_ROWS}, CLEANUP_BATCH=${CLEANUP_BATCH}`);

let dropped_events_cap = 0;
let cachedRowCount = 0;

function updateCachedCount() {
  try {
    const row = db.prepare('SELECT COUNT(*) as c FROM events').get();
    if (row && row.c !== undefined) {
      cachedRowCount = row.c;
    }
  } catch (e) {}
  return cachedRowCount;
}

let isCleanupRunning = false;

const cleanupInterval = setInterval(() => {
  if (isCleanupRunning) return;
  let count = updateCachedCount();
  if (count <= MAX_EVENT_ROWS) return;
  isCleanupRunning = true;

  function doBatch() {
    try {
      if (count <= MAX_EVENT_ROWS) { isCleanupRunning = false; return; }
      const res = db.prepare(`DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)`).run(CLEANUP_BATCH);
      if (res.changes === 0) { isCleanupRunning = false; return; }
      dropped_events_cap += res.changes;
      count -= res.changes;
      cachedRowCount = count;
      if (count > MAX_EVENT_ROWS) {
        setImmediate(doBatch);
      } else {
        isCleanupRunning = false;
      }
    } catch (err) {
      console.error('[DB CLEANUP ERROR]', err.message);
      isCleanupRunning = false;
    }
  }
  doBatch();
}, 60000);
if (cleanupInterval.unref) cleanupInterval.unref();

db.MAX_EVENT_ROWS = MAX_EVENT_ROWS;
db.getApproximateCount = () => cachedRowCount;
db.getCapDropped = () => dropped_events_cap;

db.__testRunCleanup = () => {
  return new Promise((resolve) => {
    if (isCleanupRunning) return resolve();
    let count = updateCachedCount();
    if (count <= MAX_EVENT_ROWS) return resolve();
    isCleanupRunning = true;

    function doBatch() {
      try {
        if (count <= MAX_EVENT_ROWS) { isCleanupRunning = false; return resolve(); }
        const res = db.prepare(`DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)`).run(CLEANUP_BATCH);
        if (res.changes === 0) { isCleanupRunning = false; return resolve(); }
        dropped_events_cap += res.changes;
        count -= res.changes;
        cachedRowCount = count;
        if (count > MAX_EVENT_ROWS) {
          setImmediate(doBatch);
        } else {
          isCleanupRunning = false;
          resolve();
        }
      } catch(e) { 
        isCleanupRunning = false; 
        resolve(); 
      }
    }
    doBatch();
  });
};
db.__testUpdateCachedCount = updateCachedCount;
db.__testSetDroppedCap = (val) => { dropped_events_cap = val; };

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

// Create bans table
db.exec(`
  CREATE TABLE IF NOT EXISTS bans (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    created_at TEXT,
    expires_at TEXT,
    active INTEGER
  );
`);

db.dbPath = dbPath;

module.exports = db;
