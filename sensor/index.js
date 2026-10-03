/**
 * sensor/index.js
 * 
 * Main Server Entry Point
 * -----------------------
 * Initializes the database connection and starts the fake web honeypot server (port 8080)
 * along with the private Admin API (port 3000 bound to 127.0.0.1).
 */

const fakeWebApp = require('./fakeWeb');
const adminApiApp = require('./adminApi');
require('./db'); // Trigger DB connection, WAL mode, table & index creation

const FAKE_WEB_PORT = 8080;
const ADMIN_PORT = 3000;
const ADMIN_HOST = '127.0.0.1';

// 1. Start the Fake Web Doors on Port 8080
fakeWebApp.listen(FAKE_WEB_PORT, () => {
  console.log(`====================================================`);
  console.log(`  TRIPWIRE HONEYPOT SENSOR (Step 1) STARTED`);
  console.log(`  [+] Fake Web Doors : http://0.0.0.0:${FAKE_WEB_PORT}`);
  console.log(`  [+] Admin API      : http://${ADMIN_HOST}:${ADMIN_PORT}/api/events`);
  console.log(`====================================================`);
});

// 2. Start the private Admin API on Port 3000 (Bound strictly to 127.0.0.1)
adminApiApp.listen(ADMIN_PORT, ADMIN_HOST, () => {
  console.log(`[ADMIN API] Bound to ${ADMIN_HOST}:${ADMIN_PORT}`);
});
