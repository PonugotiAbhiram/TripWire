/**
 * sensor/index.js
 * 
 * Main Server Entry Point
 * -----------------------
 * Initializes the database connection and starts all honeypot door services:
 * - Fake Web Doors (Port 8080 bound to BIND_HOST)
 * - Private Admin API (Port 3000 bound strictly to 127.0.0.1)
 * - Fake Telnet Door (Port 2323 bound to BIND_HOST)
 * - Fake FTP Door (Port 2121 bound to BIND_HOST)
 * - Fake SSH Door (Port 2222 bound to BIND_HOST)
 */

const fakeWebApp = require('./fakeWeb');
const adminApiApp = require('./adminApi');
const fakeTelnet = require('./fakeTelnet');
const fakeFtp = require('./fakeFtp');
const fakeSsh = require('./fakeSsh');
require('./db'); // Trigger DB connection, WAL mode, table & index creation

const FAKE_WEB_PORT = 8080;
const ADMIN_PORT = 3000;
const ADMIN_HOST = '127.0.0.1';
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';

console.log(`====================================================`);
console.log(`  TRIPWIRE HONEYPOT SENSOR (Step 1-3) STARTED`);
console.log(`====================================================`);

// 1. Start the Fake Web Doors on Port 8080 (Bound to BIND_HOST)
const webServer = fakeWebApp.listen(FAKE_WEB_PORT, BIND_HOST, () => {
  console.log(`[+] Fake Web Doors : http://${BIND_HOST}:${FAKE_WEB_PORT}`);
});

webServer.on('error', (err) => {
  console.error('[WEB SERVER ERROR]', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error(`[WEB SERVER ERROR] Port ${FAKE_WEB_PORT} is already in use. Exiting.`);
    process.exit(1);
  }
});

// 2. Start the private Admin API on Port 3000 (Bound strictly to 127.0.0.1)
const adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword || adminPassword.length < 12) {
  console.log(`[!] ADMIN_PASSWORD is not set or is shorter than 12 characters.`);
  console.log(`[!] Admin dashboard and API will NOT start.`);
  console.log(`[!] To enable the admin server, set ADMIN_PASSWORD to a secure phrase.`);
} else {
  const adminServer = adminApiApp.listen(ADMIN_PORT, ADMIN_HOST, () => {
    console.log(`[+] Admin API      : http://${ADMIN_HOST}:${ADMIN_PORT}/api/events`);
  });

  adminServer.on('error', (err) => {
    console.error('[ADMIN API SERVER ERROR]', err.message);
    if (err.code === 'EADDRINUSE') {
      console.error(`[ADMIN API SERVER ERROR] Port ${ADMIN_PORT} is already in use. Exiting.`);
      process.exit(1);
    }
  });
}

// 3. Start Fake TCP Doors (Telnet 2323, FTP 2121, SSH 2222)
fakeTelnet.listen(2323, BIND_HOST);
fakeFtp.listen(2121, BIND_HOST);
fakeSsh.listen(2222, BIND_HOST);
