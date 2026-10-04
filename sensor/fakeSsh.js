/**
 * sensor/fakeSsh.js
 * 
 * Fake SSH Door Server (Port 2222)
 * --------------------------------
 * Sends an OpenSSH version banner, captures the client's version string (identifying
 * the attacker's software tool), logs it as a COMMAND event, and closes the connection.
 */

const net = require('net');
const { reportEvent } = require('./reporter');
const db = require('./db');
const bans = require('./bans');

const PORT = 2222;
const HOST = process.env.BIND_HOST || '127.0.0.1';
const MAX_CONCURRENT = 20;
const IDLE_TIMEOUT_MS = 30000;
const MAX_LINE_BYTES = 256;

let activeConnections = 0;

const server = net.createServer((socket) => {
  const clientIp = (socket.remoteAddress || '0.0.0.0').replace(/^::ffff:/, '');
  if (bans.checkAndBlock(clientIp, socket, 'ssh', 2222, db)) {
    return;
  }

  // Max concurrent connection enforcement
  if (activeConnections >= MAX_CONCURRENT) {
    socket.destroy();
    return;
  }

  activeConnections++;

  let loggedConnect = false;

  // Immediately log CONNECT event
  try {
    reportEvent({
      timestamp: new Date().toISOString(),
      source_ip: clientIp,
      protocol: 'ssh',
      port: PORT,
      method: 'CONNECT',
      path: 'Connection opened',
      user_agent: null,
      username: null,
      password: null,
      raw_headers: {}
    });
    loggedConnect = true;
  } catch (err) {
    console.error('[SSH CONNECT LOG ERROR]', err.message);
  }

  // Socket timeouts & errors
  socket.setTimeout(IDLE_TIMEOUT_MS);

  socket.on('timeout', () => {
    socket.destroy();
  });

  socket.on('error', () => {
    socket.destroy();
  });

  // Decrement counter ONLY on 'close' event & log DISCONNECT
  socket.on('close', () => {
    activeConnections--;
    try {
      if (loggedConnect) {
        reportEvent({
          timestamp: new Date().toISOString(),
          source_ip: clientIp,
          protocol: 'ssh',
          port: PORT,
          method: 'DISCONNECT',
          path: 'Connection closed',
          user_agent: null,
          username: null,
          password: null,
          raw_headers: {}
        });
      }
    } catch (err) {
      console.error('[SSH DISCONNECT LOG ERROR]', err.message);
    }
  });

  let inputBuffer = Buffer.alloc(0);
  let handledFirstLine = false;

  // Send OpenSSH server version banner
  socket.write('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n');

  socket.on('data', (chunk) => {
    if (handledFirstLine) return;

    inputBuffer = Buffer.concat([inputBuffer, chunk]);

    let newlineIdx = inputBuffer.indexOf(0x0a); // '\n'
    let lineBuf;

    if (newlineIdx !== -1) {
      lineBuf = inputBuffer.slice(0, newlineIdx);
    } else if (inputBuffer.length >= MAX_LINE_BYTES) {
      lineBuf = inputBuffer.slice(0, MAX_LINE_BYTES);
    } else {
      return; // Wait for full line or buffer cap
    }

    handledFirstLine = true;
    const clientVersionStr = lineBuf.toString('utf-8').replace(/\r$/, '').trim();

    // Log COMMAND event with client SSH version string
    try {
      reportEvent({
        timestamp: new Date().toISOString(),
        source_ip: clientIp,
        protocol: 'ssh',
        port: PORT,
        method: 'COMMAND',
        path: clientVersionStr.substring(0, 500),
        user_agent: null,
        username: null,
        password: null,
        raw_headers: {}
      });
    } catch (err) {
      console.error('[SSH COMMAND LOG ERROR]', err.message);
    }

    // Close connection immediately after capturing the version line
    socket.end();
  });
});

// Server-level error handler
server.on('error', (err) => {
  console.error('[SSH SERVER ERROR]', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error(`[SSH SERVER ERROR] Port ${PORT} is already in use. Exiting.`);
    process.exit(1);
  }
});

function listen(port = PORT, host = HOST, callback) {
  server.listen(port, host, () => {
    console.log(`Fake SSH listening on ${host}:${port}`);
    if (callback) callback();
  });
  return server;
}

module.exports = {
  server,
  listen
};
