/**
 * sensor/fakeFtp.js
 * 
 * Fake FTP Door Server (Port 2121)
 * --------------------------------
 * Simulates an FTP login interface. Captures connection events, USER/PASS credentials,
 * commands, and disconnects, reporting them via reporter.js without granting access.
 */

const net = require('net');
const { reportEvent } = require('./reporter');
const db = require('./db');
const bans = require('./bans');

const PORT = 2121;
const HOST = process.env.BIND_HOST || '127.0.0.1';
const MAX_CONCURRENT = 20;
const IDLE_TIMEOUT_MS = 30000;
const MAX_LINE_BYTES = 256;
const MAX_LINES = 20;
const MAX_ATTEMPTS = 3;

let activeConnections = 0;

const server = net.createServer((socket) => {
  const clientIp = (socket.remoteAddress || '0.0.0.0').replace(/^::ffff:/, '');
  if (bans.checkAndBlock(clientIp, socket, 'ftp', 2121, db)) {
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
      protocol: 'ftp',
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
    console.error('[FTP CONNECT LOG ERROR]', err.message);
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
          protocol: 'ftp',
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
      console.error('[FTP DISCONNECT LOG ERROR]', err.message);
    }
  });

  // Door session state
  let savedUser = null;
  let attemptCount = 0;
  let lineCount = 0;
  let inputBuffer = Buffer.alloc(0);

  // Send banner
  socket.write('220 FTP server ready\r\n');

  socket.on('data', (chunk) => {
    inputBuffer = Buffer.concat([inputBuffer, chunk]);

    while (inputBuffer.length > 0) {
      let newlineIdx = inputBuffer.indexOf(0x0a); // '\n'
      let lineBuf;

      if (newlineIdx !== -1) {
        lineBuf = inputBuffer.slice(0, newlineIdx);
        inputBuffer = inputBuffer.slice(newlineIdx + 1);
      } else if (inputBuffer.length >= MAX_LINE_BYTES) {
        lineBuf = inputBuffer.slice(0, MAX_LINE_BYTES);
        inputBuffer = inputBuffer.slice(MAX_LINE_BYTES);
      } else {
        break;
      }

      lineCount++;
      if (lineCount > MAX_LINES) {
        socket.write('421 Too many commands\r\n');
        socket.destroy();
        return;
      }

      let lineStr = lineBuf.toString('utf-8').replace(/\r$/, '').trim();
      if (!lineStr) continue;

      const spaceIdx = lineStr.indexOf(' ');
      const cmd = (spaceIdx !== -1 ? lineStr.substring(0, spaceIdx) : lineStr).toUpperCase();
      const arg = spaceIdx !== -1 ? lineStr.substring(spaceIdx + 1).trim() : '';

      if (cmd === 'USER') {
        savedUser = arg;
        socket.write('331 Password required\r\n');
      } else if (cmd === 'PASS') {
        attemptCount++;
        const user = savedUser || 'anonymous';
        const pass = arg;

        try {
          reportEvent({
            timestamp: new Date().toISOString(),
            source_ip: clientIp,
            protocol: 'ftp',
            port: PORT,
            method: 'LOGIN_ATTEMPT',
            path: 'ftp-login',
            user_agent: null,
            username: user,
            password: pass,
            raw_headers: {}
          });
        } catch (err) {
          console.error('[FTP LOGIN LOG ERROR]', err.message);
        }

        savedUser = null;
        socket.write('530 Login incorrect\r\n');

        if (attemptCount >= MAX_ATTEMPTS) {
          socket.end();
          return;
        }
      } else if (cmd === 'QUIT') {
        socket.write('221 Goodbye\r\n');
        socket.end();
        return;
      } else {
        // Log unauthenticated command
        try {
          reportEvent({
            timestamp: new Date().toISOString(),
            source_ip: clientIp,
            protocol: 'ftp',
            port: PORT,
            method: 'COMMAND',
            path: lineStr.substring(0, 500),
            user_agent: null,
            username: savedUser,
            password: null,
            raw_headers: {}
          });
        } catch (err) {
          console.error('[FTP COMMAND LOG ERROR]', err.message);
        }

        socket.write('530 Please login with USER and PASS\r\n');
      }
    }
  });
});

// Server-level error handler
server.on('error', (err) => {
  console.error('[FTP SERVER ERROR]', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error(`[FTP SERVER ERROR] Port ${PORT} is already in use. Exiting.`);
    process.exit(1);
  }
});

function listen(port = PORT, host = HOST, callback) {
  server.listen(port, host, () => {
    console.log(`Fake FTP listening on ${host}:${port}`);
    if (callback) callback();
  });
  return server;
}

module.exports = {
  server,
  listen
};
