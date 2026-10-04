/**
 * sensor/fakeTelnet.js
 * 
 * Fake Telnet Door Server (Port 2323)
 * -----------------------------------
 * Simulates a Telnet login interface. Captures connection events, login attempts,
 * and disconnects, reporting them via reporter.js without granting system access.
 */

const net = require('net');
const { reportEvent } = require('./reporter');
const db = require('./db');
const bans = require('./bans');

const PORT = 2323;
const HOST = process.env.BIND_HOST || '127.0.0.1';
const MAX_CONCURRENT = 20;
const IDLE_TIMEOUT_MS = 30000;
const MAX_LINE_BYTES = 256;
const MAX_LINES = 20;
const MAX_ATTEMPTS = 3;

let activeConnections = 0;

/**
 * Strips Telnet IAC (Interpret As Command, 0xFF) byte sequences from buffer.
 * @param {Buffer} buf 
 * @returns {Buffer}
 */
function stripTelnetIAC(buf) {
  const clean = [];
  let i = 0;
  while (i < buf.length) {
    if (buf[i] === 255) {
      // Skip IAC byte plus the 2 command/option bytes
      i += 3;
    } else {
      clean.push(buf[i]);
      i++;
    }
  }
  return Buffer.from(clean);
}

const server = net.createServer((socket) => {
  const clientIp = (socket.remoteAddress || '0.0.0.0').replace(/^::ffff:/, '');
  if (bans.checkAndBlock(clientIp, socket, 'telnet', 2323, db)) {
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
      protocol: 'telnet',
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
    console.error('[TELNET CONNECT LOG ERROR]', err.message);
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
          protocol: 'telnet',
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
      console.error('[TELNET DISCONNECT LOG ERROR]', err.message);
    }
  });

  // Door session state
  let state = 'WAIT_USER';
  let pendingUser = null;
  let attemptCount = 0;
  let lineCount = 0;
  let inputBuffer = Buffer.alloc(0);

  // Send banner
  socket.write('Ubuntu 20.04 LTS\r\nrouter login: ');

  socket.on('data', (chunk) => {
    const cleanChunk = stripTelnetIAC(chunk);
    inputBuffer = Buffer.concat([inputBuffer, cleanChunk]);

    // Process lines from buffer
    while (inputBuffer.length > 0) {
      let newlineIdx = inputBuffer.indexOf(0x0a); // '\n'
      let lineBuf;

      if (newlineIdx !== -1) {
        lineBuf = inputBuffer.slice(0, newlineIdx);
        inputBuffer = inputBuffer.slice(newlineIdx + 1);
      } else if (inputBuffer.length >= MAX_LINE_BYTES) {
        // Buffer capped at 256 bytes without a newline -> force cut line
        lineBuf = inputBuffer.slice(0, MAX_LINE_BYTES);
        inputBuffer = inputBuffer.slice(MAX_LINE_BYTES);
      } else {
        // Wait for more data
        break;
      }

      lineCount++;
      if (lineCount > MAX_LINES) {
        socket.write('Too many commands\r\n');
        socket.destroy();
        return;
      }

      // Convert line buffer to string and strip trailing '\r'
      let lineStr = lineBuf.toString('utf-8').replace(/\r$/, '').trim();

      if (state === 'WAIT_USER') {
        pendingUser = lineStr;
        state = 'WAIT_PASS';
        socket.write('Password: ');
      } else if (state === 'WAIT_PASS') {
        const passwordStr = lineStr;
        attemptCount++;

        // Log LOGIN_ATTEMPT
        try {
          reportEvent({
            timestamp: new Date().toISOString(),
            source_ip: clientIp,
            protocol: 'telnet',
            port: PORT,
            method: 'LOGIN_ATTEMPT',
            path: 'telnet-login',
            user_agent: null,
            username: pendingUser,
            password: passwordStr,
            raw_headers: {}
          });
        } catch (err) {
          console.error('[TELNET LOGIN LOG ERROR]', err.message);
        }

        socket.write('Login incorrect\r\n');
        pendingUser = null;
        state = 'WAIT_USER';

        if (attemptCount >= MAX_ATTEMPTS) {
          socket.end();
          return;
        } else {
          socket.write('router login: ');
        }
      }
    }
  });
});

// Server-level error handler
server.on('error', (err) => {
  console.error('[TELNET SERVER ERROR]', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error(`[TELNET SERVER ERROR] Port ${PORT} is already in use. Exiting.`);
    process.exit(1);
  }
});

function listen(port = PORT, host = HOST, callback) {
  server.listen(port, host, () => {
    console.log(`Fake Telnet listening on ${host}:${port}`);
    if (callback) callback();
  });
  return server;
}

module.exports = {
  server,
  listen
};
