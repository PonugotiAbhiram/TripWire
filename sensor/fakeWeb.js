/**
 * sensor/fakeWeb.js
 * 
 * Fake Web Door Server (Port 8080)
 * ---------------------------------
 * This Express application simulates a fake web router and WordPress login panel.
 * It intercepts all requests, logs attacker metadata via reporter.js,
 * hides real server identity, and handles malformed/oversized requests safely.
 */

const express = require('express');
const { reportEvent } = require('./reporter');
const db = require('./db');
const bans = require('./bans');

const app = express();

// SECURITY: Hide X-Powered-By header to obscure framework details
app.disable('x-powered-by');

// SECURITY: Limit request body to 10kb to prevent Denial of Service (DoS) attacks
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// APP-LEVEL BAN CHECK: Very first middleware
app.use((req, res, next) => {
  const clientIp = getClientIp(req);
  if (bans.checkAndBlock(clientIp, req, 'http', 8080, db)) {
    return;
  }
  next();
});

/**
 * Helper to extract client IP directly from socket, bypassing X-Forwarded-For to prevent IP spoofing.
 * Removes the IPv6 loopback prefix `::ffff:` if present.
 */
function getClientIp(req) {
  const remoteAddr = req.socket ? req.socket.remoteAddress : '';
  if (!remoteAddr) return '0.0.0.0';
  return remoteAddr.replace(/^::ffff:/, '');
}

/**
 * Helper to inspect body for username and password across common field aliases.
 * Forces all values to String to prevent type confusion bugs.
 */
function extractCredentials(body) {
  let username = null;
  let password = null;

  if (body && typeof body === 'object') {
    const userKeys = ['username', 'user', 'log', 'login', 'email'];
    for (const key of userKeys) {
      if (body[key] !== undefined && body[key] !== null) {
        username = String(body[key]);
        break;
      }
    }

    const passKeys = ['password', 'pass', 'pwd'];
    for (const key of passKeys) {
      if (body[key] !== undefined && body[key] !== null) {
        password = String(body[key]);
        break;
      }
    }
  }

  return { username, password };
}

/**
 * LOGGING MIDDLEWARE
 * Executed on every request (any path, any HTTP method) to build and report the event.
 */
app.use((req, res, next) => {
  try {
    const clientIp = getClientIp(req);
    const { username, password } = extractCredentials(req.body);

    const event = {
      timestamp: new Date().toISOString(),
      source_ip: clientIp,
      protocol: 'http',
      port: 8080,
      method: req.method,
      path: req.originalUrl || req.url,
      user_agent: req.get('user-agent') || null,
      username: username,
      password: password,
      raw_headers: req.headers
    };

    // Store log status to avoid duplicate logs in error middleware
    req._honeypotLogged = true;
    reportEvent(event);
  } catch (err) {
    console.error('[MIDDLEWARE ERROR]', err.message);
  }
  next();
});

// ROUTE 1: Fake Router Login Page (GET / and GET /login)
const routerLoginHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Router Management Console - Login</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #f4f6f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 320px; }
    h2 { margin-top: 0; color: #333; text-align: center; }
    label { display: block; margin-top: 15px; color: #666; font-size: 14px; }
    input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin-top: 5px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
    button { width: 100%; margin-top: 20px; padding: 10px; background-color: #007bff; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
    button:hover { background-color: #0056b3; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Router Admin Login</h2>
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Log In</button>
    </form>
  </div>
</body>
</html>
`;

app.get('/', (req, res) => res.send(routerLoginHtml));
app.get('/login', (req, res) => res.send(routerLoginHtml));

// ROUTE 2: Fake WordPress Login Page (GET /wp-login.php)
const wpLoginHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WordPress &rsaquo; Log In</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; background: #f0f0f1; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .wp-box { background: #fff; padding: 26px 24px; border: 1px solid #c3c4c7; width: 320px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
    h1 { text-align: center; color: #2c3338; font-size: 20px; font-weight: 400; margin-bottom: 20px; }
    label { display: block; margin-bottom: 5px; color: #50575e; font-size: 14px; }
    input[type="text"], input[type="password"] { width: 100%; padding: 6px 10px; margin-bottom: 16px; border: 1px solid #8c8f94; border-radius: 4px; box-sizing: border-box; }
    input[type="submit"] { background: #2271b1; border-color: #2271b1; color: #fff; padding: 6px 14px; font-weight: 600; border-radius: 3px; cursor: pointer; float: right; }
  </style>
</head>
<body>
  <div class="wp-box">
    <h1>WordPress Log In</h1>
    <form method="POST" action="/wp-login.php">
      <label for="log">Username or Email Address</label>
      <input type="text" id="log" name="log" required>
      <label for="pwd">Password</label>
      <input type="password" id="pwd" name="pwd" required>
      <input type="submit" value="Log In">
    </form>
  </div>
</body>
</html>
`;

app.get('/wp-login.php', (req, res) => res.send(wpLoginHtml));

// ROUTE 3: POST Handlers - ALWAYS respond "Invalid username or password", NEVER log in
app.post(['/', '/login', '/wp-login.php'], (req, res) => {
  try {
    res.status(401).send(`
      <!DOCTYPE html>
      <html>
      <head><title>Login Failed</title></head>
      <body style="font-family: Arial; text-align: center; margin-top: 50px;">
        <h3 style="color: red;">Invalid username or password.</h3>
        <a href="javascript:history.back()">Try again</a>
      </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// ROUTE 4: Catch-all 404 door handler for any other path (e.g. /.env, /admin, /phpmyadmin)
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head><title>404 Not Found</title></head>
    <body style="font-family: Arial; text-align: center; margin-top: 50px;">
      <h2>404 Not Found</h2>
      <p>The requested URL ${req.path} was not found on this server.</p>
    </body>
    </html>
  `);
});

/**
 * ERROR-HANDLING MIDDLEWARE
 * Intercepts oversized (413 Payload Too Large), malformed (400 Bad Request), or server errors.
 * Ensures that even failed requests trigger an event log.
 */
app.use((err, req, res, next) => {
  try {
    if (!req._honeypotLogged) {
      const clientIp = getClientIp(req);
      const event = {
        timestamp: new Date().toISOString(),
        source_ip: clientIp,
        protocol: 'http',
        port: 8080,
        method: req.method || 'UNKNOWN',
        path: req.originalUrl || req.url || '/',
        user_agent: req.get ? req.get('user-agent') : null,
        username: null,
        password: null,
        raw_headers: req.headers || {}
      };
      reportEvent(event);
    }
  } catch (loggingErr) {
    console.error('[ERROR MIDDLEWARE LOGGING ERROR]', loggingErr.message);
  }

  const statusCode = err.status || err.statusCode || 500;
  if (statusCode === 413) {
    return res.status(413).send('<h1>413 Payload Too Large</h1><p>Request body exceeds 10KB limit.</p>');
  }
  if (statusCode === 400) {
    return res.status(400).send('<h1>400 Bad Request</h1><p>Malformed request payload.</p>');
  }

  return res.status(statusCode).send('<h1>500 Internal Server Error</h1>');
});

module.exports = app;
