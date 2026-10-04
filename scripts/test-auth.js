const http = require('http');

let hasFailed = false;

function logResult(label, isPass, detail = '') {
  if (isPass) {
    console.log(`[PASS] ${label}${detail ? ': ' + detail : ''}`);
  } else {
    console.error(`[FAIL] ${label}${detail ? ': ' + detail : ''}`);
    hasFailed = true;
  }
}

function fetchRaw(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch {}
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data,
          json
        });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function runTests() {
  console.log('=== STARTING AUTH TESTS ===\n');

  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminPassword || adminPassword.length < 12) {
    console.error('[!] ADMIN_PASSWORD is not set or is shorter than 12 characters.');
    process.exit(1);
  }

  // a. GET /api/stats without a cookie gives 401
  const resA = await fetchRaw({ hostname: '127.0.0.1', port: 3000, path: '/api/stats' });
  logResult('a', resA.statusCode === 401, 'GET /api/stats without cookie -> 401');

  // b. GET / without a cookie gives 302 to /login.html
  const resB = await fetchRaw({ hostname: '127.0.0.1', port: 3000, path: '/' });
  logResult('b', resB.statusCode === 302 && resB.headers.location === '/login.html', 'GET / without cookie -> 302 /login.html');

  // c. GET /login.html gives 200
  const resC = await fetchRaw({ hostname: '127.0.0.1', port: 3000, path: '/login.html' });
  logResult('c', resC.statusCode === 200, 'GET /login.html -> 200');

  // d. a wrong password gives 401 and no Set-Cookie header
  const resD = await fetchRaw({
    hostname: '127.0.0.1', port: 3000, path: '/api/login', method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, JSON.stringify({ password: 'wrongpassword123' }));
  logResult('d', resD.statusCode === 401 && !resD.headers['set-cookie'], 'wrong password -> 401, no cookie');

  // e. the right password gives 200 and a Set-Cookie with HttpOnly and SameSite=Strict
  const resE = await fetchRaw({
    hostname: '127.0.0.1', port: 3000, path: '/api/login', method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, JSON.stringify({ password: adminPassword }));
  const cookieHeader = (resE.headers['set-cookie'] || [])[0] || '';
  const validCookie = cookieHeader.includes('HttpOnly') && cookieHeader.includes('SameSite=Strict');
  logResult('e', resE.statusCode === 200 && validCookie, 'right password -> 200, secure cookie');
  const sessionCookie = cookieHeader.split(';')[0];
  const csrfToken = resE.json ? resE.json.csrf : '';

  // f. with the cookie, GET /api/stats gives 200
  const resF = await fetchRaw({
    hostname: '127.0.0.1', port: 3000, path: '/api/stats',
    headers: { 'Cookie': sessionCookie }
  });
  logResult('f', resF.statusCode === 200, 'with cookie, GET /api/stats -> 200');

  // g. POST /api/logout without the CSRF header gives 403
  const resG = await fetchRaw({
    hostname: '127.0.0.1', port: 3000, path: '/api/logout', method: 'POST',
    headers: { 'Cookie': sessionCookie }
  });
  logResult('g', resG.statusCode === 403, 'POST /api/logout without CSRF -> 403');

  // h. POST /api/logout with the header gives 200, and the old cookie then gives 401
  const resH = await fetchRaw({
    hostname: '127.0.0.1', port: 3000, path: '/api/logout', method: 'POST',
    headers: { 'Cookie': sessionCookie, 'X-CSRF-Token': csrfToken }
  });
  const resH2 = await fetchRaw({
    hostname: '127.0.0.1', port: 3000, path: '/api/stats',
    headers: { 'Cookie': sessionCookie }
  });
  logResult('h', resH.statusCode === 200 && resH2.statusCode === 401, 'POST /api/logout with CSRF -> 200, old cookie -> 401');

  // i. a request with Host: evil.example gives 400
  const resI = await fetchRaw({
    hostname: '127.0.0.1', port: 3000, path: '/',
    headers: { 'Host': 'evil.example' }
  });
  logResult('i', resI.statusCode === 400, 'Host: evil.example -> 400');

  // j. POST /api/login with Origin: http://evil.example gives 403
  const resJ = await fetchRaw({
    hostname: '127.0.0.1', port: 3000, path: '/api/login', method: 'POST',
    headers: { 'Origin': 'http://evil.example', 'Content-Type': 'application/json' }
  }, JSON.stringify({ password: adminPassword }));
  logResult('j', resJ.statusCode === 403, 'Origin: http://evil.example -> 403');

  console.log('\n=============================================');
  if (hasFailed) {
    console.error('=== SOME AUTH TESTS FAILED ===');
    process.exit(1);
  } else {
    console.log('=== ALL AUTH TESTS PASSED ===');
    process.exit(0);
  }
}

runTests();
