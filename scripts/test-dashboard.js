const http = require('http');
const fs = require('fs');
const path = require('path');

const API_BASE = 'http://127.0.0.1:3000';

function fetchUrl(url, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, data });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function runTests() {
  console.log('=== STARTING DASHBOARD TESTS ===\n');
  let hasFailed = false;

  function assertPass(name, condition) {
    if (condition) {
      console.log(`[PASS] ${name}`);
    } else {
      console.log(`[FAIL] ${name}`);
      hasFailed = true;
    }
  }

  try {
    // a. GET / returns 200 and Content-Type text/html
    const resA = await fetchUrl(API_BASE + '/');
    assertPass('a. GET / returns 200 and Content-Type text/html', 
      resA.status === 200 && resA.headers['content-type'].includes('text/html')
    );

    // b. GET / has a Content-Security-Policy header containing "script-src 'self'"
    assertPass('b. GET / has a Content-Security-Policy header containing "script-src \'self\'"', 
      resA.headers['content-security-policy'] && resA.headers['content-security-policy'].includes("script-src 'self'")
    );

    // c. GET /app.js returns 200
    const resC = await fetchUrl(API_BASE + '/app.js');
    assertPass('c. GET /app.js returns 200', resC.status === 200);

    // d. GET /api/stats still returns Content-Type application/json
    const resD = await fetchUrl(API_BASE + '/api/stats');
    assertPass('d. GET /api/stats still returns Content-Type application/json', 
      resD.status === 200 && resD.headers['content-type'].includes('application/json')
    );

    // e. the text of app.js contains none of: innerHTML, outerHTML, insertAdjacentHTML, document.write, eval(
    const appJsPath = path.join(__dirname, '..', 'sensor', 'public', 'app.js');
    const appJsCode = fs.readFileSync(appJsPath, 'utf8');
    const badTokens = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval('];
    const hasBadToken = badTokens.some(token => appJsCode.includes(token));
    assertPass('e. the text of app.js contains none of: innerHTML, outerHTML, insertAdjacentHTML, document.write, eval(', 
      !hasBadToken
    );

    // f. GET /nonexistent-file.txt returns 404
    const resF = await fetchUrl(API_BASE + '/nonexistent-file.txt');
    assertPass('f. GET /nonexistent-file.txt returns 404', resF.status === 404);

    // g. GET /../package.json does not return the package file (expect 404 or 400)
    // Need to use raw socket to bypass Node.js URL normalization for path traversal
    const resG = await new Promise((resolve) => {
      const client = require('net').createConnection(3000, '127.0.0.1', () => {
        client.write('GET /../package.json HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n');
      });
      let response = '';
      client.on('data', (d) => response += d);
      client.on('end', () => {
        const firstLine = response.split('\r\n')[0];
        resolve(firstLine.includes(' 404') || firstLine.includes(' 400'));
      });
      client.on('error', () => resolve(true)); // if blocked at TCP level
    });
    assertPass('g. GET /../package.json does not return the package file', resG);

    // h. GET /tripwire.db returns 404
    const resH = await fetchUrl(API_BASE + '/tripwire.db');
    assertPass('h. GET /tripwire.db returns 404', resH.status === 404);

    // i. GET /sensor/db.js returns 404
    const resI = await fetchUrl(API_BASE + '/sensor/db.js');
    assertPass('i. GET /sensor/db.js returns 404', resI.status === 404);

  } catch (err) {
    console.error('Test execution error:', err);
    hasFailed = true;
  }

  console.log('\n=============================================');
  if (hasFailed) {
    console.log('=== SOME TESTS FAILED ===');
    process.exit(1);
  } else {
    console.log('=== ALL DASHBOARD TESTS PASSED ===');
    process.exit(0);
  }
}

runTests();
