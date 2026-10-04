const http = require('http');

function loginAttempt() {
  return new Promise((resolve) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: 3000,
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, (res) => {
      resolve({ statusCode: res.statusCode, retryAfter: res.headers['retry-after'] });
    });
    req.write(JSON.stringify({ password: 'wrong' }));
    req.end();
  });
}

async function run() {
  if (process.env.CONFIRM_LOCKOUT_TEST !== '1') {
    console.error('[FATAL] This test simulates a brute-force login attack which locks out the admin IP for 15 minutes (or until a server restart).');
    console.error('[FATAL] Refusing to run unless CONFIRM_LOCKOUT_TEST=1 is set.');
    process.exit(1);
  }
  
  console.log('Testing HTTP Rate Limit Lockout:');
  let hasFailed = false;

  for (let i = 1; i <= 6; i++) {
    const res = await loginAttempt();
    let passed = false;
    let msg = '';

    if (i <= 4) {
      if (res.statusCode === 401) {
        passed = true;
        msg = `Attempt ${i}: 401 (Unauthorized)`;
      } else {
        msg = `Attempt ${i}: Expected 401, got ${res.statusCode}`;
      }
    } else if (i === 5) {
      if (res.statusCode === 429 && res.retryAfter) {
        passed = true;
        msg = `Attempt ${i}: 429 (Too Many Requests), Retry-After: ${res.retryAfter}`;
      } else {
        msg = `Attempt ${i}: Expected 429 with Retry-After, got ${res.statusCode} (Retry-After: ${res.retryAfter})`;
      }
    } else if (i === 6) {
      if (res.statusCode === 429) {
        passed = true;
        msg = `Attempt ${i}: 429 (Too Many Requests)`;
      } else {
        msg = `Attempt ${i}: Expected 429, got ${res.statusCode}`;
      }
    }

    if (passed) {
      console.log(`[PASS] ${msg}`);
    } else {
      console.error(`[FAIL] ${msg}`);
      hasFailed = true;
    }
  }

  if (hasFailed) {
    process.exit(1);
  } else {
    console.log('All tests passed.');
  }
}
run();
