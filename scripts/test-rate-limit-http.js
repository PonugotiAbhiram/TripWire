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
  console.log('Testing HTTP Rate Limit Lockout:');
  for (let i = 1; i <= 6; i++) {
    const res = await loginAttempt();
    if (res.statusCode === 401) {
      console.log(`Attempt ${i}: 401 (Unauthorized)`);
    } else if (res.statusCode === 429) {
      console.log(`Attempt ${i}: 429 (Too Many Requests), Retry-After: ${res.retryAfter}`);
    } else {
      console.log(`Attempt ${i}: ${res.statusCode}`);
    }
  }
}
run();
