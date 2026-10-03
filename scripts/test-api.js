/**
 * scripts/test-api.js
 * 
 * Admin API Test Suite
 * --------------------
 * Sends HTTP GET requests to http://127.0.0.1:3000 using Node.js built-in `http` module.
 * Evaluates endpoints /api/events, /api/attackers, /api/attackers/:ip, and /api/stats.
 */

const http = require('http');

let hasFailed = false;

function fetchJson(path) {
  return new Promise((resolve, reject) => {
    const req = http.get(`http://127.0.0.1:3000${path}`, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(body);
        } catch {
          json = null;
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data: json,
          rawBody: body
        });
      });
    });
    req.on('error', reject);
  });
}

async function runTests() {
  console.log('=== STARTING ADMIN API INTEGRATION TESTS ===\n');

  try {
    // Check g: Content-Type header on all endpoints
    // Check a: /api/events returns an array
    const resEvents = await fetchJson('/api/events');
    const contentTypeEvents = resEvents.headers['content-type'] || '';
    if (resEvents.statusCode === 200 && Array.isArray(resEvents.data) && contentTypeEvents.includes('application/json')) {
      console.log('[PASS] a. /api/events returns an array');
    } else {
      console.log('[FAIL] a. /api/events - Status:', resEvents.statusCode, 'Data:', resEvents.data);
      hasFailed = true;
    }

    // Check b: /api/attackers returns an array that includes 127.0.0.1 with level High
    const resAttackers = await fetchJson('/api/attackers');
    const contentTypeAttackers = resAttackers.headers['content-type'] || '';
    if (
      resAttackers.statusCode === 200 &&
      Array.isArray(resAttackers.data) &&
      contentTypeAttackers.includes('application/json')
    ) {
      const attacker127 = resAttackers.data.find(a => a.ip === '127.0.0.1');
      if (attacker127 && attacker127.level === 'High') {
        console.log('[PASS] b. /api/attackers returns an array including 127.0.0.1 with level High');
      } else {
        console.log('[FAIL] b. /api/attackers - 127.0.0.1 not found or not High:', attacker127);
        hasFailed = true;
      }
    } else {
      console.log('[FAIL] b. /api/attackers - Status:', resAttackers.statusCode);
      hasFailed = true;
    }

    // Check c: /api/attackers/127.0.0.1 has profile, assessment and timeline sorted oldest first
    const resIp = await fetchJson('/api/attackers/127.0.0.1');
    const contentTypeIp = resIp.headers['content-type'] || '';
    if (
      resIp.statusCode === 200 &&
      resIp.data &&
      resIp.data.profile &&
      resIp.data.assessment &&
      Array.isArray(resIp.data.timeline) &&
      contentTypeIp.includes('application/json')
    ) {
      const timeline = resIp.data.timeline;
      let sortedOldestFirst = true;
      for (let i = 1; i < timeline.length; i++) {
        if ((timeline[i].time || '').localeCompare(timeline[i - 1].time || '') < 0) {
          sortedOldestFirst = false;
          break;
        }
      }

      if (sortedOldestFirst) {
        console.log('[PASS] c. /api/attackers/127.0.0.1 has profile, assessment, and timeline sorted oldest first');
      } else {
        console.log('[FAIL] c. /api/attackers/127.0.0.1 - Timeline is not sorted oldest first');
        hasFailed = true;
      }
    } else {
      console.log('[FAIL] c. /api/attackers/127.0.0.1 - Status:', resIp.statusCode, 'Data:', resIp.data);
      hasFailed = true;
    }

    // Check d: /api/attackers/999.999.999.999 returns 400
    const resInvalidIp = await fetchJson('/api/attackers/999.999.999.999');
    const contentTypeInvalid = resInvalidIp.headers['content-type'] || '';
    if (resInvalidIp.statusCode === 400 && resInvalidIp.data && resInvalidIp.data.error === 'invalid ip' && contentTypeInvalid.includes('application/json')) {
      console.log('[PASS] d. /api/attackers/999.999.999.999 returns 400 with invalid ip');
    } else {
      console.log('[FAIL] d. /api/attackers/999.999.999.999 - Status:', resInvalidIp.statusCode, 'Data:', resInvalidIp.data);
      hasFailed = true;
    }

    // Check e: /api/attackers/10.1.2.3 returns 404
    const resUnknownIp = await fetchJson('/api/attackers/10.1.2.3');
    const contentTypeUnknown = resUnknownIp.headers['content-type'] || '';
    if (resUnknownIp.statusCode === 404 && resUnknownIp.data && resUnknownIp.data.error === 'unknown ip' && contentTypeUnknown.includes('application/json')) {
      console.log('[PASS] e. /api/attackers/10.1.2.3 returns 404 with unknown ip');
    } else {
      console.log('[FAIL] e. /api/attackers/10.1.2.3 - Status:', resUnknownIp.statusCode, 'Data:', resUnknownIp.data);
      hasFailed = true;
    }

    // Check f: /api/stats has required fields & total_events >= 24
    const resStats = await fetchJson('/api/stats');
    const contentTypeStats = resStats.headers['content-type'] || '';
    if (
      resStats.statusCode === 200 &&
      resStats.data &&
      typeof resStats.data.total_events === 'number' &&
      resStats.data.total_events >= 24 &&
      typeof resStats.data.unique_ips === 'number' &&
      Array.isArray(resStats.data.top_passwords) &&
      Array.isArray(resStats.data.top_usernames) &&
      resStats.data.events_per_protocol &&
      Array.isArray(resStats.data.events_per_hour) &&
      resStats.data.levels &&
      contentTypeStats.includes('application/json')
    ) {
      console.log('[PASS] f. /api/stats has all required fields and total_events >= 24');
    } else {
      console.log('[FAIL] f. /api/stats - Status:', resStats.statusCode, 'Data:', resStats.data);
      hasFailed = true;
    }

    // Check g: every response has Content-Type application/json
    if (
      contentTypeEvents.includes('application/json') &&
      contentTypeAttackers.includes('application/json') &&
      contentTypeIp.includes('application/json') &&
      contentTypeInvalid.includes('application/json') &&
      contentTypeUnknown.includes('application/json') &&
      contentTypeStats.includes('application/json')
    ) {
      console.log('[PASS] g. Every response has Content-Type header containing application/json');
    } else {
      console.log('[FAIL] g. Missing or incorrect Content-Type headers on API responses');
      hasFailed = true;
    }

  } catch (err) {
    console.log('[FAIL] Exception during API test execution:', err.message);
    hasFailed = true;
  }

  console.log('\n=============================================');
  if (hasFailed) {
    console.log('=== ADMIN API TESTS FAILED ===');
    process.exit(1);
  } else {
    console.log('=== ALL ADMIN API TESTS PASSED ===');
    process.exit(0);
  }
}

runTests();
