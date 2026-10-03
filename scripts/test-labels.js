/**
 * scripts/test-labels.js
 * 
 * Unit Test Suite for Attack Label Classifier (sensor/labels.js)
 * Evaluates pure function `computeLabels` against mock event streams.
 */

const { computeLabels } = require('../sensor/labels');

let hasFailed = false;

function runTest(name, events, assertFn) {
  try {
    const originalEventsJson = JSON.stringify(events);
    const result = computeLabels(events);
    
    // Safety check: ensure computeLabels did not mutate input array
    if (JSON.stringify(events) !== originalEventsJson) {
      console.log(`[FAIL] ${name} - Input array was mutated by computeLabels`);
      hasFailed = true;
      return;
    }

    const passed = assertFn(result);
    if (passed) {
      console.log(`[PASS] ${name}`);
    } else {
      console.log(`[FAIL] ${name} - Result:`, JSON.stringify(result));
      hasFailed = true;
    }
  } catch (err) {
    console.log(`[FAIL] ${name} - Exception thrown:`, err.message);
    hasFailed = true;
  }
}

console.log('=== STARTING LABELS CLASSIFIER UNIT TESTS ===\n');

// Base timestamp for generating test events: 2026-10-03T10:00:00.000Z
const baseTs = 1790935200000;
const ts = (offsetMs) => new Date(baseTs + offsetMs).toISOString();

// Case a: demo-attacker pattern (3 CONNECTs on different ports in 1s, 11 logins in 8s, 5 bait GETs)
const eventsA = [
  // 3 CONNECTs within 1s (ports 2121, 2222, 2323)
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: 'ftp', port: 2121, method: 'CONNECT', path: 'Connection opened', user_agent: null },
  { timestamp: ts(200), source_ip: '127.0.0.1', protocol: 'ssh', port: 2222, method: 'CONNECT', path: 'Connection opened', user_agent: null },
  { timestamp: ts(400), source_ip: '127.0.0.1', protocol: 'telnet', port: 2323, method: 'CONNECT', path: 'Connection opened', user_agent: null },
  
  // 11 logins within 8s (8 HTTP POST logins + 3 Telnet logins)
  { timestamp: ts(1000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', user_agent: 'TripWire-Demo-Attacker/1.0', username: 'admin', password: '123' },
  { timestamp: ts(1500), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', user_agent: 'TripWire-Demo-Attacker/1.0', username: 'admin', password: '456' },
  { timestamp: ts(2000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', user_agent: 'TripWire-Demo-Attacker/1.0', username: 'admin', password: '789' },
  { timestamp: ts(2500), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', user_agent: 'TripWire-Demo-Attacker/1.0', username: 'admin', password: 'abc' },
  { timestamp: ts(3000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', user_agent: 'TripWire-Demo-Attacker/1.0', username: 'admin', password: 'def' },
  { timestamp: ts(3500), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', user_agent: 'TripWire-Demo-Attacker/1.0', username: 'admin', password: 'ghi' },
  { timestamp: ts(4000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', user_agent: 'TripWire-Demo-Attacker/1.0', username: 'admin', password: 'jkl' },
  { timestamp: ts(4500), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', user_agent: 'TripWire-Demo-Attacker/1.0', username: 'admin', password: 'mno' },
  { timestamp: ts(5000), source_ip: '127.0.0.1', protocol: 'telnet', port: 2323, method: 'LOGIN_ATTEMPT', path: 'telnet-login', user_agent: null, username: 'root', password: '123' },
  { timestamp: ts(5500), source_ip: '127.0.0.1', protocol: 'telnet', port: 2323, method: 'LOGIN_ATTEMPT', path: 'telnet-login', user_agent: null, username: 'root', password: '456' },
  { timestamp: ts(6000), source_ip: '127.0.0.1', protocol: 'telnet', port: 2323, method: 'LOGIN_ATTEMPT', path: 'telnet-login', user_agent: null, username: 'root', password: '789' },

  // 5 bait GETs
  { timestamp: ts(6500), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/admin', user_agent: 'TripWire-Demo-Attacker/1.0' },
  { timestamp: ts(7000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/wp-login.php', user_agent: 'TripWire-Demo-Attacker/1.0' },
  { timestamp: ts(7500), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/.env', user_agent: 'TripWire-Demo-Attacker/1.0' },
  { timestamp: ts(8000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/phpmyadmin', user_agent: 'TripWire-Demo-Attacker/1.0' },
  { timestamp: ts(8500), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/config.php', user_agent: 'TripWire-Demo-Attacker/1.0' }
];

runTest('a. demo-attacker pattern gives port_scan, brute_force, web_probe', eventsA, res => 
  res.labels.includes('port_scan') &&
  res.labels.includes('brute_force') &&
  res.labels.includes('web_probe') &&
  res.tool_hints.includes('TripWire-Demo-Attacker')
);

// Case b: 3 failed logins only: no labels
const eventsB = [
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', username: 'u1', password: 'p1' },
  { timestamp: ts(500), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', username: 'u1', password: 'p2' },
  { timestamp: ts(1000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login', username: 'u1', password: 'p3' }
];

runTest('b. 3 failed logins only gives NO labels', eventsB, res => res.labels.length === 0);

// Case c: browser GET / plus GET /favicon.ico: no labels
const eventsC = [
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/', user_agent: 'Mozilla/5.0' },
  { timestamp: ts(100), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/favicon.ico', user_agent: 'Mozilla/5.0' }
];

runTest('c. normal browser GET / and /favicon.ico gives NO labels', eventsC, res => res.labels.length === 0);

// Case d: 5 logins spread over 100 seconds: NO brute_force
const eventsD = [
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' },
  { timestamp: ts(25000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' },
  { timestamp: ts(50000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' },
  { timestamp: ts(75000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' },
  { timestamp: ts(100000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' }
];

runTest('d. 5 logins spread over 100 seconds gives NO brute_force', eventsD, res => !res.labels.includes('brute_force'));

// Case e: 5 logins within 40 seconds: brute_force
const eventsE = [
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' },
  { timestamp: ts(10000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' },
  { timestamp: ts(20000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' },
  { timestamp: ts(30000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' },
  { timestamp: ts(40000), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'POST', path: '/login' }
];

runTest('e. 5 logins within 40 seconds gives brute_force', eventsE, res => res.labels.includes('brute_force'));

// Case f: 2 CONNECTs on different ports within 1s: NO port_scan
const eventsF = [
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: 'ftp', port: 2121, method: 'CONNECT' },
  { timestamp: ts(500), source_ip: '127.0.0.1', protocol: 'ssh', port: 2222, method: 'CONNECT' }
];

runTest('f. 2 CONNECTs on different ports within 1s gives NO port_scan', eventsF, res => !res.labels.includes('port_scan'));

// Case g: the same bait path requested 5 times: NO web_probe (needs distinct)
const eventsG = [
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/admin' },
  { timestamp: ts(100), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/admin' },
  { timestamp: ts(200), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/admin' },
  { timestamp: ts(300), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/admin' },
  { timestamp: ts(400), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/admin' }
];

runTest('g. same bait path requested 5 times gives NO web_probe', eventsG, res => !res.labels.includes('web_probe'));

// Case h: GET /ADMIN?x=1, /.ENV and /Config.php count as 3 bait paths
const eventsH = [
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/ADMIN?x=1' },
  { timestamp: ts(100), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/.ENV' },
  { timestamp: ts(200), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: '/Config.php' }
];

runTest('h. GET /ADMIN?x=1, /.ENV and /Config.php gives web_probe', eventsH, res => res.labels.includes('web_probe'));

// Case i: empty array gives no labels
runTest('i. empty array gives no labels or errors', [], res => 
  Array.isArray(res.labels) && res.labels.length === 0 &&
  Array.isArray(res.reasons) && res.reasons.length === 0 &&
  Array.isArray(res.tool_hints) && res.tool_hints.length === 0
);

// Case j: rows with null fields give no crash
const eventsJ = [
  { timestamp: ts(0), source_ip: '127.0.0.1', protocol: null, port: null, method: null, path: null, user_agent: null, username: null, password: null },
  { timestamp: ts(100), source_ip: '127.0.0.1', protocol: 'http', port: 8080, method: 'GET', path: null, user_agent: null }
];

runTest('j. rows with null fields give no crash', eventsJ, res => 
  Array.isArray(res.labels) && res.labels.length === 0
);

console.log('\n=============================================');
if (hasFailed) {
  console.log('=== TEST SUITE FAILED ===');
  process.exit(1);
} else {
  console.log('=== ALL UNIT TESTS PASSED ===');
  process.exit(0);
}
