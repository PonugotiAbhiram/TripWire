/**
 * scripts/test-doors.js
 * 
 * Test suite for TripWire fake TCP doors (Ports 2323, 2121, 2222, 3000).
 * Target is hard-coded strictly to 127.0.0.1 (No --target flag permitted).
 * Built-in Node.js modules only (net, http).
 */

const net = require('net');
const http = require('http');

const TARGET = '127.0.0.1';
const skipSlow = process.argv.includes('--skip-slow');

let passed = true;

function logResult(label, isPass, detail = '') {
  if (isPass) {
    console.log(`[PASS] Test ${label}${detail ? ': ' + detail : ''}`);
  } else {
    console.error(`[FAIL] Test ${label}${detail ? ': ' + detail : ''}`);
    passed = false;
  }
}

// Helper for HTTP GET to Admin API
function fetchAdminEvents() {
  return new Promise((resolve, reject) => {
    http.get(`http://${TARGET}:3000/api/events`, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

// Helper to sleep
const sleep = (ms) => new Promise(res => setTimeout(res, ms));

async function runTests() {
  console.log('===========================================================');
  console.log('  TRIPWIRE TEST-DOORS SUITE (Target: 127.0.0.1)');
  console.log('===========================================================');

  // ------------------------------------------------------------------------
  // Test a: Cap test - 25 simultaneous connections to 2323, at most 20 stay open
  // ------------------------------------------------------------------------
  try {
    const sockets = [];
    let openCount = 0;
    let closedCount = 0;

    for (let i = 0; i < 25; i++) {
      const s = new net.Socket();
      sockets.push(s);
      s.on('connect', () => { openCount++; });
      s.on('close', () => { closedCount++; });
      s.on('error', () => {});
      s.connect(2323, TARGET);
    }

    await sleep(400);

    const activeCount = sockets.filter(s => !s.destroyed).length;
    const passA = activeCount <= 20 && activeCount >= 1 && (openCount - closedCount) <= 20;
    logResult('a (Cap Test)', passA, `25 connected, ${activeCount} active sockets remain (<= 20)`);

    sockets.forEach(s => s.destroy());
    await sleep(300);
  } catch (err) {
    logResult('a (Cap Test)', false, err.message);
  }

  // ------------------------------------------------------------------------
  // Test b: Counter test - after closing them, a new connection gets the prompt
  // ------------------------------------------------------------------------
  try {
    let receivedPrompt = false;
    let promptData = '';

    await new Promise((resolve) => {
      const s = new net.Socket();
      s.on('data', (d) => {
        promptData += d.toString('utf-8');
        if (/login:/i.test(promptData)) {
          receivedPrompt = true;
          s.destroy();
          resolve();
        }
      });
      s.on('error', () => { s.destroy(); resolve(); });
      s.on('close', () => resolve());
      s.connect(2323, TARGET);
      setTimeout(() => { s.destroy(); resolve(); }, 2000);
    });

    logResult('b (Counter Test)', receivedPrompt, `New connection received prompt: "${promptData.trim()}"`);
  } catch (err) {
    logResult('b (Counter Test)', false, err.message);
  }

  // ------------------------------------------------------------------------
  // Test c: Reset test - destroy a socket mid-line, door still accepts new ones
  // ------------------------------------------------------------------------
  try {
    const midLineSocket = new net.Socket();
    midLineSocket.on('error', () => {});
    midLineSocket.connect(2323, TARGET, () => {
      midLineSocket.write('partial_user_with_no_newline');
      setImmediate(() => midLineSocket.destroy());
    });

    await sleep(300);

    let resetPass = false;
    let resetData = '';

    await new Promise((resolve) => {
      const s = new net.Socket();
      s.on('data', (d) => {
        resetData += d.toString('utf-8');
        if (/login:/i.test(resetData)) {
          resetPass = true;
          s.destroy();
          resolve();
        }
      });
      s.on('error', () => { s.destroy(); resolve(); });
      s.on('close', () => resolve());
      s.connect(2323, TARGET);
      setTimeout(() => { s.destroy(); resolve(); }, 2000);
    });

    logResult('c (Reset Test)', resetPass, `Door accepted new connection after mid-line reset`);
  } catch (err) {
    logResult('c (Reset Test)', false, err.message);
  }

  // ------------------------------------------------------------------------
  // Test d: IAC test - send bytes FF FD 01, then "admin\r\n", then "pass\r\n".
  // Read /api/events. Latest LOGIN_ATTEMPT username must be exactly "admin" (length 5).
  // ------------------------------------------------------------------------
  try {
    await new Promise((resolve) => {
      const s = new net.Socket();
      let step = 0;
      s.on('data', (d) => {
        const text = d.toString('utf-8');
        if (step === 0 && /login:/i.test(text)) {
          step = 1;
          const iacBuf = Buffer.from([0xff, 0xfd, 0x01]);
          const userBuf = Buffer.from('admin\r\n', 'utf-8');
          s.write(Buffer.concat([iacBuf, userBuf]));
        } else if (step === 1 && /Password:/i.test(text)) {
          step = 2;
          s.write('pass\r\n');
        } else if (step === 2) {
          s.destroy();
          resolve();
        }
      });
      s.on('error', () => { s.destroy(); resolve(); });
      s.on('close', () => resolve());
      s.connect(2323, TARGET);
      setTimeout(() => { s.destroy(); resolve(); }, 3000);
    });

    await sleep(300);

    const events = await fetchAdminEvents();
    const telnetLogins = events.filter(e => e.protocol === 'telnet' && e.method === 'LOGIN_ATTEMPT');
    const latestLogin = telnetLogins[0]; // Newest first

    const passD = latestLogin && latestLogin.username === 'admin' && latestLogin.username.length === 5;
    const detailD = latestLogin
      ? `Captured username="${latestLogin.username}" (length=${latestLogin.username ? latestLogin.username.length : 0})`
      : 'No login event found';

    logResult('d (IAC Test)', passD, detailD);
  } catch (err) {
    logResult('d (IAC Test)', false, err.message);
  }

  // ------------------------------------------------------------------------
  // Test e: Silent connect on 2222 creates a CONNECT row with protocol ssh
  // ------------------------------------------------------------------------
  try {
    const beforeEvents = await fetchAdminEvents();
    const maxBeforeId = beforeEvents.length > 0 ? Math.max(...beforeEvents.map(e => e.id)) : 0;

    await new Promise((resolve) => {
      const s = new net.Socket();
      s.on('error', () => {});
      s.connect(2222, TARGET, () => {
        setTimeout(() => { s.destroy(); resolve(); }, 200);
      });
    });

    await sleep(300);

    const afterEvents = await fetchAdminEvents();
    const newSshConnect = afterEvents.find(e => e.id > maxBeforeId && e.protocol === 'ssh' && e.method === 'CONNECT');

    const passE = !!newSshConnect;
    logResult('e (Silent SSH Connect)', passE, newSshConnect ? `Logged CONNECT event (id=${newSshConnect.id}) for SSH on port 2222` : 'No new SSH CONNECT event found');
  } catch (err) {
    logResult('e (Silent SSH Connect)', false, err.message);
  }

  // ------------------------------------------------------------------------
  // Test f: Idle test - 2121 closes an idle connection within about 35 seconds
  // ------------------------------------------------------------------------
  if (skipSlow) {
    console.log('[SKIP] Test f (Idle Test): Skipped due to --skip-slow flag');
  } else {
    try {
      console.log('Running Test f (Idle Test, waiting ~30-35s for idle timeout)...');
      const startIdle = Date.now();
      let closedByServer = false;

      await new Promise((resolve) => {
        const s = new net.Socket();
        s.on('data', () => {}); // Consume banner to prevent backpressure
        s.on('close', () => {
          closedByServer = true;
          resolve();
        });
        s.on('error', () => { resolve(); });
        s.connect(2121, TARGET);
        setTimeout(() => { s.destroy(); resolve(); }, 45000);
      });

      const elapsedSecNum = Number(((Date.now() - startIdle) / 1000).toFixed(2));
      const passF = closedByServer && elapsedSecNum >= 28 && elapsedSecNum <= 42;
      logResult('f (Idle Timeout Test)', passF, `Idle FTP connection closed by server after ${elapsedSecNum}s (expected ~30-35s)`);
    } catch (err) {
      logResult('f (Idle Timeout Test)', false, err.message);
    }
  }

  console.log('===========================================================');
  if (passed) {
    console.log('  ALL TEST-DOORS SUITE CHECKS PASSED');
    console.log('===========================================================');
    process.exit(0);
  } else {
    console.error('  SOME TEST-DOORS SUITE CHECKS FAILED');
    console.log('===========================================================');
    process.exit(1);
  }
}

runTests();
