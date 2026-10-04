const http = require('http');
const net = require('net');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error("ADMIN_PASSWORD env var is required");
  process.exit(1);
}

let sessionCookie = '';
let csrfToken = '';

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port: 3000,
      path: path,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };
    if (sessionCookie) opts.headers['Cookie'] = sessionCookie;
    if (csrfToken) opts.headers['X-CSRF-Token'] = csrfToken;

    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: data
        });
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function login() {
  const res = await request('POST', '/api/login', { password: ADMIN_PASSWORD });
  if (res.status !== 200) throw new Error("Login failed");
  const parsed = JSON.parse(res.data);
  csrfToken = parsed.csrf;
  const setCookie = res.headers['set-cookie'] || [];
  sessionCookie = setCookie[0].split(';')[0];
}

function testTelnet(expectPrompt) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let dataStr = '';
    socket.connect(2323, '127.0.0.1', () => {
      // connected
    });
    socket.on('data', (d) => {
      dataStr += d.toString();
    });
    socket.on('close', () => {
      if (expectPrompt) {
        resolve(dataStr.includes('router login'));
      } else {
        resolve(dataStr === '');
      }
    });
    socket.on('error', () => {
      resolve(!expectPrompt); // if errored immediately, count as no prompt
    });
    
    // Safety timeout
    setTimeout(() => {
      socket.destroy();
    }, 500);
  });
}

function assert(condition, msg) {
  if (!condition) {
    console.error(`[FAIL] ${msg}`);
    throw new Error('Assertion failed');
  }
  console.log(`[PASS] ${msg}`);
}

async function run() {
  try {
    await login();

    // POST /api/bans for 127.0.0.1
    const banRes = await request('POST', '/api/bans', { ip: '127.0.0.1', reason: 'Flow test', hours: 1 });
    
    // Check if ALLOW_LOCAL_BAN is working
    if (banRes.status === 403) {
      let body;
      try { body = JSON.parse(banRes.data); } catch(e) {}
      assert(body && body.error === 'this address can never be banned', "Server answered 403 { error: 'this address can never be banned' } for local ban (ALLOW_LOCAL_BAN=0 expected)");
      return; // End of test for this mode
    }

    assert(banRes.status === 201, "Ban 127.0.0.1 succeeds (ALLOW_LOCAL_BAN=1)");

    // (1) new Telnet connection closed immediately with no banner
    const telnetClosed = await testTelnet(false);
    assert(telnetClosed, "(1) Telnet connection closed immediately with no banner");

    // Wait a brief moment for DB write
    await new Promise(r => setTimeout(r, 200));

    // (2) BLOCKED row appears in /api/events
    const evRes = await request('GET', '/api/events');
    const events = JSON.parse(evRes.data);
    const hasBlocked = events.some(e => e.method === 'BLOCKED' && e.protocol === 'telnet');
    assert(hasBlocked, "(2) BLOCKED row appears in /api/events");

    // (3) dashboard still works
    const dbRes = await request('GET', '/api/stats');
    assert(dbRes.status === 200, "(3) Dashboard (port 3000) still works");

    // NEW: API input validation tests
    const badReasonRes = await request('POST', '/api/bans', { ip: '127.0.0.1', reason: 'a'.repeat(201), hours: 1 });
    assert(badReasonRes.status === 400, "POST /api/bans with 201-character reason answers 400");
    
    const badHoursRes = await request('POST', '/api/bans', { ip: '127.0.0.1', reason: 'test', hours: 0 });
    assert(badHoursRes.status === 400, "POST /api/bans with hours=0 answers 400");
    
    const badIpRes = await request('POST', '/api/bans', { ip: 'abc', reason: 'test', hours: 1 });
    if (badIpRes.status !== 400) console.log("badIpRes was:", badIpRes.status, badIpRes.data);
    assert(badIpRes.status === 400, "POST /api/bans with invalid ip answers 400");

    // NEW: 10 FTP connections in 5 seconds (to avoid telnet's rate limit from earlier)
    function testFtp() {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.connect(2121, '127.0.0.1');
        socket.on('close', () => resolve());
        socket.on('error', () => resolve());
        setTimeout(() => socket.destroy(), 500);
      });
    }

    const evBefore = JSON.parse((await request('GET', '/api/events')).data);
    let promises = [];
    for (let i = 0; i < 10; i++) {
      promises.push(testFtp());
    }
    await Promise.all(promises);
    await new Promise(r => setTimeout(r, 200)); // wait for db writes
    
    const evAfter = JSON.parse((await request('GET', '/api/events')).data);
    const beforeIds = new Set(evBefore.map(e => e.id));
    const newEvents = evAfter.filter(e => !beforeIds.has(e.id));
    const blockedRows = newEvents.filter(e => e.method === 'BLOCKED');
    const connectRows = newEvents.filter(e => e.method === 'CONNECT');
    const disconnectRows = newEvents.filter(e => e.method === 'DISCONNECT');
    
    if (blockedRows.length !== 1) {
      console.log("newEvents total:", newEvents.length);
      console.log("blockedRows count:", blockedRows.length);
      console.log("newEvents:", JSON.stringify(newEvents, null, 2));
    }
    assert(blockedRows.length === 1, "10 FTP connections in 5 seconds produces exactly 1 BLOCKED row");
    assert(connectRows.length === 0, "No CONNECT rows for banned IP");
    assert(disconnectRows.length === 0, "No DISCONNECT rows for banned IP");

    // (4) POST unban
    const unbanRes = await request('POST', '/api/bans/127.0.0.1/unban');
    assert(unbanRes.status === 200, "(4) POST /api/bans/127.0.0.1/unban succeeds");

    // (5) new Telnet connection gets login prompt again
    const telnetPrompt = await testTelnet(true);
    assert(telnetPrompt, "(5) Telnet connection gets login prompt again");

  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  } finally {
    // always unban at the end
    try {
      await request('POST', '/api/bans/127.0.0.1/unban');
    } catch (e) {}

    // Show that GET /api/bans returns an empty list
    try {
      const res = await request('GET', '/api/bans');
      const activeBans = JSON.parse(res.data);
      console.log(`[HTTP CHECK] GET /api/bans returned ${activeBans.length} active bans`);
    } catch (e) {
      console.log(`[HTTP CHECK] Error fetching bans: ${e.message}`);
    }
  }
}

run();
