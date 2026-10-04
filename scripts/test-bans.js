const fs = require('fs');
const path = require('path');
const bans = require('../sensor/bans');

const { DatabaseSync: Database } = require('node:sqlite');

const tempDbPath = path.join(__dirname, '..', 'temp_test_bans.db');
let db;

function setup() {
  if (fs.existsSync(tempDbPath)) fs.unlinkSync(tempDbPath);
  db = new Database(tempDbPath);
  db.exec(`
    CREATE TABLE bans (
      ip TEXT PRIMARY KEY,
      reason TEXT,
      created_at TEXT,
      expires_at TEXT,
      active INTEGER
    );
  `);
  bans.__testClearMap();
  process.env.ALLOW_LOCAL_BAN = '0';
  process.env.WHITELIST = '';
}

function teardown() {
  if (db) db.close();
  if (fs.existsSync(tempDbPath)) fs.unlinkSync(tempDbPath);
  bans.__testClearMap();
}

function assert(condition, message) {
  if (!condition) {
    console.error(`[FAIL] ${message}`);
    teardown();
    process.exit(1);
  }
  console.log(`[PASS] ${message}`);
}

try {
  setup();

  // a. normalizeIp
  assert(bans.normalizeIp('::ffff:1.2.3.4') === '1.2.3.4', "normalizeIp('::ffff:1.2.3.4') gives '1.2.3.4'");
  assert(bans.normalizeIp('abc') === null, "normalizeIp('abc') gives null");

  // b. canBan refuses defaults
  assert(!bans.canBan('::1').ok, "canBan refuses ::1");
  assert(!bans.canBan('127.0.0.1').ok, "canBan refuses 127.0.0.1");
  assert(!bans.canBan('10.1.2.3').ok, "canBan refuses 10.1.2.3");
  assert(!bans.canBan('192.168.1.5').ok, "canBan refuses 192.168.1.5");
  assert(!bans.canBan('0.0.0.0').ok, "canBan refuses 0.0.0.0");

  // c. ALLOW_LOCAL_BAN=1 allows 127.0.0.1 but still refuses 0.0.0.0
  process.env.ALLOW_LOCAL_BAN = '1';
  assert(bans.canBan('127.0.0.1').ok, "ALLOW_LOCAL_BAN=1 allows 127.0.0.1");
  assert(!bans.canBan('0.0.0.0').ok, "ALLOW_LOCAL_BAN=1 refuses 0.0.0.0");

  // d. a WHITELIST ip is refused even with ALLOW_LOCAL_BAN=1
  process.env.WHITELIST = '10.0.0.5';
  assert(!bans.canBan('10.0.0.5').ok, "WHITELIST ip is refused even with ALLOW_LOCAL_BAN=1");
  process.env.WHITELIST = ''; // reset

  // e. addBan/removeBan logic
  bans.addBan(db, '8.8.8.8', 'test');
  assert(bans.isBanned('8.8.8.8') === true, "after addBan of 8.8.8.8 isBanned is true");
  bans.removeBan(db, '8.8.8.8');
  assert(bans.isBanned('8.8.8.8') === false, "after removeBan it is false");

  // f. fake clock expiry
  bans.addBan(db, '9.9.9.9', 'clock', 1); // 1 hour
  assert(bans.isBanned('9.9.9.9') === true, "banned before time shift");
  const originalNow = Date.now;
  Date.now = () => originalNow() + (61 * 60 * 1000); // 61 minutes later
  assert(bans.isBanned('9.9.9.9') === false, "ban with hours=1 counts as not banned when clock is 61 minutes later");
  Date.now = originalNow; // restore

  // g. limits on reason and hours
  let threwLength = false;
  try {
    bans.addBan(db, '7.7.7.7', 'a'.repeat(201), 24);
  } catch (e) {
    threwLength = true;
  }
  assert(threwLength, "reason longer than 200 chars is refused");
  let threw0 = false;
  try { bans.addBan(db, '7.7.7.7', 'reason', 0); } catch (e) { threw0 = true; }
  assert(threw0, "hours=0 is refused");
  
  let threw9999 = false;
  try { bans.addBan(db, '7.7.7.7', 'reason', 9999); } catch (e) { threw9999 = true; }
  assert(threw9999, "hours=9999 is refused");

  // h. ban survives restart
  bans.addBan(db, '1.1.1.1', 'restart-test', 24);
  bans.__testClearMap(); // simulate restart
  assert(bans.isBanned('1.1.1.1') === false, "cleared map -> not banned");
  bans.loadBans(db);
  assert(bans.isBanned('1.1.1.1') === true, "a banned IP survives a restart (reload from temp db)");

  console.log('All tests passed.');
} finally {
  teardown();
}
