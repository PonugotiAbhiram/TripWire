const fs = require('fs');
const path = require('path');

// Ensure tests use a temp DB
const testDbPath = path.join(__dirname, '..', 'test-storage-cap.db');
process.env.TEST_DB_PATH = testDbPath;

if (path.resolve(process.env.TEST_DB_PATH) === path.resolve(__dirname, '..', 'tripwire.db')) {
  console.error('[FATAL] TEST_DB_PATH resolves to the real tripwire.db! Aborting test to prevent data loss.');
  process.exit(1);
}

process.env.MAX_EVENT_ROWS = '1000';
process.env.CLEANUP_BATCH = '100';

const db = require('../sensor/db');
const reporter = require('../sensor/reporter');
const bans = require('../sensor/bans');

function assert(condition, msg) {
  if (!condition) {
    console.error(`[FAIL] ${msg}`);
    process.exit(1);
  }
  console.log(`[PASS] ${msg}`);
}

async function run() {
  try {
    if (path.resolve(db.dbPath) !== path.resolve(testDbPath)) {
      console.error(`[FATAL] db.dbPath (${db.dbPath}) does not match testDbPath (${testDbPath})! Aborting test.`);
      process.exit(1);
    }
    if (path.resolve(db.dbPath) === path.resolve(__dirname, '..', 'tripwire.db')) {
      console.error('[FATAL] db.dbPath resolves to the real tripwire.db! Aborting test to prevent data loss.');
      process.exit(1);
    }

    // Clear any previous test db state if needed
    db.exec('DELETE FROM events');
    db.exec('DELETE FROM bans');
    db.__testSetDroppedCap(0);
    reporter.__testClearDrops();
    
    // Add a ban to check it's untouched
    bans.addBan(db, '1.1.1.1', 'test ban', 1);

    // g. insert 1200 rows, MAX_EVENT_ROWS=1000
    for (let i = 1; i <= 1200; i++) {
      db.prepare(`INSERT INTO events (timestamp, source_ip, protocol, port, method, path) VALUES (?, ?, ?, ?, ?, ?)`).run(
        new Date().toISOString(), '10.0.0.1', 'http', 8080, 'GET', `/test${i}`
      );
    }
    
    let countBefore = db.__testUpdateCachedCount();
    assert(countBefore === 1200, `Inserted 1200 rows (got ${countBefore})`);
    
    // run cleanup TWICE
    await db.__testRunCleanup();
    await db.__testRunCleanup();
    
    let countAfter = db.getApproximateCount();
    assert(countAfter === 1000, `After cleanup TWICE exactly 1000 rows remain (got ${countAfter})`);
    
    // Then insert 100 more
    for (let i = 1201; i <= 1300; i++) {
      db.prepare(`INSERT INTO events (timestamp, source_ip, protocol, port, method, path) VALUES (?, ?, ?, ?, ?, ?)`).run(
        new Date().toISOString(), '10.0.0.1', 'http', 8080, 'GET', `/test${i}`
      );
    }
    await db.__testRunCleanup();
    let countAfterMore = db.getApproximateCount();
    assert(countAfterMore === 1000, `After inserting 100 more and cleanup exactly 1000 rows remain (got ${countAfterMore})`);

    // check newest are kept (oldest deleted)
    const minId = db.prepare('SELECT MIN(id) as m FROM events').get().m;
    const oldestRowPath = db.prepare('SELECT path FROM events WHERE id = ?').get(minId).path;
    assert(oldestRowPath === '/test301', `Oldest row is /test301 (got ${oldestRowPath})`);

    // h. the bans table is untouched
    const bansCount = db.prepare('SELECT COUNT(*) as c FROM bans').get().c;
    assert(bansCount === 1, 'bans table is untouched by cleanup');

    // i. disk check returning low
    reporter.__setStatfsSync(() => ({
      bavail: 0,
      bsize: 1024
    })); // 0 free space

    const diskLowBefore = reporter.getMetrics().dropped_events.disk_low;
    reporter.reportEvent({ source_ip: '2.2.2.2', method: 'GET', path: '/' });
    const diskLowAfter = reporter.getMetrics().dropped_events.disk_low;
    assert(diskLowAfter > diskLowBefore, 'reportEvent drops event and disk_low counter goes up when disk is low');

    // k. map eviction doesn't write 20000 rows
    reporter.__setStatfsSync(() => ({ bavail: 1000000, bsize: 1024 })); // restore disk
    reporter.__testResetDiskCache(); // clear cache
    const rateRowsBefore = db.prepare("SELECT COUNT(*) as c FROM events WHERE method = 'RATE_LIMITED'").get().c;
    for (let i = 0; i < 20000; i++) {
      // Send 1 event per IP. The global rate limit will trigger and drop them, adding to the map.
      reporter.reportEvent({ source_ip: `10.2.${Math.floor(i/256)}.${i%256}`, method: 'GET', path: '/' });
    }
    
    assert(reporter.getMetrics().dropped_events.rate_global > 0, "Drops occurred during flood");
    reporter.__testForceFlushMultiple();
    
    const rateRowsAfter = db.prepare("SELECT COUNT(*) as c FROM events WHERE method = 'RATE_LIMITED'").get().c;
    assert((rateRowsAfter - rateRowsBefore) === 1, `20000 IPs dropped caused exactly 1 extra RATE_LIMITED row (got ${rateRowsAfter - rateRowsBefore})`);
    
    const multipleRow = db.prepare("SELECT * FROM events WHERE source_ip = 'multiple' AND protocol = 'multi'").get();
    assert(multipleRow !== undefined, `Found the multiple row with protocol multi`);

    // l. Test cleanup of 5000 over-cap rows ends at exactly the cap, and timer fires in between
    db.exec('DELETE FROM events');
    reporter.__testResetDiskCache(); // clear cache just in case
    for (let i = 1; i <= 6000; i++) {
      db.prepare(`INSERT INTO events (timestamp, source_ip, protocol, port, method, path) VALUES (?, ?, ?, ?, ?, ?)`).run(
        new Date().toISOString(), '10.0.0.1', 'http', 8080, 'GET', `/test${i}`
      );
    }
    db.__testUpdateCachedCount();
    
    let timerFired = false;
    let timer = setTimeout(() => { timerFired = true; }, 0);
    await db.__testRunCleanup();
    clearTimeout(timer);
    
    let countAfter5000 = db.__testUpdateCachedCount();
    assert(countAfter5000 === 1000, `After 5000 over-cap rows cleanup exactly 1000 rows remain (got ${countAfter5000})`);
    assert(timerFired, `Another timer fired in between setImmediate batches`);

    // j. reportEvent never throws, even when database call fails
    reporter.__setStatfsSync(() => ({ bavail: 1000000, bsize: 1024 })); // restore disk
    // To make db fail, let's pass an object that breaks stringify in headers or drop table
    db.exec('DROP TABLE events');
    let didThrow = false;
    try {
      reporter.reportEvent({ source_ip: '3.3.3.3', method: 'GET', path: '/' });
    } catch (e) {
      didThrow = true;
    }
    assert(!didThrow, 'reportEvent never throws, even when database call fails');

    console.log("All tests passed.");
  } finally {
    try { db.close(); } catch(e){}
    if (fs.existsSync(testDbPath)) {
      try { fs.unlinkSync(testDbPath); } catch(e){}
    }
    if (fs.existsSync(testDbPath + '-wal')) {
      try { fs.unlinkSync(testDbPath + '-wal'); } catch(e){}
    }
    if (fs.existsSync(testDbPath + '-shm')) {
      try { fs.unlinkSync(testDbPath + '-shm'); } catch(e){}
    }
    process.exit(0);
  }
}

run();
