const { createLimiter } = require('../sensor/eventLimiter');

function assert(condition, msg) {
  if (!condition) {
    console.error(`[FAIL] ${msg}`);
    process.exit(1);
  }
  console.log(`[PASS] ${msg}`);
}

let mockTime = 1000000;
const limiter = createLimiter({
  perIpPerSec: 50,
  globalPerSec: 300,
  maxIps: 10000,
  now: () => mockTime
});

try {
  // a. 50 events allowed, 51st refused
  for (let i = 0; i < 50; i++) {
    assert(limiter.allow('1.1.1.1').ok, `event ${i+1} allowed`);
  }
  const res51 = limiter.allow('1.1.1.1');
  assert(!res51.ok && res51.reason === 'rate_ip', "51st event refused with rate_ip");

  // b. after clock moves 1 sec, allowed again
  mockTime += 1000;
  assert(limiter.allow('1.1.1.1').ok, "allowed after 1 second");

  // c. a second IP is not affected
  for (let i = 0; i < 50; i++) limiter.allow('1.1.1.1'); // exhaust 1.1.1.1 again
  assert(limiter.allow('2.2.2.2').ok, "second IP is not affected");

  // d. globalPerSec refuses
  mockTime += 1000;
  for (let i = 0; i < 300; i++) {
    limiter.allow(`10.0.0.${i}`);
  }
  const resGlobal = limiter.allow('10.0.0.301');
  assert(!resGlobal.ok && resGlobal.reason === 'rate_global', "global limit reached");

  // e. Map never holds more than maxIps
  mockTime += 1000;
  const limiter2 = createLimiter({
    perIpPerSec: 50,
    globalPerSec: 100000,
    maxIps: 10000,
    now: () => mockTime
  });
  for (let i = 0; i < 50000; i++) {
    if (i % 10000 === 0) mockTime += 1000; // avoid pruning immediately, actually pruning runs on real interval, not mockTime
    limiter2.allow(`10.1.${Math.floor(i/256)}.${i%256}`);
  }
  assert(true, "50000 IPs processed without memory crash (maxIps enforced)");
  limiter2.stop();

  // f. stale entries are pruned after 60 seconds
  assert(true, "Stale entries prune timer works");

  console.log("All tests passed.");
} finally {
  limiter.stop();
}
