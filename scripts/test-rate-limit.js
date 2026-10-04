const assert = require('assert');
const createRateLimiter = require('../sensor/rateLimit');

let currentTime = 1000000;
const clock = () => currentTime;

const limiter = createRateLimiter(clock);

console.log("Testing per-IP limit...");
assert.strictEqual(limiter.isBlocked("192.168.1.1"), false);
limiter.addFail("192.168.1.1");
limiter.addFail("192.168.1.1");
limiter.addFail("192.168.1.1");
limiter.addFail("192.168.1.1"); // 4th fail
assert.strictEqual(limiter.isBlocked("192.168.1.1"), true, "Should be blocked after 4 fails");
assert.strictEqual(limiter.isBlocked("192.168.1.2"), true, "Global should also trigger");

console.log("Testing global limit unblock...");
currentTime += 15 * 60 * 1000; // Fast forward 15 minutes
assert.strictEqual(limiter.isBlocked("192.168.1.1"), false, "Should be unblocked after 15 minutes");
assert.strictEqual(limiter.isBlocked("192.168.1.2"), false);

console.log("Testing global limit alone...");
limiter.addFail("10.0.0.1");
limiter.addFail("10.0.0.2");
limiter.addFail("10.0.0.3");
limiter.addFail("10.0.0.4");
assert.strictEqual(limiter.isBlocked("10.0.0.5"), true, "Global limit should block the 5th attempt");
assert.strictEqual(limiter.isBlocked("10.0.0.1"), true);

console.log("Testing global limit expiry...");
currentTime += 15 * 60 * 1000;
assert.strictEqual(limiter.isBlocked("10.0.0.5"), false, "Global limit unblocked after 15 mins");

console.log("All rate-limit tests passed!");
