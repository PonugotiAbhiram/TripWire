/**
 * sensor/eventLimiter.js
 * 
 * Pure function to limit events per IP and globally per second.
 * No database dependency. Uses a Map with a memory cap.
 */

function createLimiter({ perIpPerSec, globalPerSec, maxIps = 10000, now = Date.now }) {
  const ipMap = new Map();
  let globalWindow = 0;
  let globalCount = 0;

  // Prune entries not seen for 60 seconds
  const pruneInterval = setInterval(() => {
    const currentTime = now();
    for (const [ip, state] of ipMap.entries()) {
      if (currentTime - state.lastSeen > 60000) {
        ipMap.delete(ip);
      }
    }
  }, 60000);
  if (pruneInterval.unref) pruneInterval.unref();

  return {
    allow: function(ip) {
      const currentTime = now();
      const currentWindow = Math.floor(currentTime / 1000);

      // 1. Global limit
      if (currentWindow !== globalWindow) {
        globalWindow = currentWindow;
        globalCount = 0;
      }
      globalCount++;
      if (globalCount > globalPerSec) {
        return { ok: false, reason: 'rate_global' };
      }

      // 2. IP limit
      let state = ipMap.get(ip);
      if (!state) {
        if (ipMap.size >= maxIps) {
          // Drop oldest (first in Map iteration)
          const firstKey = ipMap.keys().next().value;
          ipMap.delete(firstKey);
        }
        state = { window: currentWindow, count: 0, lastSeen: currentTime };
        ipMap.set(ip, state);
      } else {
        state.lastSeen = currentTime;
        if (state.window !== currentWindow) {
          state.window = currentWindow;
          state.count = 0;
        }
      }
      
      state.count++;
      if (state.count > perIpPerSec) {
        return { ok: false, reason: 'rate_ip' };
      }

      return { ok: true };
    },
    stop: () => clearInterval(pruneInterval)
  };
}

module.exports = { createLimiter };
