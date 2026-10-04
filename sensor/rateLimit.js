module.exports = function createRateLimiter(clock = Date.now) {
  const ipFails = new Map();
  let globalFails = [];
  const WINDOW_MS = 15 * 60 * 1000;
  const MAX_FAILS = 4;

  return {
    isBlocked(ip) {
      const now = clock();
      globalFails = globalFails.filter(t => now - t < WINDOW_MS);
      if (globalFails.length >= MAX_FAILS) return true;

      let ipFailTimes = ipFails.get(ip) || [];
      ipFailTimes = ipFailTimes.filter(t => now - t < WINDOW_MS);
      if (ipFailTimes.length >= MAX_FAILS) return true;
      
      return false;
    },
    addFail(ip) {
      const now = clock();
      globalFails = globalFails.filter(t => now - t < WINDOW_MS);
      globalFails.push(now);
      
      let ipFailTimes = ipFails.get(ip) || [];
      ipFailTimes = ipFailTimes.filter(t => now - t < WINDOW_MS);
      ipFailTimes.push(now);
      ipFails.set(ip, ipFailTimes);
    }
  };
};
