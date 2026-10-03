/**
 * scripts/demo-attacker.js
 * 
 * TripWire Honeypot - Step 2 Demo Attacker Script
 * ------------------------------------------------
 * Generates controlled, repeatable test traffic against a local TripWire sensor.
 * Uses ONLY built-in Node.js modules (net, http).
 * 
 * SAFETY NOTICE:
 * - Target defaults to 127.0.0.1.
 * - Only permits localhost (127.x.x.x, ::1) or private IP ranges (10.x, 192.168.x, 172.16-31.x).
 * - Hard limits on port count, password attempts, and probed paths.
 */

const net = require('net');
const http = require('http');

// ============================================================================
// HARD LIMIT CONSTANTS & CONFIGURATION
// ============================================================================
const MAX_PORTS = 20;
const MAX_PASSWORD_GUESSES = 12; // Hard cap at max 12 password attempts (HTTP + Telnet)
const MAX_WEB_PATHS = 5;
const DEFAULT_TARGET = '127.0.0.1';
const DEFAULT_DELAY = 200;
const DEFAULT_PORT = 8080;
const USER_AGENT = 'TripWire-Demo-Attacker/1.0';

// ============================================================================
// SAFETY & IP VALIDATION HELPER
// ============================================================================

/**
 * Parses and strictly checks whether a target IP string is localhost or a private IPv4/IPv6 range.
 * No string prefix matching - strictly uses net.isIP and octet numerical validation.
 * @param {string} targetStr 
 * @returns {boolean}
 */
function isAllowedTarget(targetStr) {
  if (targetStr === 'localhost') return true;

  const ipType = net.isIP(targetStr);
  if (ipType === 4) {
    const parts = targetStr.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return false;
    }
    const [a, b] = parts;
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 10.0.0.0/8 (Private)
    if (a === 10) return true;
    // 192.168.0.0/16 (Private)
    if (a === 192 && b === 168) return true;
    // 172.16.0.0/12 (Private 172.16.0.0 - 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;
  } else if (ipType === 6) {
    // IPv6 Loopback
    if (targetStr === '::1' || targetStr === '0:0:0:0:0:0:0:1') return true;
  }

  return false;
}

/**
 * Prints CLI usage instructions and exits.
 */
function printUsageAndExit(message) {
  if (message) {
    console.error(`\n[ERROR] ${message}`);
  }
  console.log(`
Usage: node scripts/demo-attacker.js [options]

Options:
  --target <ip>    Target IP address or localhost (default: 127.0.0.1)
                   Must be localhost or private range (127.x, 10.x, 192.168.x, 172.16-31.x, ::1)
  --delay <ms>     Delay between requests in milliseconds (default: 200, must be >= 0)
  --phase <1|2|3>  Run only a specific phase (1: Port Sweep, 2: Passwords, 3: Web Paths)
`);
  process.exit(1);
}

// ============================================================================
// CLI ARGUMENT PARSER
// ============================================================================
function parseArgs() {
  const args = process.argv.slice(2);
  let target = DEFAULT_TARGET;
  let delay = DEFAULT_DELAY;
  let phase = null; // null means run all phases

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--target') {
      if (i + 1 >= args.length) printUsageAndExit('Missing value for --target');
      target = args[++i];
    } else if (arg === '--delay') {
      if (i + 1 >= args.length) printUsageAndExit('Missing value for --delay');
      delay = Number(args[++i]);
      if (isNaN(delay) || delay < 0) {
        printUsageAndExit('Invalid --delay value. Must be a non-negative number.');
      }
    } else if (arg === '--phase') {
      if (i + 1 >= args.length) printUsageAndExit('Missing value for --phase');
      phase = Number(args[++i]);
      if (isNaN(phase) || ![1, 2, 3].includes(phase)) {
        printUsageAndExit('Invalid --phase value. Must be 1, 2, or 3.');
      }
    } else if (arg === '-h' || arg === '--help') {
      printUsageAndExit();
    } else {
      printUsageAndExit(`Unknown option: ${arg}`);
    }
  }

  return { target, delay, phase };
}

// Helper utility for async delays
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// ============================================================================
// PHASE IMPLEMENTATIONS
// ============================================================================

/**
 * Phase 1: TCP Port Sweep
 */
async function runPhase1(target, delay) {
  console.log('\n===========================================================');
  console.log('  PHASE 1: TCP PORT SWEEP');
  console.log('===========================================================');

  const ports = [21, 22, 23, 80, 2121, 2222, 2323, 3000, 8080, 8081];
  const targetPorts = ports.slice(0, MAX_PORTS);

  let openCount = 0;
  let closedCount = 0;
  const startTime = Date.now();

  for (const port of targetPorts) {
    await new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(500);

      socket.on('connect', () => {
        console.log(`  [+] Port ${port.toString().padEnd(5)} : OPEN`);
        openCount++;
        socket.destroy();
        resolve();
      });

      const handleError = () => {
        console.log(`  [-] Port ${port.toString().padEnd(5)} : CLOSED`);
        closedCount++;
        socket.destroy();
        resolve();
      };

      socket.on('timeout', handleError);
      socket.on('error', handleError);

      socket.connect(port, target);
    });
  }

  const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log(`\n  [Phase 1 Complete] Swept ${targetPorts.length} ports in ${durationSec}s (${openCount} open, ${closedCount} closed)`);

  return { portsTested: targetPorts.length };
}

/**
 * Phase 2: Password Guessing (HTTP POST to /login)
 */
async function runPhase2(target, delay) {
  console.log('\n===========================================================');
  console.log('  PHASE 2: PASSWORD GUESSING (HTTP POST)');
  console.log('===========================================================');

  const formAttempts = [
    { username: 'admin', password: 'admin' },
    { username: 'root', password: '123456' },
    { username: 'admin', password: 'password' },
    { username: 'admin', password: 'admin123' },
    { username: 'user', password: 'user' },
    { username: 'root', password: 'toor' }
  ];

  const jsonAttempts = [
    { username: 'admin', password: 'secret', format: 'json' },
    { user: 'guest', pass: 'guest123', format: 'json' }
  ];

  const allAttempts = [...formAttempts, ...jsonAttempts].slice(0, MAX_PASSWORD_GUESSES);
  let sentCount = 0;

  for (const attempt of allAttempts) {
    const isJson = attempt.format === 'json';
    let bodyData;
    let contentType;
    let userDisplay;
    let passDisplay;

    if (isJson) {
      bodyData = JSON.stringify(attempt);
      contentType = 'application/json';
      userDisplay = attempt.username || attempt.user;
      passDisplay = attempt.password || attempt.pass;
    } else {
      bodyData = `username=${encodeURIComponent(attempt.username)}&password=${encodeURIComponent(attempt.password)}`;
      contentType = 'application/x-www-form-urlencoded';
      userDisplay = attempt.username;
      passDisplay = attempt.password;
    }

    await new Promise((resolve) => {
      const reqOptions = {
        hostname: target,
        port: DEFAULT_PORT,
        path: '/login',
        method: 'POST',
        headers: {
          'Content-Type': contentType,
          'Content-Length': Buffer.byteLength(bodyData),
          'User-Agent': USER_AGENT
        }
      };

      const req = http.request(reqOptions, (res) => {
        const typeStr = isJson ? '[POST JSON]' : '[POST Form]';
        console.log(`  ${typeStr.padEnd(12)} Credentials: ${userDisplay}:${passDisplay} -> Status: ${res.statusCode}`);
        sentCount++;
        res.resume(); // consume response stream
        resolve();
      });

      req.on('error', (err) => {
        const typeStr = isJson ? '[POST JSON]' : '[POST Form]';
        console.log(`  ${typeStr.padEnd(12)} Credentials: ${userDisplay}:${passDisplay} -> Error: ${err.message}`);
        sentCount++;
        resolve();
      });

      req.write(bodyData);
      req.end();
    });

    if (delay > 0) await sleep(delay);
  }

  console.log(`\n  [HTTP POST Complete] Sent ${sentCount} HTTP login attempts to http://${target}:${DEFAULT_PORT}/login`);

  // --- Telnet Password Guessing (Port 2323) ---
  console.log('  --- Telnet Password Guessing (Port 2323) ---');
  const telnetAttempts = [
    { username: 'admin', password: 'admin' },
    { username: 'root', password: '123456' },
    { username: 'admin', password: 'password' }
  ];

  await new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(5000);

    let receiveBuffer = '';

    socket.on('data', (chunk) => {
      receiveBuffer += chunk.toString('utf-8');
    });

    function waitForPattern(regex, timeoutMs = 2000) {
      return new Promise((res) => {
        // 1. Check if pattern is already in receiveBuffer before waiting
        const initialMatch = receiveBuffer.match(regex);
        if (initialMatch) {
          const idx = receiveBuffer.search(regex);
          receiveBuffer = receiveBuffer.slice(idx + initialMatch[0].length);
          return res(true);
        }

        let timer;
        function checkBuffer() {
          const m = receiveBuffer.match(regex);
          if (m) {
            if (timer) clearTimeout(timer);
            socket.removeListener('data', checkBuffer);
            const idx = receiveBuffer.search(regex);
            receiveBuffer = receiveBuffer.slice(idx + m[0].length);
            res(true);
          }
        }

        timer = setTimeout(() => {
          socket.removeListener('data', checkBuffer);
          res(false);
        }, timeoutMs);

        socket.on('data', checkBuffer);
      });
    }

    const cleanup = () => {
      socket.destroy();
      resolve();
    };

    socket.on('error', cleanup);
    socket.on('timeout', cleanup);

    socket.connect(2323, target, async () => {
      try {
        for (const attempt of telnetAttempts) {
          // Wait for login prompt
          await waitForPattern(/login:/i);
          socket.write(attempt.username + '\r\n');

          // Wait for password prompt
          await waitForPattern(/Password:/i);
          socket.write(attempt.password + '\r\n');

          // Wait for failure response
          await waitForPattern(/Login incorrect/i);
          console.log(`  [Telnet 2323] Credentials: ${attempt.username}:${attempt.password} -> Response: Login incorrect`);
          sentCount++;

          if (delay > 0) await sleep(delay);
        }
      } catch (err) {
        console.log(`  [Telnet 2323] Error: ${err.message}`);
      } finally {
        cleanup();
      }
    });
  });

  console.log(`\n  [Phase 2 Complete] Sent ${sentCount} total password guess attempts across HTTP & Telnet`);

  return { guessesSent: sentCount };
}

/**
 * Phase 3: Web Path Probing (HTTP GET)
 */
async function runPhase3(target, delay) {
  console.log('\n===========================================================');
  console.log('  PHASE 3: WEB PATH PROBING (HTTP GET)');
  console.log('===========================================================');

  const webPaths = ['/admin', '/wp-login.php', '/.env', '/phpmyadmin', '/config.php'].slice(0, MAX_WEB_PATHS);
  let probedCount = 0;

  for (const path of webPaths) {
    await new Promise((resolve) => {
      const reqOptions = {
        hostname: target,
        port: DEFAULT_PORT,
        path: path,
        method: 'GET',
        headers: {
          'User-Agent': USER_AGENT
        }
      };

      const req = http.request(reqOptions, (res) => {
        console.log(`  [GET] ${path.padEnd(16)} -> Status: ${res.statusCode}`);
        probedCount++;
        res.resume();
        resolve();
      });

      req.on('error', (err) => {
        console.log(`  [GET] ${path.padEnd(16)} -> Error: ${err.message}`);
        probedCount++;
        resolve();
      });

      req.end();
    });

    if (delay > 0) await sleep(delay);
  }

  console.log(`\n  [Phase 3 Complete] Probed ${probedCount} web paths on http://${target}:${DEFAULT_PORT}`);

  return { pathsProbed: probedCount };
}

// ============================================================================
// MAIN SCRIPT EXECUTION
// ============================================================================
async function main() {
  const { target, delay, phase } = parseArgs();

  // Safety Check: Strict IP / Localhost Validation
  if (!isAllowedTarget(target)) {
    console.error('\n[WARNING] Safety Violation: Target is not allowed.');
    console.error(`          Given target: "${target}"`);
    console.error('          Only localhost and private IP addresses are permitted:');
    console.error('          - localhost, 127.0.0.0/8, ::1');
    console.error('          - 10.0.0.0/8');
    console.error('          - 192.168.0.0/16');
    console.error('          - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)');
    console.error('\n          Target must be a device you own.');
    console.error('          Exiting immediately.\n');
    process.exit(1);
  }

  // Print Banner
  console.log('===========================================================');
  console.log('  TRIPWIRE DEMO ATTACKER');
  console.log('  Only run against your own TripWire.');
  console.log('  Target must be a device you own.');
  console.log('===========================================================');
  console.log(`  [+] Target Host     : ${target}`);
  console.log(`  [+] Request Delay   : ${delay} ms`);
  console.log(`  [+] Phase Mode      : ${phase ? `Phase ${phase} only` : 'All 3 Phases'}`);
  console.log(`  [+] User-Agent      : ${USER_AGENT}`);
  console.log('===========================================================');

  const globalStartTime = Date.now();
  let totalPorts = 0;
  let totalGuesses = 0;
  let totalPaths = 0;

  try {
    if (!phase || phase === 1) {
      const res1 = await runPhase1(target, delay);
      totalPorts = res1.portsTested;
    }

    if (!phase || phase === 2) {
      const res2 = await runPhase2(target, delay);
      totalGuesses = res2.guessesSent;
    }

    if (!phase || phase === 3) {
      const res3 = await runPhase3(target, delay);
      totalPaths = res3.pathsProbed;
    }
  } catch (err) {
    console.error('\n[FATAL ERROR]', err.message);
  }

  const totalTimeSec = ((Date.now() - globalStartTime) / 1000).toFixed(2);

  // Final Summary
  console.log('\n===========================================================');
  console.log('  DEMO ATTACK SUMMARY');
  console.log('-----------------------------------------------------------');
  console.log(`  Target Host       : ${target}`);
  console.log(`  Ports Swept       : ${totalPorts}`);
  console.log(`  Password Guesses  : ${totalGuesses}`);
  console.log(`  Web Paths Probed  : ${totalPaths}`);
  console.log(`  Total Time Taken  : ${totalTimeSec} seconds`);
  console.log('===========================================================');
}

main();
