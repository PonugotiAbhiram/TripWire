/**
 * scripts/test-severity.js
 * 
 * Unit Test Suite for Threat Severity Scoring Engine (sensor/severity.js)
 * Evaluates pure function `computeSeverity` against mock label sets.
 */

const { computeSeverity } = require('../sensor/severity');

let hasFailed = false;

function runTest(name, labels, expectedLevel, expectedScore, config) {
  try {
    const result = computeSeverity(labels, config);
    const passLevel = result.level === expectedLevel;
    const passScore = expectedScore === undefined || result.score === expectedScore;

    if (passLevel && passScore) {
      console.log(`[PASS] ${name}`);
    } else {
      console.log(`[FAIL] ${name} - Got: { level: '${result.level}', score: ${result.score} }, Expected: { level: '${expectedLevel}', score: ${expectedScore} }`);
      hasFailed = true;
    }
  } catch (err) {
    console.log(`[FAIL] ${name} - Exception thrown:`, err.message);
    hasFailed = true;
  }
}

console.log('=== STARTING SEVERITY ENGINE UNIT TESTS ===\n');

// Case a: [] gives None, score 0
runTest('a. [] gives None, score 0', [], 'None', 0);

// Case b: ['port_scan'] gives Low
runTest('b. [port_scan] gives Low', ['port_scan'], 'Low', 1);

// Case c: ['web_probe'] gives Low
runTest('c. [web_probe] gives Low', ['web_probe'], 'Low', 1);

// Case d: ['brute_force'] gives Medium
runTest('d. [brute_force] gives Medium', ['brute_force'], 'Medium', 2);

// Case e: ['port_scan','web_probe'] gives Medium
runTest('e. [port_scan, web_probe] gives Medium', ['port_scan', 'web_probe'], 'Medium', 2);

// Case f: ['brute_force','web_probe'] gives High
runTest('f. [brute_force, web_probe] gives High', ['brute_force', 'web_probe'], 'High', 3);

// Case g: ['port_scan','brute_force','web_probe'] gives High, score 4
runTest('g. [port_scan, brute_force, web_probe] gives High, score 4', ['port_scan', 'brute_force', 'web_probe'], 'High', 4);

// Case h: ['port_scan','port_scan'] counts once, gives Low
runTest('h. [port_scan, port_scan] counts once, gives Low', ['port_scan', 'port_scan'], 'Low', 1);

// Case i: ['unknown_label'] gives None
runTest('i. [unknown_label] gives None', ['unknown_label'], 'None', 0);

// Case j: ['constructor'] gives None, score 0
runTest('j. [constructor] gives None, score 0', ['constructor'], 'None', 0);

// Case k: custom config { points: { port_scan: 5 }, levels: { low: 1, medium: 3, high: 5 } } with ['port_scan'] gives High
const customConfigK = {
  points: { port_scan: 5 },
  levels: { low: 1, medium: 3, high: 5 }
};
runTest('k. custom config with [port_scan] gives High', ['port_scan'], 'High', 5, customConfigK);

console.log('\n=============================================');
if (hasFailed) {
  console.log('=== TEST SUITE FAILED ===');
  process.exit(1);
} else {
  console.log('=== ALL UNIT TESTS PASSED ===');
  process.exit(0);
}
