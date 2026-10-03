/**
 * scripts/show-profile.js
 * 
 * CLI tool to view IP profiles or list all tracked IPs in the TripWire honeypot.
 * 
 * Usage:
 *   node scripts/show-profile.js          - List all tracked IPs
 *   node scripts/show-profile.js <ip>     - Display detailed profile for <ip>
 */

const net = require('net');
const analyzer = require('../sensor/analyzer');
const labelsModule = require('../sensor/labels');

function main() {
  const targetIp = process.argv[2];

  // If no IP argument is provided, list all active IPs
  if (!targetIp) {
    const ips = analyzer.listIps(100);
    console.log(JSON.stringify(ips, null, 2));
    process.exit(0);
  }

  // Validate IP input format
  if (net.isIP(targetIp) === 0) {
    console.error('Invalid IP');
    process.exit(1);
  }

  // Retrieve IP security profile
  const profile = analyzer.getProfile(targetIp);
  if (!profile) {
    console.error(`No events for ${targetIp}`);
    process.exit(1);
  }

  // Retrieve labels, reasons, and tool hints
  const labelsData = labelsModule.getLabels(targetIp) || { labels: [], reasons: [], tool_hints: [] };

  const combinedProfile = {
    ...profile,
    labels: labelsData.labels,
    reasons: labelsData.reasons,
    tool_hints: labelsData.tool_hints
  };

  console.log(JSON.stringify(combinedProfile, null, 2));
  process.exit(0);
}

main();
