/**
 * sensor/severity.js
 * 
 * Threat Severity Scoring Engine
 * ------------------------------
 * Calculates risk scores and threat levels (None, Low, Medium, High)
 * based on attack labels detected by `sensor/labels.js`.
 */

const net = require('net');
const labelsModule = require('./labels');

const SEVERITY_CONFIG = {
  points: {
    port_scan: 1,
    web_probe: 1,
    brute_force: 2
  },
  levels: {
    low: 1,
    medium: 2,
    high: 3
  }
};

/**
 * Calculates total score and threat level for an array of attack labels.
 * 
 * @param {Array<string>} labels - Array of label strings
 * @param {object} [config=SEVERITY_CONFIG] - Configurable points and levels map
 * @returns {{ score: number, level: string }}
 */
function computeSeverity(labels, config = SEVERITY_CONFIG) {
  if (!Array.isArray(labels) || labels.length === 0) {
    return { score: 0, level: 'None' };
  }

  const activeConfig = config || SEVERITY_CONFIG;
  const pointsMap = activeConfig.points || SEVERITY_CONFIG.points;
  const levelsMap = activeConfig.levels || SEVERITY_CONFIG.levels;

  const uniqueLabels = new Set(labels);
  let score = 0;

  for (const label of uniqueLabels) {
    if (label && typeof label === 'string' && Object.hasOwn(pointsMap, label)) {
      const pts = Number(pointsMap[label]);
      if (!isNaN(pts)) {
        score += pts;
      }
    }
  }

  let level = 'None';
  if (score >= levelsMap.high) {
    level = 'High';
  } else if (score >= levelsMap.medium) {
    level = 'Medium';
  } else if (score >= levelsMap.low) {
    level = 'Low';
  }

  return { score, level };
}

/**
 * Retrieves attack assessment for an IP address including labels, score, level, and summary.
 * 
 * @param {string} ip - Source IP address
 * @returns {object|null} Assessment object or null if IP is invalid
 */
function getAssessment(ip) {
  if (!ip || typeof ip !== 'string' || net.isIP(ip) === 0) {
    return null;
  }

  const labelsData = labelsModule.getLabels(ip);
  if (!labelsData) {
    return null;
  }

  const { labels, reasons, tool_hints } = labelsData;
  const { score, level } = computeSeverity(labels);

  let summary = 'No attack behavior detected';
  if (level !== 'None' && Array.isArray(reasons) && reasons.length > 0) {
    summary = `${level}: ${reasons.join(', ')}`;
  }

  return {
    ip,
    level,
    score,
    labels,
    reasons,
    tool_hints,
    summary
  };
}

module.exports = {
  SEVERITY_CONFIG,
  computeSeverity,
  getAssessment
};
