/**
 * Export Service & CI/CD Quality Gate — Phase 4
 * WebVitals
 *
 * Coordinates SARIF 2.1.0, Markdown exports, and deterministic CI/CD build gates.
 */

'use strict';

const { scanRepository } = require('../storage/scanRepository');
const { exportToSarif } = require('./sarifExporter');
const { exportToMarkdown } = require('./markdownExporter');

/**
 * Generates SARIF 2.1.0 export for a scan.
 * @param {string} scanId
 */
function getSarifReport(scanId) {
  const scanReport = scanRepository.getScan(scanId);
  if (!scanReport) {
    const err = new Error(`Scan not found: ${scanId}`);
    err.code = 'SCAN_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }
  return exportToSarif(scanReport);
}

/**
 * Generates Markdown audit report for a scan.
 * @param {string} scanId
 */
function getMarkdownReport(scanId) {
  const scanReport = scanRepository.getScan(scanId);
  if (!scanReport) {
    const err = new Error(`Scan not found: ${scanId}`);
    err.code = 'SCAN_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }
  return exportToMarkdown(scanReport);
}

/**
 * Evaluates a deterministic CI/CD quality gate against a scan score.
 *
 * @param {string} scanId
 * @param {number} [minScore=80]
 * @returns {{ passed: boolean, statusCode: number, result: object }}
 */
function evaluateQualityGate(scanId, minScore = 80) {
  const scanReport = scanRepository.getScan(scanId);
  if (!scanReport) {
    const err = new Error(`Scan not found: ${scanId}`);
    err.code = 'SCAN_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }

  const threshold = typeof minScore === 'number' && !isNaN(minScore)
    ? Math.max(0, Math.min(100, minScore))
    : 80;

  const score = scanReport.score ?? 0;
  const passed = score >= threshold;

  return {
    passed,
    statusCode: passed ? 200 : 422,
    result: {
      passed,
      score,
      minimumScore: threshold,
      grade: scanReport.grade || 'F',
      scanId,
      target: scanReport.hostname,
      failedControlsCount: (scanReport.findings || []).filter((f) => f.status === 'FAIL').length,
      reason: passed
        ? `Security score ${score} meets or exceeds configured gate threshold of ${threshold}.`
        : `Security score ${score} is below configured gate threshold of ${threshold}.`,
      timestamp: new Date().toISOString(),
    },
  };
}

module.exports = {
  getSarifReport,
  getMarkdownReport,
  evaluateQualityGate,
};
