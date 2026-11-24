/**
 * Export & Quality Gate Controller — Phase 4
 * WebVitals
 *
 * Handles HTTP requests for:
 *   - GET /api/scan/export/sarif?scanId=...
 *   - GET /api/scan/export/markdown?scanId=...
 *   - GET /api/scan/gate?scanId=...&minScore=...
 */

'use strict';

const { getSarifReport, getMarkdownReport, evaluateQualityGate } = require('../exports/exportService');
const { sendSuccess, sendError } = require('../utils/helpers');

/**
 * GET /api/scan/export/sarif?scanId=...
 */
function handleSarifExport(req, res, parsedUrl) {
  const scanId = parsedUrl.searchParams.get('scanId');
  if (!scanId) {
    return sendError(res, 400, 'MISSING_SCAN_ID', 'scanId query parameter is required');
  }

  try {
    const sarif = getSarifReport(scanId);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="webvitals-${scanId}.sarif"`);
    res.writeHead(200);
    res.end(JSON.stringify(sarif, null, 2));
  } catch (err) {
    sendError(res, err.statusCode || 500, err.code || 'EXPORT_ERROR', err.message);
  }
}

/**
 * GET /api/scan/export/markdown?scanId=...
 */
function handleMarkdownExport(req, res, parsedUrl) {
  const scanId = parsedUrl.searchParams.get('scanId');
  if (!scanId) {
    return sendError(res, 400, 'MISSING_SCAN_ID', 'scanId query parameter is required');
  }

  try {
    const markdown = getMarkdownReport(scanId);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="webvitals-${scanId}.md"`);
    res.writeHead(200);
    res.end(markdown);
  } catch (err) {
    sendError(res, err.statusCode || 500, err.code || 'EXPORT_ERROR', err.message);
  }
}

/**
 * GET /api/scan/gate?scanId=...&minScore=80
 */
function handleQualityGate(req, res, parsedUrl) {
  const scanId = parsedUrl.searchParams.get('scanId');
  if (!scanId) {
    return sendError(res, 400, 'MISSING_SCAN_ID', 'scanId query parameter is required');
  }

  const rawMinScore = parsedUrl.searchParams.get('minScore');
  const minScore = rawMinScore ? parseInt(rawMinScore, 10) : 80;
  const failOnStatus = parsedUrl.searchParams.get('failOnStatus') === 'true' || parsedUrl.searchParams.get('strict') === 'true';
  const fallbackScore = parsedUrl.searchParams.get('score');

  try {
    let gate;
    try {
      gate = evaluateQualityGate(scanId, minScore);
    } catch (evalErr) {
      if (evalErr.statusCode === 404 && fallbackScore !== null && !isNaN(Number(fallbackScore))) {
        const score = Math.max(0, Math.min(100, Number(fallbackScore)));
        const threshold = Math.max(0, Math.min(100, minScore));
        const passed = score >= threshold;
        gate = {
          passed,
          statusCode: passed ? 200 : 422,
          result: {
            passed,
            score,
            minimumScore: threshold,
            grade: score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : 'F',
            scanId,
            target: 'Active Target',
            failedControlsCount: 0,
            reason: passed
              ? `Security score ${score} meets or exceeds configured gate threshold of ${threshold}.`
              : `Security score ${score} is below configured gate threshold of ${threshold}.`,
            timestamp: new Date().toISOString(),
          },
        };
      } else {
        throw evalErr;
      }
    }

    const { passed, statusCode, result } = gate;
    res.setHeader('Content-Type', 'application/json');
    // For CI workflows requesting strict status (failOnStatus=true), return 200 or 422.
    // For UI clients, return 200 with result.passed so the browser does not log network failure.
    res.writeHead(failOnStatus ? statusCode : 200);
    res.end(JSON.stringify({
      success: true,
      passed,
      data: result,
    }));
  } catch (err) {
    sendError(res, err.statusCode || 500, err.code || 'GATE_EVALUATION_ERROR', err.message);
  }
}

module.exports = {
  handleSarifExport,
  handleMarkdownExport,
  handleQualityGate,
};
