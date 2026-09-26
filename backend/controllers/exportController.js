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

  try {
    const { passed, statusCode, result } = evaluateQualityGate(scanId, minScore);
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(statusCode);
    res.end(JSON.stringify({
      success: passed,
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
