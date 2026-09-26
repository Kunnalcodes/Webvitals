/**
 * AI & Remediation Controller — Phase 4
 * WebVitals
 *
 * Handles HTTP requests for:
 *   - POST /api/ai/explain
 *   - POST /api/ai/remediate
 *   - POST /api/ai/chat
 *   - GET  /api/ai/executive-summary?scanId=...
 */

'use strict';

const { URL } = require('url');
const { checkRateLimit } = require('../middleware/rateLimiter');
const { explainFinding, generateExecutiveSummary, chatWithScan, resolveRemediation } = require('../ai/aiService');
const { scanRepository } = require('../storage/scanRepository');
const { sendSuccess, sendError } = require('../utils/helpers');

/**
 * Reads and parses JSON body with length bounds.
 */
async function readJsonBody(req, maxBytes = 8192) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (d) => {
      body += d;
      if (body.length > maxBytes) req.destroy(new Error('Payload too large'));
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

/**
 * POST /api/ai/explain
 * Body: { scanId: "...", findingId: "...", audience: "developer" | "executive" }
 */
async function handleExplain(req, res) {
  if (!checkRateLimit(req, res, 'ai')) return;

  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendError(res, 400, 'INVALID_BODY', 'Invalid JSON body');
  }

  const { scanId, findingId, audience = 'developer' } = body;
  if (!scanId || !findingId) {
    return sendError(res, 400, 'MISSING_REQUIRED_FIELDS', 'scanId and findingId are required');
  }

  try {
    const explanation = await explainFinding(scanId, findingId, audience);
    sendSuccess(res, explanation);
  } catch (err) {
    sendError(res, err.statusCode || 500, err.code || 'AI_EXPLAIN_ERROR', err.message);
  }
}

/**
 * POST /api/ai/remediate
 * Body: { scanId: "...", findingId: "...", preferredStack?: "nginx" | "apache" | "next" | "node" }
 */
async function handleRemediate(req, res) {
  if (!checkRateLimit(req, res, 'ai')) return;

  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendError(res, 400, 'INVALID_BODY', 'Invalid JSON body');
  }

  const { scanId, findingId, preferredStack } = body;
  if (!scanId || !findingId) {
    return sendError(res, 400, 'MISSING_REQUIRED_FIELDS', 'scanId and findingId are required');
  }

  const scanReport = scanRepository.getScan(scanId);
  if (!scanReport) {
    return sendError(res, 404, 'SCAN_NOT_FOUND', `Scan not found: ${scanId}`);
  }

  try {
    const remediation = resolveRemediation(scanReport, findingId, preferredStack);
    if (!remediation) {
      return sendError(res, 404, 'FINDING_NOT_FOUND', `Finding '${findingId}' not found in scan`);
    }
    sendSuccess(res, remediation);
  } catch (err) {
    sendError(res, 500, 'REMEDIATION_ERROR', err.message);
  }
}

/**
 * POST /api/ai/chat
 * Body: { scanId: "...", message: "...", conversationId?: "..." }
 */
async function handleChat(req, res) {
  if (!checkRateLimit(req, res, 'ai')) return;

  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendError(res, 400, 'INVALID_BODY', 'Invalid JSON body');
  }

  const { scanId, message, conversationId } = body;
  if (!scanId || !message) {
    return sendError(res, 400, 'MISSING_REQUIRED_FIELDS', 'scanId and message are required');
  }

  try {
    const chatResult = await chatWithScan(scanId, message, conversationId);
    sendSuccess(res, chatResult);
  } catch (err) {
    sendError(res, err.statusCode || 500, err.code || 'AI_CHAT_ERROR', err.message);
  }
}

/**
 * GET /api/ai/executive-summary?scanId=...
 */
async function handleExecutiveSummary(req, res, parsedUrl) {
  if (!checkRateLimit(req, res, 'ai')) return;

  const scanId = parsedUrl.searchParams.get('scanId');
  if (!scanId) {
    return sendError(res, 400, 'MISSING_SCAN_ID', 'scanId query parameter is required');
  }

  try {
    const summary = await generateExecutiveSummary(scanId);
    sendSuccess(res, summary);
  } catch (err) {
    sendError(res, err.statusCode || 500, err.code || 'EXECUTIVE_SUMMARY_ERROR', err.message);
  }
}

module.exports = {
  handleExplain,
  handleRemediate,
  handleChat,
  handleExecutiveSummary,
};
