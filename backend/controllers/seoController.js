/**
 * SEO Audit Controller
 * WebVitals — Phase 1
 */

'use strict';

const { performSeoAudit } = require('../seo');
const { readBody, sendSuccess, sendError } = require('../utils/helpers');

// In-memory SEO history (Phase 3 will move this into ScanRepository)
const _seoHistory = [];

async function handleSeoAnalyze(req, res, parsedUrl) {
  let targetUrl = '';
  if (req.method === 'POST') {
    try {
      const raw = await readBody(req);
      const parsed = JSON.parse(raw || '{}');
      targetUrl = parsed.url || parsed.target || '';
    } catch {
      return sendError(res, 400, 'INVALID_BODY', 'Could not parse request body.');
    }
  } else {
    targetUrl = parsedUrl.searchParams.get('url') || '';
  }

  if (!targetUrl.trim()) {
    return sendError(res, 400, 'MISSING_URL', 'Missing target "url" parameter.');
  }

  try {
    const report = await performSeoAudit(targetUrl.trim());
    _seoHistory.unshift({ timestamp: report.timestamp, url: report.url, score: report.score, grade: report.grade });
    if (_seoHistory.length > 50) _seoHistory.length = 50;
    sendSuccess(res, report);
  } catch (err) {
    sendError(res, 500, 'SEO_FAILED', `SEO audit failed: ${err.message}`);
  }
}

function handleSeoHistory(req, res) {
  sendSuccess(res, _seoHistory, { count: _seoHistory.length });
}

module.exports = {
  handleSeoAnalyze,
  handleSeoHistory,
};
