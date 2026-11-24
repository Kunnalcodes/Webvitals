/**
 * Competitive Intelligence Controller — WebVitals 2.0
 *
 * Handles HTTP requests for:
 *   - POST /api/competitive/analyze
 *   - GET /api/competitive/status
 *   - GET /api/competitive/history
 *   - GET /api/competitive/export
 */

'use strict';

const { performCompetitiveAnalysis } = require('../competitive/competitiveOrchestrator');
const { defaultCompetitiveRepository } = require('../competitive/competitiveRepository');
const { readBody, sendSuccess, sendError } = require('../utils/helpers');

/**
 * Handles competitive analysis execution.
 */
async function handleCompetitiveAnalyze(req, res, parsedUrl) {
  let primaryUrl = '';
  let competitorUrl = '';
  let options = {};

  if (req.method === 'POST') {
    try {
      const raw = await readBody(req);
      const parsed = JSON.parse(raw || '{}');
      primaryUrl = parsed.primaryUrl || parsed.primary || parsed.url || '';
      competitorUrl = parsed.competitorUrl || parsed.competitor || '';
      options = {
        businessName: parsed.businessName || '',
        targetLocation: parsed.targetLocation || parsed.location || '',
        targetCountry: parsed.targetCountry || parsed.country || '',
        targetLanguage: parsed.targetLanguage || parsed.language || '',
        industry: parsed.industry || parsed.category || '',
        businessObjectives: Array.isArray(parsed.businessObjectives) ? parsed.businessObjectives : [],
      };
    } catch {
      return sendError(res, 400, 'INVALID_BODY', 'Could not parse request body.');
    }
  } else {
    primaryUrl = parsedUrl.searchParams.get('primaryUrl') || parsedUrl.searchParams.get('primary') || '';
    competitorUrl = parsedUrl.searchParams.get('competitorUrl') || parsedUrl.searchParams.get('competitor') || '';
    options = {
      businessName: parsedUrl.searchParams.get('businessName') || '',
      targetLocation: parsedUrl.searchParams.get('location') || '',
      targetCountry: parsedUrl.searchParams.get('country') || '',
      targetLanguage: parsedUrl.searchParams.get('language') || '',
      industry: parsedUrl.searchParams.get('industry') || '',
    };
  }

  if (!primaryUrl.trim()) {
    return sendError(res, 400, 'MISSING_PRIMARY_URL', 'Missing required "primaryUrl" parameter.');
  }

  if (!competitorUrl.trim()) {
    return sendError(res, 400, 'MISSING_COMPETITOR_URL', 'Missing required "competitorUrl" parameter.');
  }

  try {
    const report = await performCompetitiveAnalysis(primaryUrl.trim(), competitorUrl.trim(), options);
    defaultCompetitiveRepository.saveScan(report);
    return sendSuccess(res, report);
  } catch (err) {
    return sendError(res, 400, 'COMPETITIVE_SCAN_FAILED', `Competitive intelligence scan failed: ${err.message}`);
  }
}

/**
 * Handles status retrieval by scanId.
 */
function handleCompetitiveStatus(req, res, parsedUrl) {
  const scanId = parsedUrl.searchParams.get('scanId');
  if (!scanId) {
    return sendError(res, 400, 'MISSING_SCAN_ID', 'Missing required "scanId" query parameter.');
  }

  const scan = defaultCompetitiveRepository.getScan(scanId);
  if (!scan) {
    return sendError(res, 404, 'SCAN_NOT_FOUND', `No scan record found for scanId "${scanId}".`);
  }

  return sendSuccess(res, scan);
}

/**
 * Handles competitive scan history.
 */
function handleCompetitiveHistory(req, res) {
  const history = defaultCompetitiveRepository.listHistory(30);
  return sendSuccess(res, history, { count: history.length });
}

/**
 * Handles report JSON export.
 */
function handleCompetitiveExport(req, res, parsedUrl) {
  const scanId = parsedUrl.searchParams.get('scanId');
  if (!scanId) {
    return sendError(res, 400, 'MISSING_SCAN_ID', 'Missing required "scanId" parameter.');
  }

  const scan = defaultCompetitiveRepository.getScan(scanId);
  if (!scan) {
    return sendError(res, 404, 'SCAN_NOT_FOUND', `Scan "${scanId}" not found.`);
  }

  const filename = `WebVitals_Competitive_${scan.primary.domain}_vs_${scan.competitor.domain}_${new Date().toISOString().slice(0, 10)}.json`;
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Disposition': `attachment; filename="${filename}"`,
  });
  return res.end(JSON.stringify(scan, null, 2));
}

module.exports = {
  handleCompetitiveAnalyze,
  handleCompetitiveStatus,
  handleCompetitiveHistory,
  handleCompetitiveExport,
};
