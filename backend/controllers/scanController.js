/**
 * Scan Controller — Phase 2 & 3
 * WebVitals
 *
 * Handles HTTP scan endpoints:
 *   - POST /api/scan (enqueues scan, returns instant scanId & status)
 *   - GET  /api/scan?url=... (query-based scan submission)
 *   - GET  /api/scan/status?scanId=... (returns live in-flight progress or completed report)
 *   - GET  /api/history
 *   - GET  /api/history/trend?domain=...
 */

'use strict';

const { URL } = require('url');
const { validateTargetUrl } = require('../middleware/abuseProtection');
const { checkRateLimit, acquireScanSlot, releaseScanSlot } = require('../middleware/rateLimiter');
const { enqueue, getQueueStatus } = require('../scan/scanQueue');
const { executeScan } = require('../scan/scanOrchestrator');
const { getPublicState, buildEvent } = require('../scan/scanLifecycle');
const { scanRepository } = require('../storage/scanRepository');
const { sendSuccess, sendError } = require('../utils/helpers');

/**
 * POST or GET /api/scan
 * Body or Query: { url: "https://example.com", sync: false }
 */
async function handleScan(req, res) {
  // 1. Rate limit
  if (!checkRateLimit(req, res, 'scan')) return;

  // 2. Concurrency limit (per-IP and global)
  if (!acquireScanSlot(req, res)) return;

  let body = '';
  try {
    await new Promise((resolve, reject) => {
      req.on('data', (d) => {
        body += d;
        if (body.length > 4096) req.destroy(new Error('Body too large'));
      });
      req.on('end', resolve);
      req.on('error', reject);
    });
  } catch {
    releaseScanSlot(req);
    return sendError(res, 400, 'INVALID_BODY', 'Request body could not be read.');
  }

  let rawUrl = '';
  let isSync = false;
  let mode = 'passive';
  let hasConsent = false;
  let depth = 'standard';

  // Try JSON body first if present
  if (body && body.trim()) {
    try {
      const parsed = JSON.parse(body);
      rawUrl = parsed.url || parsed.target || '';
      isSync = !!parsed.sync;
      mode = parsed.mode || 'passive';
      hasConsent = !!(parsed.hasConsent || parsed.consent);
      depth = parsed.depth || 'standard';
    } catch {
      // ignore
    }
  }

  // Fallback to URL search parameters (GET /api/scan?url=... or POST with query param)
  if (!rawUrl || !rawUrl.trim()) {
    try {
      const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      rawUrl = parsedUrl.searchParams.get('url') || parsedUrl.searchParams.get('target') || '';
      if (!isSync) {
        isSync = parsedUrl.searchParams.get('sync') === 'true';
      }
      if (parsedUrl.searchParams.get('mode')) {
        mode = parsedUrl.searchParams.get('mode');
      }
      if (parsedUrl.searchParams.get('consent') === 'true') {
        hasConsent = true;
      }
    } catch {
      // ignore
    }
  }

  rawUrl = (rawUrl || '').trim();

  const validation = validateTargetUrl(rawUrl);
  if (!validation.valid) {
    releaseScanSlot(req);
    return sendError(res, 400, 'INVALID_TARGET', validation.message);
  }

  const scanOptions = { mode, hasConsent, depth };

  try {
    const jobResult = enqueue(rawUrl, scanOptions);

    // Release HTTP concurrency slot right away
    releaseScanSlot(req);

    if (isSync) {
      // Synchronous execution mode: wait for scan to complete and return full report
      try {
        await executeScan(jobResult.scanId, rawUrl, scanOptions);
        const report = scanRepository.getScan(jobResult.scanId);
        if (report) {
          return sendSuccess(res, report, { statusCode: 200 });
        }
      } catch (execErr) {
        return sendError(res, 500, 'SCAN_EXECUTION_FAILED', execErr.message);
      }
    }

    // Default Async Mode: Instant response with scanId & polling/ws endpoints
    sendSuccess(res, {
      scanId: jobResult.scanId,
      status: jobResult.status,
      queuePosition: jobResult.queuePosition,
      target: rawUrl,
      message: jobResult.queuePosition ? `Scan queued at position #${jobResult.queuePosition}` : 'Scan worker assigned — scan starting immediately',
      wsEndpoint: `/ws?scanId=${jobResult.scanId}`,
      pollEndpoint: `/api/scan/status?scanId=${jobResult.scanId}`,
    }, { statusCode: 202 });

  } catch (err) {
    releaseScanSlot(req);
    const code = err.code || 'SCAN_SUBMIT_FAILED';
    const statusCode = code === 'SCAN_QUEUE_FULL' ? 503 : 500;
    sendError(res, statusCode, code, err.message);
  }
}

/**
 * GET /api/scan/status?scanId=xxx
 * Returns current snapshot of scan lifecycle or persisted historical report.
 */
function handleScanStatus(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const scanId = parsedUrl.searchParams.get('scanId');
  if (!scanId) return sendError(res, 400, 'MISSING_SCAN_ID', 'scanId query parameter is required.');

  // 1. Check in-flight lifecycle
  const inFlight = getPublicState(scanId);
  if (inFlight) {
    return sendSuccess(res, {
      scanId: inFlight.scanId,
      status: inFlight.status,
      stage: inFlight.stage,
      progress: inFlight.progress,
      message: inFlight.message,
      stages: inFlight.stages,
      startedAt: inFlight.startedAt,
      completedAt: inFlight.completedAt,
      error: inFlight.error,
      report: inFlight.report,
    });
  }

  // 2. Check persisted repository
  const persisted = scanRepository.getScan(scanId);
  if (persisted) {
    return sendSuccess(res, {
      scanId,
      status: 'COMPLETE',
      stage: 'REPORT_READY',
      progress: 100,
      message: 'Scan complete',
      startedAt: persisted.startedAt || persisted.timestamp,
      completedAt: persisted.completedAt || persisted.timestamp,
      report: persisted,
    });
  }

  // 3. Not found
  return sendError(res, 404, 'SCAN_NOT_FOUND', `No scan found with ID: ${scanId}`);
}

/**
 * GET /api/history
 */
function handleHistory(req, res) {
  const scans = scanRepository.getRecentScans(30);
  sendSuccess(res, scans, { count: scans.length });
}

/**
 * GET /api/history/trend?domain=xxx
 */
function handleTrend(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const domain = parsedUrl.searchParams.get('domain');
  if (!domain) return sendError(res, 400, 'MISSING_DOMAIN', 'domain query parameter is required.');

  const points = scanRepository.getDomainTrend(domain);
  sendSuccess(res, points, { count: points.length, domain });
}

/**
 * GET /api/scan/queue
 */
function handleQueueStatus(req, res) {
  sendSuccess(res, getQueueStatus());
}

module.exports = {
  handleScan,
  handleScanStatus,
  handleHistory,
  handleTrend,
  handleDomainTrend: handleTrend,
  handleQueueStatus,
};
