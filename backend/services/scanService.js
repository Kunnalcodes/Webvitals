/**
 * Scan Service — Phase 1
 * WebVitals
 *
 * Fixes P0-3: No fake demo data — history is real or empty.
 * Fixes P0-4: Every scan has a scanId, status, progress, and timestamps.
 *
 * Scan lifecycle:
 *   QUEUED → VALIDATING → CONNECTING → TLS_ANALYSIS → HTTP_ANALYSIS →
 *   HEADER_ANALYSIS → COOKIE_ANALYSIS → CORS_ANALYSIS → DNS_ANALYSIS →
 *   PHISHING_ANALYSIS → SENSITIVE_FILES → SCORING → REPORT_READY | FAILED
 */

'use strict';

const crypto = require('crypto');
const { URL } = require('url');
const { validateTargetUrl, validateResolvedHost } = require('../middleware/abuseProtection');
const { fetchWithRedirects, getCertInfo } = require('./networkService');
const { analyzeCookies, analyzeCors }    = require('./cookieCorsService');
const { analyzeDnsSecurity }             = require('./dnsSecurityService');
const { scanSensitiveFiles }             = require('./sensitiveFileService');
const { analyzeUrlStructure }            = require('./heuristicService');
const { evaluateChannels, computeScore, gradeFor, classify } = require('./securityEvaluator');
const { scanRepository } = require('../storage/scanRepository');

// ─── Scan lifecycle states ────────────────────────────────────────────────────
const STAGES = [
  { key: 'QUEUED',            pct: 0,   message: 'Scan queued' },
  { key: 'VALIDATING',        pct: 5,   message: 'Validating target URL' },
  { key: 'CONNECTING',        pct: 15,  message: 'Connecting to target' },
  { key: 'TLS_ANALYSIS',      pct: 25,  message: 'Analysing TLS certificate' },
  { key: 'HTTP_ANALYSIS',     pct: 35,  message: 'Fetching HTTP response headers' },
  { key: 'HEADER_ANALYSIS',   pct: 50,  message: 'Evaluating security headers' },
  { key: 'COOKIE_ANALYSIS',   pct: 60,  message: 'Inspecting cookie attributes' },
  { key: 'CORS_ANALYSIS',     pct: 65,  message: 'Checking CORS policy' },
  { key: 'DNS_ANALYSIS',      pct: 72,  message: 'Checking SPF, DMARC and CAA records' },
  { key: 'PHISHING_ANALYSIS', pct: 82,  message: 'Running phishing heuristics' },
  { key: 'SENSITIVE_FILES',   pct: 88,  message: 'Probing for exposed sensitive files' },
  { key: 'SCORING',           pct: 95,  message: 'Computing weighted security score' },
  { key: 'REPORT_READY',      pct: 100, message: 'Scan complete' },
];

// ─── In-flight scan tracker ───────────────────────────────────────────────────
// scanId → { status, stage, progress, message, emitter }
const _activeScans = new Map();

/**
 * Emit a progress event to any registered listener.
 * This is the hook that WebSocket (Phase 2) will listen to.
 */
function emit(scanId, event) {
  const scan = _activeScans.get(scanId);
  if (scan?.emitter) {
    try { scan.emitter(event); } catch { /* ignore listener errors */ }
  }
}

function setStage(scanId, stageKey, extraMessage) {
  const stage = STAGES.find((s) => s.key === stageKey) || STAGES[0];
  const record = _activeScans.get(scanId);
  if (record) {
    record.status   = stageKey === 'REPORT_READY' ? 'COMPLETE' : stageKey === 'FAILED' ? 'FAILED' : 'RUNNING';
    record.stage    = stage.key;
    record.progress = stage.pct;
    record.message  = extraMessage || stage.message;
  }
  emit(scanId, {
    scanId,
    stage:    stage.key,
    progress: stage.pct,
    message:  extraMessage || stage.message,
  });
}

/**
 * Executes a full multi-vector security scan.
 *
 * @param {string} rawInput - Raw URL or domain string from the user
 * @param {object} [opts]
 * @param {Function} [opts.onProgress] - Called with progress events during scan
 * @returns {Promise<ScanReport>}
 */
async function performScan(rawInput, opts = {}) {
  const scanId    = crypto.randomUUID();
  const startedAt = new Date().toISOString();

  // Register in-flight scan
  _activeScans.set(scanId, {
    scanId,
    status:   'QUEUED',
    stage:    'QUEUED',
    progress: 0,
    message:  'Scan queued',
    startedAt,
    emitter:  opts.onProgress || null,
  });

  try {
    // ── STAGE: VALIDATING ────────────────────────────────────────────────────
    setStage(scanId, 'VALIDATING');

    const validation = validateTargetUrl(rawInput);
    if (!validation.valid) {
      throw Object.assign(new Error(validation.message), { code: 'INVALID_TARGET' });
    }

    const urlObj    = validation.parsedUrl;
    const hostname  = urlObj.hostname;

    // DNS-based SSRF check on the initial hostname
    const dnsCheck = await validateResolvedHost(hostname);
    if (dnsCheck.blocked) {
      throw Object.assign(new Error(dnsCheck.reason), { code: 'SSRF_BLOCKED' });
    }

    // ── STAGE: CONNECTING ────────────────────────────────────────────────────
    setStage(scanId, 'CONNECTING');
    let scanResult;
    try {
      scanResult = await fetchWithRedirects(urlObj);
    } catch (err) {
      // Connection failure is not a scan failure — record it with empty headers
      scanResult = {
        finalUrl:     urlObj,
        status:       null,
        headers:      {},
        chain:        [{ url: urlObj.toString(), status: null, error: err.message }],
        elapsedMs:    0,
        protocolUsed: urlObj.protocol,
        connectionError: err.message,
      };
    }

    const finalHost = scanResult.finalUrl?.hostname || hostname;

    // ── STAGE: TLS_ANALYSIS ──────────────────────────────────────────────────
    setStage(scanId, 'TLS_ANALYSIS');
    let certInfo = null;
    if (scanResult.finalUrl?.protocol === 'https:') {
      certInfo = await getCertInfo(finalHost).catch(() => null);
    }

    // ── STAGE: HTTP_ANALYSIS ─────────────────────────────────────────────────
    setStage(scanId, 'HTTP_ANALYSIS');
    // (headers already captured by fetchWithRedirects)

    // ── STAGE: HEADER_ANALYSIS ───────────────────────────────────────────────
    setStage(scanId, 'HEADER_ANALYSIS');
    // (evaluated later in evaluateChannels)

    // ── STAGE: COOKIE_ANALYSIS ───────────────────────────────────────────────
    setStage(scanId, 'COOKIE_ANALYSIS');
    const cookieInfo = analyzeCookies(scanResult.headers || {});

    // ── STAGE: CORS_ANALYSIS ─────────────────────────────────────────────────
    setStage(scanId, 'CORS_ANALYSIS');
    const corsInfo = analyzeCors(scanResult.headers || {});

    // ── STAGE: DNS_ANALYSIS ──────────────────────────────────────────────────
    setStage(scanId, 'DNS_ANALYSIS');
    const dnsInfo = await analyzeDnsSecurity(finalHost).catch(() => null);

    // ── STAGE: PHISHING_ANALYSIS ─────────────────────────────────────────────
    setStage(scanId, 'PHISHING_ANALYSIS');
    const urlStructure = analyzeUrlStructure(scanResult.finalUrl, rawInput);

    // ── STAGE: SENSITIVE_FILES ───────────────────────────────────────────────
    setStage(scanId, 'SENSITIVE_FILES');
    const sensitiveFiles = await scanSensitiveFiles(scanResult.finalUrl).catch(() => ({
      totalChecked: 0,
      exposedCount: 0,
      findings: [],
    }));

    // ── STAGE: SCORING ───────────────────────────────────────────────────────
    setStage(scanId, 'SCORING');

    const findings = evaluateChannels({ scanResult, certInfo, urlStructure, cookieInfo, corsInfo, dnsInfo });
    const score    = computeScore(findings);
    const { grade, label } = gradeFor(score);
    const classification   = classify(score, urlStructure?.score);

    const completedAt = new Date().toISOString();

    // Build the final report
    const report = {
      scanId,
      requestedUrl:    rawInput,
      finalUrl:        scanResult.finalUrl?.toString() || rawInput,
      hostname:        finalHost,
      httpStatus:      scanResult.status,
      https:           scanResult.finalUrl?.protocol === 'https:',
      redirects:       scanResult.chain?.length > 1 ? scanResult.chain.length - 1 : 0,
      redirectChain:   scanResult.chain || [],
      connectionError: scanResult.connectionError || null,
      scanTimeMs:      new Date(completedAt) - new Date(startedAt),
      startedAt,
      completedAt,
      score,
      grade,
      gradeLabel: label,
      classification,
      findings,       // structured findings model
      cookieInfo,
      corsInfo,
      dnsInfo,
      sensitiveFiles,
      certInfo,
      timestamp:   completedAt,
    };

    // Persist (no fake data — real scans only)
    scanRepository.saveScan(report);

    // ── STAGE: REPORT_READY ──────────────────────────────────────────────────
    setStage(scanId, 'REPORT_READY');

    return report;

  } catch (err) {
    const record = _activeScans.get(scanId);
    if (record) {
      record.status  = 'FAILED';
      record.stage   = 'FAILED';
      record.message = err.message;
    }
    emit(scanId, { scanId, stage: 'FAILED', progress: 0, message: err.message });
    throw err;
  } finally {
    // Keep the scan record for a short window so status polls can read it,
    // then clean up to avoid memory leaks.
    setTimeout(() => _activeScans.delete(scanId), 5 * 60_000).unref();
  }
}

/**
 * Returns the current progress state for an active scan.
 */
function getScanProgress(scanId) {
  return _activeScans.get(scanId) || null;
}

module.exports = {
  performScan,
  getScanProgress,
  STAGES,
};
