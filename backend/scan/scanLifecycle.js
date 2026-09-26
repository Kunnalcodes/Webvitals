/**
 * Scan Lifecycle — Phase 2
 * WebVitals
 *
 * Canonical lifecycle state model for every scan.
 * This is the single source of truth for scan status.
 * Transport layers (WS, polling) read from this; they do not own it.
 *
 * Status values:   QUEUED | RUNNING | COMPLETE | FAILED
 * Stage values:    see STAGES below (canonical ordered list)
 */

'use strict';

const crypto = require('crypto');

// ─── Canonical stage definitions ─────────────────────────────────────────────
// progress: the percentage reported when this stage BEGINS
// label: human-readable string for the frontend
const STAGES = [
  { key: 'VALIDATING',            pct:  5,   label: 'Validating target URL' },
  { key: 'CONNECTING',            pct:  15,  label: 'Connecting to target' },
  { key: 'TLS_ANALYSIS',          pct:  25,  label: 'Analysing TLS certificate' },
  { key: 'HTTP_ANALYSIS',         pct:  35,  label: 'Reading HTTP response' },
  { key: 'HEADERS_ANALYSIS',      pct:  45,  label: 'Evaluating security headers' },
  { key: 'COOKIE_ANALYSIS',       pct:  52,  label: 'Inspecting cookie attributes' },
  { key: 'CORS_ANALYSIS',         pct:  58,  label: 'Checking CORS policy' },
  { key: 'DNS_ANALYSIS',          pct:  70,  label: 'Checking SPF, DMARC and CAA' },
  { key: 'TECH_STACK_ANALYSIS',   pct:  77,  label: 'Fingerprinting technology stack' },
  { key: 'SEO_ANALYSIS',          pct:  82,  label: 'Running SEO analysis' },
  { key: 'SENSITIVE_FILE_ANALYSIS', pct: 87, label: 'Probing for exposed files' },
  { key: 'PHISHING_ANALYSIS',     pct:  92,  label: 'Running phishing heuristics' },
  { key: 'SCORING',               pct:  95,  label: 'Computing weighted security score' },
  { key: 'FINALIZING',            pct:  98,  label: 'Finalizing report' },
  { key: 'REPORT_READY',          pct:  100, label: 'Scan complete' },
];

// Legacy stage key aliases (Phase 1 used different names — map them)
const STAGE_ALIAS = {
  HEADER_ANALYSIS:  'HEADERS_ANALYSIS',
  SENSITIVE_FILES:  'SENSITIVE_FILE_ANALYSIS',
  PHISHING:         'PHISHING_ANALYSIS',
};

// Fast lookup by key
const STAGE_MAP = Object.fromEntries(STAGES.map((s) => [s.key, s]));

/** Resolve a stage key (including legacy aliases) → canonical stage object */
function resolveStage(key) {
  const canonical = STAGE_ALIAS[key] || key;
  return STAGE_MAP[canonical] || null;
}

// ─── TTL ──────────────────────────────────────────────────────────────────────
const SCAN_STATE_TTL_MS = parseInt(process.env.SCAN_STATE_TTL_MS || '300000', 10); // 5 min

// ─── In-memory lifecycle store ────────────────────────────────────────────────
/** @type {Map<string, ScanLifecycle>} */
const _store = new Map();

/**
 * Creates and registers a new scan lifecycle.
 *
 * @param {string} url - The target URL
 * @returns {ScanLifecycle}
 */
function createScanLifecycle(url) {
  const scanId    = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  const lifecycle = {
    scanId,
    requestedUrl: url,
    status:       'QUEUED',
    stage:        null,
    progress:     0,
    message:      'Scan queued — waiting for a worker',
    createdAt,
    startedAt:    null,
    completedAt:  null,
    error:        null,
    /** stage key → { status, startedAt, completedAt, durationMs } */
    stages:       Object.fromEntries(STAGES.map((s) => [s.key, {
      status:      'PENDING',
      startedAt:   null,
      completedAt: null,
      durationMs:  null,
    }])),
    /** Full report — only set when COMPLETE */
    report: null,
    /** Internal: cleanup timer handle */
    _cleanupTimer: null,
  };

  _store.set(scanId, lifecycle);
  return lifecycle;
}

/**
 * Transition a scan into RUNNING and record startedAt.
 */
function markRunning(scanId) {
  const lc = _store.get(scanId);
  if (!lc) return;
  lc.status    = 'RUNNING';
  lc.startedAt = new Date().toISOString();
}

/**
 * Transition a single stage.
 * Returns the updated lifecycle (or null if not found).
 *
 * @param {string} scanId
 * @param {string} stageKey  - canonical or aliased stage key
 * @param {'RUNNING'|'COMPLETE'|'FAILED'|'SKIPPED'} stageStatus
 * @param {object} [opts]
 * @param {string} [opts.message]  - override message
 * @param {string} [opts.startedAt]
 * @param {string} [opts.completedAt]
 * @param {number} [opts.durationMs]
 */
function transitionStage(scanId, stageKey, stageStatus, opts = {}) {
  const lc = _store.get(scanId);
  if (!lc) return null;

  const stage = resolveStage(stageKey);
  if (!stage) return lc;

  const now = new Date().toISOString();

  // Update overall lifecycle progress
  // Progress is monotonic: only advance if new value is higher
  if (stage.pct > lc.progress) {
    lc.progress = stage.pct;
  }
  lc.stage   = stage.key;
  lc.message = opts.message || stage.label;

  // Update per-stage record
  const stageRecord = lc.stages[stage.key];
  if (stageRecord) {
    stageRecord.status = stageStatus;
    if (stageStatus === 'RUNNING') {
      stageRecord.startedAt = opts.startedAt || now;
    }
    if (stageStatus === 'COMPLETE' || stageStatus === 'FAILED' || stageStatus === 'SKIPPED') {
      stageRecord.completedAt = opts.completedAt || now;
      if (stageRecord.startedAt) {
        stageRecord.durationMs = opts.durationMs ??
          (new Date(stageRecord.completedAt) - new Date(stageRecord.startedAt));
      }
    }
  }

  return lc;
}

/**
 * Mark scan COMPLETE and attach the report.
 */
function markComplete(scanId, report) {
  const lc = _store.get(scanId);
  if (!lc) return null;
  const now = new Date().toISOString();
  lc.status      = 'COMPLETE';
  lc.stage       = 'REPORT_READY';
  lc.progress    = 100;
  lc.message     = 'Scan complete';
  lc.completedAt = now;
  lc.report      = report;
  _scheduleCleanup(scanId);
  return lc;
}

/**
 * Mark scan FAILED with a structured error.
 */
function markFailed(scanId, code, message) {
  const lc = _store.get(scanId);
  if (!lc) return null;
  const now = new Date().toISOString();
  lc.status      = 'FAILED';
  lc.completedAt = now;
  lc.error       = { code: code || 'SCAN_FAILED', message: message || 'Scan failed' };
  _scheduleCleanup(scanId);
  return lc;
}

/**
 * Retrieve lifecycle by scanId.
 */
function getLifecycle(scanId) {
  return _store.get(scanId) || null;
}

/**
 * Returns a safe public snapshot of the lifecycle (no internal fields).
 */
function getPublicState(scanId) {
  const lc = _store.get(scanId);
  if (!lc) return null;
  // eslint-disable-next-line no-unused-vars
  const { _cleanupTimer, ...pub } = lc;
  return pub;
}

/**
 * Schedule TTL cleanup of lifecycle state.
 * Allows polls/WS reconnects to still read state briefly after completion.
 */
function _scheduleCleanup(scanId) {
  const lc = _store.get(scanId);
  if (!lc) return;
  if (lc._cleanupTimer) clearTimeout(lc._cleanupTimer);
  lc._cleanupTimer = setTimeout(() => {
    _store.delete(scanId);
  }, SCAN_STATE_TTL_MS).unref();
}

/**
 * Build a canonical progress event object.
 * @param {string} type - SCAN_PROGRESS | SCAN_COMPLETE | SCAN_ERROR | SCAN_SNAPSHOT
 */
function buildEvent(type, lc, extra = {}) {
  return {
    type,
    scanId:    lc.scanId,
    status:    lc.status,
    stage:     lc.stage,
    progress:  lc.progress,
    message:   lc.message,
    timestamp: new Date().toISOString(),
    ...extra,
  };
}

module.exports = {
  STAGES,
  STAGE_MAP,
  resolveStage,
  createScanLifecycle,
  markRunning,
  transitionStage,
  markComplete,
  markFailed,
  getLifecycle,
  getPublicState,
  buildEvent,
  SCAN_STATE_TTL_MS,
};
