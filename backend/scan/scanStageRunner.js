/**
 * Scan Stage Runner — Phase 2
 * WebVitals
 *
 * Reusable abstraction for executing a single scan stage.
 * Handles: lifecycle transition, timing, progress emission, fault isolation.
 *
 * Usage:
 *   const result = await runStage(ctx, 'DNS_ANALYSIS', () => analyzeDns(host));
 *
 * On success: returns the value returned by the stage fn.
 * On failure (non-fatal): logs, marks stage FAILED, returns null.
 *   The scan continues — fault isolation.
 * On failure (fatal): rethrows.
 */

'use strict';

const { transitionStage, buildEvent } = require('./scanLifecycle');
const { emit }                        = require('./progressEmitter');

/**
 * Stable error codes for stage-level failures.
 */
const STAGE_ERROR_CODES = {
  DNS_ANALYSIS:          'DNS_RESOLUTION_FAILED',
  TLS_ANALYSIS:          'TLS_CONNECTION_FAILED',
  HTTP_ANALYSIS:         'HTTP_CONNECTION_REFUSED',
  CONNECTING:            'TARGET_UNREACHABLE',
  SENSITIVE_FILE_ANALYSIS: 'SCAN_STAGE_FAILED',
  DEFAULT:               'SCAN_STAGE_FAILED',
};

/**
 * Stages that are FATAL — their failure terminates the entire scan.
 * All others are non-fatal: produce NOT_EVALUATED and continue.
 */
const FATAL_STAGES = new Set(['VALIDATING', 'CONNECTING']);

/**
 * Execute a single scan stage with full lifecycle + fault isolation.
 *
 * @param {object}   ctx          - Scan context from scanOrchestrator
 * @param {string}   stageKey     - Canonical stage key (e.g. 'DNS_ANALYSIS')
 * @param {Function} fn           - async () => result
 * @param {object}   [opts]
 * @param {boolean}  [opts.fatal] - Override default fatality. Defaults to FATAL_STAGES.has(stageKey)
 * @param {string}   [opts.message] - Custom stage start message
 * @returns {Promise<{value: *, error: object|null}>}
 */
async function runStage(ctx, stageKey, fn, opts = {}) {
  const { scanId, log } = ctx;
  const isFatal = opts.fatal !== undefined ? opts.fatal : FATAL_STAGES.has(stageKey);
  const startedAt = new Date().toISOString();

  // 1. Mark stage RUNNING + emit progress
  const lc = transitionStage(scanId, stageKey, 'RUNNING', {
    startedAt,
    message: opts.message,
  });

  if (lc) {
    emit(scanId, buildEvent('SCAN_PROGRESS', lc));
  }

  log(`${stageKey} started`);

  // 2. Execute
  try {
    const value = await fn();
    const completedAt = new Date().toISOString();
    const durationMs  = Date.now() - new Date(startedAt).getTime();

    // 3. Mark stage COMPLETE
    const lc2 = transitionStage(scanId, stageKey, 'COMPLETE', { completedAt, durationMs });
    if (lc2) emit(scanId, buildEvent('SCAN_PROGRESS', lc2));

    log(`${stageKey} completed in ${durationMs}ms`);
    return { value, error: null };

  } catch (err) {
    const completedAt = new Date().toISOString();
    const durationMs  = Date.now() - new Date(startedAt).getTime();
    const errorCode   = err.code || STAGE_ERROR_CODES[stageKey] || STAGE_ERROR_CODES.DEFAULT;
    const stageError  = { code: errorCode, message: err.message };

    log(`${stageKey} FAILED in ${durationMs}ms — ${errorCode}: ${err.message}`);

    // 4. Mark stage FAILED
    const lc2 = transitionStage(scanId, stageKey, 'FAILED', { completedAt, durationMs });
    if (lc2) emit(scanId, buildEvent('SCAN_PROGRESS', lc2));

    // 5. Fatal stages rethrow → scan FAILED
    if (isFatal) {
      const fatalErr = Object.assign(new Error(err.message), { code: errorCode });
      throw fatalErr;
    }

    // 6. Non-fatal: return null + structured error, scan continues
    return { value: null, error: stageError };
  }
}

/**
 * Mark a stage as SKIPPED (e.g. TLS analysis skipped for plain HTTP).
 */
function skipStage(ctx, stageKey, reason) {
  const { scanId, log } = ctx;
  const lc = transitionStage(scanId, stageKey, 'SKIPPED', {
    message: reason || `${stageKey} skipped`,
  });
  if (lc) emit(scanId, buildEvent('SCAN_PROGRESS', lc));
  log(`${stageKey} SKIPPED — ${reason || 'not applicable'}`);
}

module.exports = { runStage, skipStage, FATAL_STAGES, STAGE_ERROR_CODES };
