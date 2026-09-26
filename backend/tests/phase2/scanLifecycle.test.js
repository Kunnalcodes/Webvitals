/**
 * Scan Lifecycle Unit Tests — Phase 2
 * WebVitals
 *
 * Tests state transitions, monotonic progress, stage tracking, error handling.
 * Run: node --test backend/tests/phase2/scanLifecycle.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  createScanLifecycle,
  markRunning,
  transitionStage,
  markComplete,
  markFailed,
  getLifecycle,
  getPublicState,
  buildEvent,
  STAGES,
} = require('../../scan/scanLifecycle');

describe('Scan Lifecycle State Machine', () => {
  test('createScanLifecycle initializes default QUEUED state', () => {
    const lc = createScanLifecycle('https://example.com');
    assert.ok(lc.scanId);
    assert.strictEqual(lc.requestedUrl, 'https://example.com');
    assert.strictEqual(lc.status, 'QUEUED');
    assert.strictEqual(lc.progress, 0);
    assert.ok(lc.stages.VALIDATING);
    assert.strictEqual(lc.stages.VALIDATING.status, 'PENDING');
  });

  test('markRunning transitions status to RUNNING', () => {
    const lc = createScanLifecycle('https://example.com');
    markRunning(lc.scanId);
    const updated = getLifecycle(lc.scanId);
    assert.strictEqual(updated.status, 'RUNNING');
    assert.ok(updated.startedAt);
  });

  test('transitionStage updates progress monotonically', () => {
    const lc = createScanLifecycle('https://example.com');
    markRunning(lc.scanId);

    // Transition to CONNECTING (pct: 15)
    transitionStage(lc.scanId, 'CONNECTING', 'RUNNING');
    assert.strictEqual(getLifecycle(lc.scanId).progress, 15);
    assert.strictEqual(getLifecycle(lc.scanId).stage, 'CONNECTING');

    // Transition to TLS_ANALYSIS (pct: 25)
    transitionStage(lc.scanId, 'TLS_ANALYSIS', 'RUNNING');
    assert.strictEqual(getLifecycle(lc.scanId).progress, 25);

    // If an earlier stage completes, progress does NOT decrease
    transitionStage(lc.scanId, 'VALIDATING', 'COMPLETE');
    assert.strictEqual(getLifecycle(lc.scanId).progress, 25);
  });

  test('markComplete updates status to COMPLETE and progress to 100', () => {
    const lc = createScanLifecycle('https://example.com');
    const mockReport = { scanId: lc.scanId, score: 95, grade: 'A' };
    markComplete(lc.scanId, mockReport);

    const updated = getLifecycle(lc.scanId);
    assert.strictEqual(updated.status, 'COMPLETE');
    assert.strictEqual(updated.progress, 100);
    assert.strictEqual(updated.stage, 'REPORT_READY');
    assert.deepStrictEqual(updated.report, mockReport);
  });

  test('markFailed records structured error', () => {
    const lc = createScanLifecycle('https://example.com');
    markFailed(lc.scanId, 'DNS_ERROR', 'Domain not resolved');

    const updated = getLifecycle(lc.scanId);
    assert.strictEqual(updated.status, 'FAILED');
    assert.strictEqual(updated.error.code, 'DNS_ERROR');
    assert.strictEqual(updated.error.message, 'Domain not resolved');
  });

  test('buildEvent builds typed event payload', () => {
    const lc = createScanLifecycle('https://example.com');
    const evt = buildEvent('SCAN_PROGRESS', lc, { extra: 'data' });
    assert.strictEqual(evt.type, 'SCAN_PROGRESS');
    assert.strictEqual(evt.scanId, lc.scanId);
    assert.strictEqual(evt.extra, 'data');
    assert.ok(evt.timestamp);
  });
});
