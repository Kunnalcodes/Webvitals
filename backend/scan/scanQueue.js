/**
 * Scan Queue & Worker Pool — Phase 2
 * WebVitals
 *
 * In-memory FIFO queue with configurable concurrency.
 * No external dependencies (no Redis, BullMQ, etc.).
 *
 * Model:
 *   pendingJobs[]   — FIFO queue of waiting scans
 *   activeJobs      — Set of currently executing scanIds
 *   maxConcurrency  — maximum active scans at once
 *   maxQueueSize    — maximum pending jobs allowed
 *
 * IMPORTANT:
 *   WebSocket sockets are NOT stored here.
 *   This module only knows about scanId + url + metadata.
 */

'use strict';

const { executeScan }                           = require('./scanOrchestrator');
const { createScanLifecycle, getLifecycle }     = require('./scanLifecycle');
const { emit }                                  = require('./progressEmitter');

const MAX_CONCURRENCY = parseInt(process.env.SCAN_MAX_CONCURRENCY || '3', 10);
const MAX_QUEUE_SIZE  = parseInt(process.env.SCAN_MAX_QUEUE_SIZE  || '25', 10);

// ─── State ────────────────────────────────────────────────────────────────────

/** @type {{ scanId: string, url: string, createdAt: number }[]} */
const _pending = [];

/** @type {Set<string>} set of currently active scanIds */
const _active  = new Set();

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Drain: attempt to start queued scans if worker slots are available.
 */
function _drain() {
  while (_active.size < MAX_CONCURRENCY && _pending.length > 0) {
    const job = _pending.shift(); // FIFO
    _startJob(job);
  }
}

/**
 * Start executing a scan job.
 */
function _startJob(job) {
  const { scanId, url } = job;
  _active.add(scanId);
  console.log(`[ScanQueue] STARTED scanId=${scanId.slice(0, 8)} active=${_active.size} pending=${_pending.length}`);

  executeScan(scanId, url)
    .catch((err) => {
      // executeScan handles its own failure reporting, but catch here to prevent
      // unhandled promise rejection crashing the process.
      console.error(`[ScanQueue] Unexpected error for scanId=${scanId.slice(0, 8)}:`, err.message);
    })
    .finally(() => {
      _active.delete(scanId);
      console.log(`[ScanQueue] DONE scanId=${scanId.slice(0, 8)} active=${_active.size} pending=${_pending.length}`);
      // Immediately try to process the next job
      _drain();
    });
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Enqueue a new scan.
 *
 * @param {string} url  - Target URL (already validated by the controller)
 * @returns {{ scanId: string, status: 'QUEUED', queuePosition: number|null }}
 *          or throws with code 'SCAN_QUEUE_FULL'
 */
function enqueue(url) {
  if (_pending.length >= MAX_QUEUE_SIZE) {
    const err = new Error('The scan queue is currently full. Please try again later.');
    err.code  = 'SCAN_QUEUE_FULL';
    err.queuePosition = _pending.length;
    throw err;
  }

  // Create lifecycle BEFORE enqueueing so the scanId is immediately available
  const lc = createScanLifecycle(url);
  const { scanId } = lc;

  const job = { scanId, url, createdAt: Date.now() };

  if (_active.size < MAX_CONCURRENCY) {
    // Start immediately (no queueing needed)
    _startJob(job);
    console.log(`[ScanQueue] QUEUED+STARTED scanId=${scanId.slice(0, 8)} (immediate)`);
    return { scanId, status: 'QUEUED', queuePosition: null };
  } else {
    // Add to pending queue
    _pending.push(job);
    const queuePosition = _pending.length;
    console.log(`[ScanQueue] QUEUED scanId=${scanId.slice(0, 8)} position=${queuePosition} active=${_active.size}`);
    return { scanId, status: 'QUEUED', queuePosition };
  }
}

/**
 * Returns a diagnostic snapshot of the queue state.
 */
function getQueueStatus() {
  return {
    activeCount:    _active.size,
    pendingCount:   _pending.length,
    maxConcurrency: MAX_CONCURRENCY,
    maxQueueSize:   MAX_QUEUE_SIZE,
    activeScans:    Array.from(_active),
    pendingScans:   _pending.map((j) => ({ scanId: j.scanId, createdAt: j.createdAt })),
  };
}

/**
 * Whether a scanId is currently active (running).
 */
function isActive(scanId) {
  return _active.has(scanId);
}

/**
 * Whether a scanId is currently pending (queued, not yet running).
 */
function isPending(scanId) {
  return _pending.some((j) => j.scanId === scanId);
}

module.exports = {
  enqueue,
  getQueueStatus,
  isActive,
  isPending,
  MAX_CONCURRENCY,
  MAX_QUEUE_SIZE,
  // Expose internals for testing only
  _pending,
  _active,
};
