/**
 * Progress Emitter — Phase 2
 * WebVitals
 *
 * Transport-agnostic event bus for scan progress.
 * The scan orchestrator emits here; WebSocket and polling read from here.
 *
 * Design:
 *   scanId → Set<listener>
 *
 * A listener is a plain function: (event) => void
 * This allows WebSocket connections, polling caches, and tests to subscribe.
 *
 * Listeners are not persisted. If a client disconnects and reconnects,
 * they get the lifecycle SNAPSHOT from scanLifecycle.js, then subscribe fresh.
 */

'use strict';

const MAX_LISTENERS_PER_SCAN = 50; // safety: prevent unlimited tab/listener accumulation

/** @type {Map<string, Set<Function>>} */
const _listeners = new Map();

/**
 * Subscribe a listener to progress events for a scan.
 * Returns an unsubscribe function.
 *
 * @param {string}   scanId
 * @param {Function} fn  - (event: object) => void
 * @returns {Function} unsubscribe
 */
function subscribe(scanId, fn) {
  if (!_listeners.has(scanId)) {
    _listeners.set(scanId, new Set());
  }
  const set = _listeners.get(scanId);
  if (set.size >= MAX_LISTENERS_PER_SCAN) {
    // Evict the oldest listener (first inserted)
    const [oldest] = set;
    set.delete(oldest);
  }
  set.add(fn);

  return function unsubscribe() {
    const s = _listeners.get(scanId);
    if (s) {
      s.delete(fn);
      if (s.size === 0) _listeners.delete(scanId);
    }
  };
}

/**
 * Emit a progress event to all subscribers for a scan.
 * Errors in individual listeners are caught and logged — one bad listener
 * must not block other listeners or the scan itself.
 *
 * @param {string} scanId
 * @param {object} event
 */
function emit(scanId, event) {
  const set = _listeners.get(scanId);
  if (!set || set.size === 0) return;
  for (const fn of set) {
    try {
      fn(event);
    } catch (err) {
      console.error(`[ProgressEmitter] Listener error for scan ${scanId}:`, err.message);
    }
  }
}

/**
 * Remove all listeners for a scan (called after scan completes + TTL).
 */
function cleanup(scanId) {
  _listeners.delete(scanId);
}

/**
 * Returns the count of active listeners for a scan (for diagnostics).
 */
function listenerCount(scanId) {
  return _listeners.get(scanId)?.size ?? 0;
}

module.exports = { subscribe, emit, cleanup, listenerCount };
