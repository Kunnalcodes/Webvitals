/**
 * Progress Emitter Unit Tests — Phase 2
 * WebVitals
 *
 * Tests pub/sub event bus, listener isolation, and cleanup.
 * Run: node --test backend/tests/phase2/progressEmitter.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { subscribe, emit, cleanup, listenerCount } = require('../../scan/progressEmitter');

describe('Progress Emitter Event Bus', () => {
  test('subscribes and receives events for matching scanId', () => {
    const scanId = 'scan-test-1';
    const received = [];

    const unsub = subscribe(scanId, (evt) => {
      received.push(evt);
    });

    emit(scanId, { stage: 'VALIDATING', progress: 5 });
    emit(scanId, { stage: 'CONNECTING', progress: 15 });

    assert.strictEqual(received.length, 2);
    assert.strictEqual(received[0].stage, 'VALIDATING');
    assert.strictEqual(received[1].stage, 'CONNECTING');

    unsub();
    assert.strictEqual(listenerCount(scanId), 0);
  });

  test('does not leak events across different scanIds', () => {
    const scanIdA = 'scan-a';
    const scanIdB = 'scan-b';
    const receivedA = [];
    const receivedB = [];

    const unsubA = subscribe(scanIdA, (e) => receivedA.push(e));
    const unsubB = subscribe(scanIdB, (e) => receivedB.push(e));

    emit(scanIdA, { id: 'A1' });
    emit(scanIdB, { id: 'B1' });

    assert.strictEqual(receivedA.length, 1);
    assert.strictEqual(receivedA[0].id, 'A1');
    assert.strictEqual(receivedB.length, 1);
    assert.strictEqual(receivedB[0].id, 'B1');

    unsubA();
    unsubB();
  });

  test('listener exceptions do not break other listeners', () => {
    const scanId = 'scan-err-test';
    let safeListenerCalled = false;

    subscribe(scanId, () => {
      throw new Error('Boom in listener!');
    });

    subscribe(scanId, () => {
      safeListenerCalled = true;
    });

    emit(scanId, { type: 'TEST' });
    assert.strictEqual(safeListenerCalled, true);
    cleanup(scanId);
  });
});
