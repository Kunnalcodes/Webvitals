/**
 * Scoring Engine Tests — Phase 1
 * WebVitals
 *
 * Tests the weighted scoring formula, boundary conditions, and grade logic.
 * Run: node --test tests/scoring.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  computeScore,
  gradeFor,
  classify,
  CHANNEL_WEIGHTS,
  STATUS,
} = require('../services/securityEvaluator');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeFindings(overrides = []) {
  // Create a standard all-PASS finding set
  return Object.entries(CHANNEL_WEIGHTS).map(([id, weight], i) => {
    const override = overrides.find((o) => o.id === id) || {};
    return {
      id,
      weight,
      maxScore: weight,
      score:    override.score  !== undefined ? override.score  : weight,
      status:   override.status !== undefined ? override.status : STATUS.PASS,
    };
  });
}

// ─── computeScore ─────────────────────────────────────────────────────────────
describe('computeScore — boundary conditions', () => {
  test('all channels PASS → score is 100', () => {
    const findings = makeFindings();
    assert.strictEqual(computeScore(findings), 100);
  });

  test('all channels FAIL (score=0) → score is 0', () => {
    const findings = makeFindings(
      Object.keys(CHANNEL_WEIGHTS).map((id) => ({ id, score: 0, status: STATUS.FAIL }))
    );
    assert.strictEqual(computeScore(findings), 0);
  });

  test('empty findings array → score is 0', () => {
    assert.strictEqual(computeScore([]), 0);
  });

  test('null findings → score is 0', () => {
    assert.strictEqual(computeScore(null), 0);
  });

  test('score is always an integer between 0 and 100', () => {
    for (let i = 0; i < 50; i++) {
      const findings = makeFindings(
        Object.keys(CHANNEL_WEIGHTS).map((id) => ({
          id,
          score: Math.random() * CHANNEL_WEIGHTS[id],
          status: STATUS.WARN,
        }))
      );
      const score = computeScore(findings);
      assert.ok(Number.isInteger(score), `Score ${score} is not an integer`);
      assert.ok(score >= 0,   `Score ${score} is below 0`);
      assert.ok(score <= 100, `Score ${score} is above 100`);
    }
  });

  test('NOT_EVALUATED channels are excluded from weight sum', () => {
    const findings = makeFindings().map((f) => {
      if (f.id === 'tls') {
        return { ...f, status: STATUS.NOT_EVALUATED, score: 0 };
      }
      return f;
    });
    // Without TLS, the remaining channels all PASS → score should still be 100
    assert.strictEqual(computeScore(findings), 100);
  });

  test('half channels PASS, half FAIL → score is roughly 50', () => {
    const ids = Object.keys(CHANNEL_WEIGHTS);
    const half = ids.length / 2;
    const overrides = ids.slice(0, Math.floor(half)).map((id) => ({ id, score: 0, status: STATUS.FAIL }));
    const findings = makeFindings(overrides);
    const score = computeScore(findings);
    // Score should be between 30 and 70 for half pass/fail
    assert.ok(score > 20 && score < 80, `Expected score around 50, got ${score}`);
  });

  test('score with NaN earned value does not produce NaN score', () => {
    const findings = makeFindings([{ id: 'https', score: NaN }]);
    const score = computeScore(findings);
    assert.ok(Number.isFinite(score), `Score is not finite: ${score}`);
  });
});

// ─── gradeFor ─────────────────────────────────────────────────────────────────
describe('gradeFor — all grade boundaries', () => {
  const cases = [
    { score: 100, grade: 'A' },
    { score: 90,  grade: 'A' },
    { score: 89,  grade: 'B' },
    { score: 80,  grade: 'B' },
    { score: 79,  grade: 'C' },
    { score: 70,  grade: 'C' },
    { score: 69,  grade: 'D' },
    { score: 60,  grade: 'D' },
    { score: 59,  grade: 'F' },
    { score: 0,   grade: 'F' },
  ];
  for (const { score, grade } of cases) {
    test(`score ${score} → grade ${grade}`, () => {
      const result = gradeFor(score);
      assert.strictEqual(result.grade, grade);
      assert.ok(result.label?.length > 0, 'label should be non-empty');
    });
  }
});

// ─── classify ─────────────────────────────────────────────────────────────────
describe('classify', () => {
  test('score >= 80 without phishing → Safe', () => {
    assert.strictEqual(classify(80), 'Safe');
    assert.strictEqual(classify(100), 'Safe');
  });

  test('score 50–79 → Needs Attention', () => {
    assert.strictEqual(classify(50), 'Needs Attention');
    assert.strictEqual(classify(79), 'Needs Attention');
  });

  test('score < 50 → High Risk', () => {
    assert.strictEqual(classify(49), 'High Risk');
    assert.strictEqual(classify(0),  'High Risk');
  });

  test('low phishing score overrides safe score → High Risk', () => {
    assert.strictEqual(classify(95, 3), 'High Risk');
    assert.strictEqual(classify(95, 2), 'High Risk');
  });

  test('high phishing score with safe overall score → Safe', () => {
    assert.strictEqual(classify(90, 10), 'Safe');
  });
});

// ─── CHANNEL_WEIGHTS sanity ───────────────────────────────────────────────────
describe('CHANNEL_WEIGHTS', () => {
  test('all weights are positive numbers', () => {
    for (const [id, w] of Object.entries(CHANNEL_WEIGHTS)) {
      assert.ok(w > 0, `Weight for channel "${id}" must be positive`);
    }
  });

  test('has exactly 12 channels', () => {
    assert.strictEqual(Object.keys(CHANNEL_WEIGHTS).length, 12);
  });
});
