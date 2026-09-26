/**
 * Executive Summary Engine Unit Tests — Phase 4
 * WebVitals
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { generateDeterministicExecutiveSummary, estimateEffort } = require('../../executive/executiveSummaryEngine');

describe('Executive Summary Engine', () => {
  const mockReport = {
    scanId: 'scan-exec-123',
    hostname: 'example.com',
    score: 65,
    grade: 'D',
    scannerVersion: '3.0.0',
    findings: [
      {
        id: 'HSTS_MISSING',
        channel: 'HSTS',
        title: 'HSTS Header Missing',
        severity: 'HIGH',
        status: 'FAIL',
        scoreImpact: -20,
        impact: 'Users are vulnerable to SSL stripping.',
        recommendation: 'Add Strict-Transport-Security header.',
      },
      {
        id: 'CSP_MISSING',
        channel: 'CSP',
        title: 'Content Security Policy Missing',
        severity: 'HIGH',
        status: 'FAIL',
        scoreImpact: -15,
        impact: 'Increased risk of XSS execution.',
        recommendation: 'Implement CSP header.',
      },
      {
        id: 'SPF_RECORD_MISSING',
        channel: 'DNS',
        title: 'SPF Record Missing',
        severity: 'MEDIUM',
        status: 'FAIL',
        scoreImpact: -10,
        impact: 'Domain spoofing risks.',
        recommendation: 'Add TXT SPF record.',
      },
      {
        id: 'TLS_STRONG',
        channel: 'TLS',
        title: 'Strong TLS Configuration',
        severity: 'INFO',
        status: 'PASS',
        scoreImpact: 0,
      },
    ],
  };

  test('generateDeterministicExecutiveSummary generates accurate statistics', () => {
    const summary = generateDeterministicExecutiveSummary(mockReport);

    assert.ok(summary);
    assert.equal(summary.target, 'example.com');
    assert.equal(summary.scanId, 'scan-exec-123');
    assert.equal(summary.overallScore, 65);
    assert.equal(summary.grade, 'D');

    assert.equal(summary.counts.high, 2);
    assert.equal(summary.counts.medium, 1);
    assert.equal(summary.counts.critical, 0);
  });

  test('prioritizes top actions by score impact', () => {
    const summary = generateDeterministicExecutiveSummary(mockReport);
    assert.ok(Array.isArray(summary.topPriorityActions));
    assert.equal(summary.topPriorityActions.length, 3);

    // First priority should be HSTS (-20), followed by CSP (-15), then SPF (-10)
    assert.equal(summary.topPriorityActions[0].findingId, 'HSTS_MISSING');
    assert.equal(summary.topPriorityActions[1].findingId, 'CSP_MISSING');
    assert.equal(summary.topPriorityActions[2].findingId, 'SPF_RECORD_MISSING');
  });

  test('categorizes effort vs impact correctly', () => {
    const summary = generateDeterministicExecutiveSummary(mockReport);

    assert.ok(summary.effortVsImpact);
    assert.ok(summary.effortVsImpact.quickWins.length >= 1);
    assert.ok(summary.effortVsImpact.strategicActions.length >= 1);
  });

  test('estimateEffort assigns appropriate effort categories', () => {
    assert.equal(estimateEffort({ channel: 'HSTS', id: 'HSTS_1' }), 'LOW');
    assert.equal(estimateEffort({ channel: 'DNS', id: 'SPF_RECORD_MISSING' }), 'LOW');
    assert.equal(estimateEffort({ channel: 'CORS', id: 'CORS_WILDCARD' }), 'MEDIUM');
    assert.equal(estimateEffort({ channel: 'CSP', id: 'CSP_MISSING' }), 'HIGH');
    assert.equal(estimateEffort({ channel: 'TLS', id: 'TLS_WEAK' }), 'HIGH');
  });

  test('handles empty or missing findings gracefully', () => {
    const emptyReport = { scanId: 'scan-empty', hostname: 'empty.com', score: 100, grade: 'A', findings: [] };
    const summary = generateDeterministicExecutiveSummary(emptyReport);

    assert.ok(summary);
    assert.equal(summary.overallScore, 100);
    assert.equal(summary.topPriorityActions.length, 0);
    assert.equal(summary.counts.critical, 0);
  });
});
