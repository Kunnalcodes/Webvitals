/**
 * Phishing & Homograph Analyzer Unit Tests — Phase 3
 * WebVitals
 *
 * Tests entropy calculation, Punycode detection, and false-positive suppression on legitimate subdomains.
 * Run: node --test backend/tests/phase3/phishingAnalyzer.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { analyzePhishingHeuristics, calculateShannonEntropy } = require('../../analyzers/phishingAnalyzer');

describe('Phishing Heuristics & False-Positive Elimination', () => {
  test('calculateShannonEntropy calculates higher entropy for random strings', () => {
    const lowEntropy = calculateShannonEntropy('aaaaaa');
    const normalDomain = calculateShannonEntropy('example.com');
    const highEntropy = calculateShannonEntropy('x7k9q2m1z8w4p5t0');

    assert.ok(lowEntropy < 1.0);
    assert.ok(highEntropy > normalDomain);
  });

  test('does NOT penalize legitimate login subdomains on trusted apex domains', () => {
    const msLogin = 'https://login.microsoft.com/oauth/authorize';
    const findings = analyzePhishingHeuristics(msLogin);
    const cleanFinding = findings.find((f) => f.id === 'PHISHING_HEURISTIC_CLEAN');
    assert.ok(cleanFinding);
    assert.strictEqual(cleanFinding.status, 'PASS');
  });

  test('flags Punycode and excessive hyphens on untrusted domain as HIGH RISK', () => {
    const suspiciousUrl = 'https://xn--pypal-4ve-security-update-center.com/login';
    const findings = analyzePhishingHeuristics(suspiciousUrl);
    const highRisk = findings.find((f) => f.id === 'PHISHING_HEURISTIC_HIGH_RISK');
    assert.ok(highRisk);
    assert.strictEqual(highRisk.status, 'WARNING');
    assert.strictEqual(highRisk.severity, 'HIGH');
  });
});
