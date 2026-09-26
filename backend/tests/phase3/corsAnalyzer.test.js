/**
 * CORS Security Analyzer Unit Tests — Phase 3
 * WebVitals
 *
 * Tests dynamic CORS analysis for origin reflection, credentials exposure, and public wildcards.
 * Run: node --test backend/tests/phase3/corsAnalyzer.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeCorsSecurity } = require('../../analyzers/corsAnalyzer');

describe('CORS Security Analyzer', () => {
  test('flags arbitrary origin reflection with credentials as CRITICAL FAIL', () => {
    const corsTelemetry = {
      targetUrl: 'https://api.example.com',
      acao: 'https://webvitals-origin-audit.invalid',
      acac: true,
      varyOrigin: true,
      reflectsExternalOrigin: true,
      reflectsNullOrigin: false,
      hasWildcardOrigin: false,
      riskType: 'ARBITRARY_ORIGIN_REFLECTION_WITH_CREDENTIALS',
      probeResponses: {},
    };

    const findings = analyzeCorsSecurity(corsTelemetry);
    const criticalFinding = findings.find((f) => f.id === 'CORS_ARBITRARY_ORIGIN_CREDENTIALS');
    assert.ok(criticalFinding);
    assert.strictEqual(criticalFinding.status, 'FAIL');
    assert.strictEqual(criticalFinding.severity, 'CRITICAL');
  });

  test('flags null origin reflection with credentials as HIGH FAIL', () => {
    const corsTelemetry = {
      targetUrl: 'https://api.example.com',
      acao: 'null',
      acac: true,
      reflectsExternalOrigin: false,
      reflectsNullOrigin: true,
      hasWildcardOrigin: false,
      riskType: 'NULL_ORIGIN_REFLECTION_WITH_CREDENTIALS',
      probeResponses: {},
    };

    const findings = analyzeCorsSecurity(corsTelemetry);
    const nullFinding = findings.find((f) => f.id === 'CORS_NULL_ORIGIN_CREDENTIALS');
    assert.ok(nullFinding);
    assert.strictEqual(nullFinding.status, 'FAIL');
    assert.strictEqual(nullFinding.severity, 'HIGH');
  });

  test('treats public API wildcard (*) without credentials as PASS / INFO', () => {
    const corsTelemetry = {
      targetUrl: 'https://api.example.com/public',
      acao: '*',
      acac: false,
      reflectsExternalOrigin: false,
      reflectsNullOrigin: false,
      hasWildcardOrigin: true,
      riskType: 'PUBLIC_WILDCARD_NO_CREDENTIALS',
      probeResponses: {},
    };

    const findings = analyzeCorsSecurity(corsTelemetry);
    const publicFinding = findings.find((f) => f.id === 'CORS_PUBLIC_WILDCARD');
    assert.ok(publicFinding);
    assert.strictEqual(publicFinding.status, 'PASS');
    assert.strictEqual(publicFinding.severity, 'INFO');
  });
});
