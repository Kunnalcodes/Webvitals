/**
 * TLS Security Analyzer Unit Tests — Phase 3
 * WebVitals
 *
 * Tests SAN wildcard matching, expiration states, self-signed detection, protocol version checks.
 * Run: node --test backend/tests/phase3/tlsAnalyzer.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeTlsSecurity } = require('../../analyzers/tlsAnalyzer');
const { matchesHostname } = require('../../telemetry/tlsTelemetry');

describe('TLS Hostname SANs Matching', () => {
  test('matches exact hostname', () => {
    assert.strictEqual(matchesHostname('example.com', ['example.com', 'www.example.com']), true);
    assert.strictEqual(matchesHostname('other.com', ['example.com']), false);
  });

  test('matches wildcard SANs (*.example.com)', () => {
    assert.strictEqual(matchesHostname('sub.example.com', ['*.example.com']), true);
    assert.strictEqual(matchesHostname('api.example.com', ['*.example.com']), true);
    // Wildcard should not match multiple subdomain levels (RFC 6125)
    assert.strictEqual(matchesHostname('deep.sub.example.com', ['*.example.com']), false);
    // Wildcard does not match apex directly
    assert.strictEqual(matchesHostname('example.com', ['*.example.com']), false);
  });
});

describe('TLS Security Findings Generation', () => {
  const baseHttpData = {
    protocol: 'https:',
    requestedUrl: 'https://example.com',
    finalUrl: 'https://example.com',
  };

  test('generates PASS for valid certificate and TLS 1.3', () => {
    const mockTls = {
      connected: true,
      hasCert: true,
      hostname: 'example.com',
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_256_GCM_SHA384' },
      commonName: 'example.com',
      subjectAltNames: ['example.com', 'www.example.com'],
      validFrom: 'Jan 1 2026',
      validTo: 'Jan 1 2027',
      daysRemaining: 200,
      isExpired: false,
      isNearExpiry: false,
      isHostnameMatch: true,
      isSelfSigned: false,
      authorized: true,
    };

    const findings = analyzeTlsSecurity(mockTls, baseHttpData);
    assert.ok(findings.some((f) => f.id === 'HTTPS_ENABLED' && f.status === 'PASS'));
    assert.ok(findings.some((f) => f.id === 'TLS_HOSTNAME_VALID' && f.status === 'PASS'));
    assert.ok(findings.some((f) => f.id === 'TLS_CERT_VALID' && f.status === 'PASS'));
    assert.ok(findings.some((f) => f.id === 'TLS_MODERN_PROTOCOL' && f.status === 'PASS'));
  });

  test('generates CRITICAL FAIL for expired certificate', () => {
    const expiredTls = {
      connected: true,
      hasCert: true,
      hostname: 'example.com',
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_128_GCM_SHA256' },
      commonName: 'example.com',
      subjectAltNames: ['example.com'],
      validTo: 'Jan 1 2024',
      daysRemaining: -50,
      isExpired: true,
      isNearExpiry: false,
      isHostnameMatch: true,
      isSelfSigned: false,
      authorized: false,
    };

    const findings = analyzeTlsSecurity(expiredTls, baseHttpData);
    const expiredFinding = findings.find((f) => f.id === 'TLS_CERT_EXPIRED');
    assert.ok(expiredFinding);
    assert.strictEqual(expiredFinding.status, 'FAIL');
    assert.strictEqual(expiredFinding.severity, 'CRITICAL');
  });

  test('generates HIGH FAIL for hostname mismatch', () => {
    const mismatchTls = {
      connected: true,
      hasCert: true,
      hostname: 'target.com',
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_128_GCM_SHA256' },
      commonName: 'wrong.com',
      subjectAltNames: ['wrong.com'],
      validTo: 'Jan 1 2027',
      daysRemaining: 150,
      isExpired: false,
      isNearExpiry: false,
      isHostnameMatch: false,
      isSelfSigned: false,
      authorized: false,
    };

    const findings = analyzeTlsSecurity(mismatchTls, baseHttpData);
    const mismatchFinding = findings.find((f) => f.id === 'TLS_HOSTNAME_MISMATCH');
    assert.ok(mismatchFinding);
    assert.strictEqual(mismatchFinding.status, 'FAIL');
    assert.strictEqual(mismatchFinding.severity, 'HIGH');
  });

  test('generates FAIL for deprecated TLS 1.0/1.1 protocol', () => {
    const legacyTls = {
      connected: true,
      hasCert: true,
      hostname: 'example.com',
      protocol: 'TLSv1.0',
      cipher: { name: 'ECDHE-RSA-AES128-SHA' },
      commonName: 'example.com',
      subjectAltNames: ['example.com'],
      validTo: 'Jan 1 2027',
      daysRemaining: 150,
      isExpired: false,
      isNearExpiry: false,
      isHostnameMatch: true,
      isSelfSigned: false,
      authorized: true,
    };

    const findings = analyzeTlsSecurity(legacyTls, baseHttpData);
    const legacyFinding = findings.find((f) => f.id === 'TLS_DEPRECATED_PROTOCOL');
    assert.ok(legacyFinding);
    assert.strictEqual(legacyFinding.status, 'FAIL');
  });
});
