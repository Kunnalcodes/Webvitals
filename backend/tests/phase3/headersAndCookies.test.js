/**
 * Headers & Cookies Security Analyzers Unit Tests — Phase 3
 * WebVitals
 *
 * Tests HSTS, CSP, Clickjacking dual-correlation, and Cookie security classification.
 * Run: node --test backend/tests/phase3/headersAndCookies.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeSecurityHeaders, parseHsts, parseCsp } = require('../../analyzers/headerAnalyzer');
const { analyzeCookieSecurity, parseSetCookieHeaders } = require('../../analyzers/cookieAnalyzer');

describe('Security Headers Analyzer', () => {
  test('parseHsts extracts max-age, includeSubDomains, and preload', () => {
    const parsed = parseHsts('max-age=31536000; includeSubDomains; preload');
    assert.strictEqual(parsed.maxAge, 31536000);
    assert.strictEqual(parsed.includeSubDomains, true);
    assert.strictEqual(parsed.preload, true);
  });

  test('parseCsp detects unsafe-inline and unsafe-eval', () => {
    const parsed = parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'");
    assert.strictEqual(parsed.hasUnsafeInline, true);
    assert.strictEqual(parsed.hasUnsafeEval, true);
    assert.strictEqual(parsed.blocksObjects, true);
  });

  test('clickjacking passes when CSP frame-ancestors is present even without X-Frame-Options', () => {
    const headers = {
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
    };

    const findings = analyzeSecurityHeaders(headers, true);
    const clickjack = findings.find((f) => f.id === 'CLICKJACKING_PROTECTED');
    assert.ok(clickjack);
    assert.strictEqual(clickjack.status, 'PASS');
  });
});

describe('Cookie Security Analyzer', () => {
  test('parseSetCookieHeaders classifies session cookies vs analytics cookies', () => {
    const rawCookies = [
      'session_id=abc12345; Secure; HttpOnly; SameSite=Strict',
      '_ga=GA1.2.12345678.12345678; Path=/; Domain=.example.com',
    ];
    const parsed = parseSetCookieHeaders(rawCookies);
    assert.strictEqual(parsed[0].name, 'session_id');
    assert.strictEqual(parsed[0].purpose, 'AUTHENTICATION_SESSION');
    assert.strictEqual(parsed[0].isSession, true);
    assert.strictEqual(parsed[0].httpOnly, true);
    assert.strictEqual(parsed[0].secure, true);

    assert.strictEqual(parsed[1].name, '_ga');
    assert.strictEqual(parsed[1].purpose, 'ANALYTICS_TRACKING');
    assert.strictEqual(parsed[1].isSession, false);
  });

  test('flags session cookie missing HttpOnly as HIGH FAIL', () => {
    const headers = {
      'set-cookie': 'auth_token=jwt_secret_token_value; Secure; SameSite=Lax',
    };
    const findings = analyzeCookieSecurity(headers, true);
    const sessionFinding = findings.find((f) => f.id === 'COOKIE_SESSION_HTTPONLY_MISSING');
    assert.ok(sessionFinding);
    assert.strictEqual(sessionFinding.status, 'FAIL');
    assert.strictEqual(sessionFinding.severity, 'HIGH');
  });
});
