/**
 * SSRF Protection Tests — Phase 1
 * WebVitals
 *
 * Tests every SSRF scenario documented in the Phase 0 audit.
 * Uses Node.js built-in test runner (node --test).
 *
 * Run: node --test tests/ssrf.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  isRestrictedHost,
  isBlockedIPv4,
  isBlockedIPv6,
  validateTargetUrl,
} = require('../middleware/abuseProtection');

// ─── isBlockedIPv4 ────────────────────────────────────────────────────────────
describe('isBlockedIPv4 — blocked ranges', () => {
  const blocked = [
    '127.0.0.1', '127.0.0.2', '127.255.255.255',   // Loopback
    '10.0.0.1', '10.255.255.255',                    // RFC-1918
    '172.16.0.1', '172.31.255.255',                  // RFC-1918
    '192.168.0.1', '192.168.255.255',                // RFC-1918
    '169.254.0.1', '169.254.169.254',                // Link-local / metadata
    '0.0.0.1', '0.255.255.255',                      // Unspecified
    '224.0.0.1', '239.255.255.255',                  // Multicast
    '240.0.0.1', '255.255.255.255',                  // Reserved
  ];
  for (const ip of blocked) {
    test(`blocks ${ip}`, () => assert.ok(isBlockedIPv4(ip), `Expected ${ip} to be blocked`));
  }
});

describe('isBlockedIPv4 — allowed public IPs', () => {
  const allowed = ['1.1.1.1', '8.8.8.8', '142.250.185.78', '104.16.0.0'];
  for (const ip of allowed) {
    test(`allows ${ip}`, () => assert.ok(!isBlockedIPv4(ip), `Expected ${ip} to be allowed`));
  }
});

// ─── isBlockedIPv6 ────────────────────────────────────────────────────────────
describe('isBlockedIPv6 — blocked ranges', () => {
  const blocked = [
    '::1',             // loopback
    '::',              // unspecified
    'fc00::1',         // unique local (fc00::/7)
    'fd12:3456::1',    // unique local (fd prefix)
    'fe80::1',         // link-local
    'feab::1',         // link-local
    '::ffff:127.0.0.1',  // IPv4-mapped loopback
    '::ffff:10.0.0.1',   // IPv4-mapped private
    '::ffff:192.168.1.1', // IPv4-mapped private
  ];
  for (const ip of blocked) {
    test(`blocks ${ip}`, () => assert.ok(isBlockedIPv6(ip), `Expected ${ip} to be blocked`));
  }
});

describe('isBlockedIPv6 — allowed public IPv6', () => {
  const allowed = ['2001:db8::1', '2606:4700::1111', '2a00:1450:4001:81e::200e'];
  for (const ip of allowed) {
    test(`allows ${ip}`, () => assert.ok(!isBlockedIPv6(ip), `Expected ${ip} to be allowed`));
  }
});

// ─── isRestrictedHost ─────────────────────────────────────────────────────────
describe('isRestrictedHost — blocked hostnames', () => {
  const blocked = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    'metadata.google.internal',
    'metadata.google',
    '169.254.169.254',
    'app.localhost',
    'service.local',
    'internal.corp',
    'my.intranet',
  ];
  for (const host of blocked) {
    test(`blocks ${host}`, () => assert.ok(isRestrictedHost(host), `Expected ${host} to be blocked`));
  }
});

describe('isRestrictedHost — allowed public hostnames', () => {
  const allowed = ['example.com', 'google.com', 'github.com', 'api.example.org'];
  for (const host of allowed) {
    test(`allows ${host}`, () => assert.ok(!isRestrictedHost(host), `Expected ${host} to be allowed`));
  }
});

// ─── validateTargetUrl ────────────────────────────────────────────────────────
describe('validateTargetUrl — blocked inputs', () => {
  const cases = [
    { input: 'javascript:alert(1)',       desc: 'javascript: scheme' },
    { input: 'file:///etc/passwd',        desc: 'file: scheme' },
    { input: 'ftp://example.com',         desc: 'ftp: scheme' },
    { input: 'data:text/html,<h1>hi</h1>',desc: 'data: scheme' },
    { input: 'http://localhost/',          desc: 'localhost HTTP' },
    { input: 'http://127.0.0.1/',          desc: 'loopback IP' },
    { input: 'https://10.0.0.1/',          desc: 'private RFC-1918' },
    { input: 'https://192.168.1.1/',       desc: 'private RFC-1918 /16' },
    { input: 'https://169.254.169.254/',   desc: 'metadata IP' },
    { input: '',                            desc: 'empty string' },
    { input: null,                          desc: 'null' },
    { input: 'a'.repeat(2049),             desc: 'URL too long' },
    { input: 'https://example.com/<script>alert(1)</script>', desc: 'script injection' },
  ];
  for (const { input, desc } of cases) {
    test(`rejects: ${desc}`, () => {
      const result = validateTargetUrl(input);
      assert.strictEqual(result.valid, false, `Expected validation to fail for: ${desc}`);
    });
  }
});

describe('validateTargetUrl — valid inputs', () => {
  const cases = [
    'https://example.com',
    'http://example.com',
    'example.com',
    'https://sub.example.org/path?q=1',
    'https://1.1.1.1',  // Public IP — allowed
  ];
  for (const input of cases) {
    test(`accepts: ${input}`, () => {
      const result = validateTargetUrl(input);
      assert.strictEqual(result.valid, true, `Expected validation to pass for: ${input}`);
    });
  }
});

describe('validateTargetUrl — normalizes URLs without protocol', () => {
  test('adds https:// to bare domain', () => {
    const result = validateTargetUrl('example.com');
    assert.ok(result.valid);
    assert.ok(result.normalizedUrl.startsWith('https://'));
  });
});
