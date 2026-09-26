/**
 * Remediation Engine & Generators Unit Tests — Phase 4
 * WebVitals
 *
 * Tests multi-stack code generation for Nginx, Apache, Node, Next.js, Caddy, Cloudflare, and DNS.
 * Run: node --test backend/tests/phase4/remediation.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { resolveRemediation } = require('../../remediation/remediationEngine');
const { generateNginxRemediation } = require('../../remediation/generators/nginxGenerator');
const { generateApacheRemediation } = require('../../remediation/generators/apacheGenerator');
const { generateNodeRemediation } = require('../../remediation/generators/nodeGenerator');
const { generateNextRemediation } = require('../../remediation/generators/nextGenerator');
const { generateDnsRemediation } = require('../../remediation/generators/dnsGenerator');

describe('Remediation Generators', () => {
  test('Nginx generator outputs valid add_header syntax and rollback steps', () => {
    const res = generateNginxRemediation('HSTS_MISSING');
    assert.ok(res);
    assert.strictEqual(res.stack, 'Nginx');
    assert.match(res.snippet, /add_header Strict-Transport-Security/);
    assert.ok(res.validationSteps);
    assert.ok(res.rollbackSteps);
  });

  test('Apache generator outputs mod_headers directives', () => {
    const res = generateApacheRemediation('CLICKJACKING_UNPROTECTED');
    assert.ok(res);
    assert.strictEqual(res.stack, 'Apache');
    assert.match(res.snippet, /Header always set X-Frame-Options/);
  });

  test('Node.js generator outputs zero-dependency middleware', () => {
    const res = generateNodeRemediation('MIME_SNIFFING_UNPROTECTED');
    assert.ok(res);
    assert.match(res.snippet, /res\.setHeader\('X-Content-Type-Options', 'nosniff'\)/);
  });

  test('Next.js generator outputs next.config.js headers array', () => {
    const res = generateNextRemediation('CSP_MISSING');
    assert.ok(res);
    assert.strictEqual(res.stack, 'Next.js');
    assert.match(res.snippet, /next\.config\.js/);
  });

  test('DNS generator produces SPF record with merge warning', () => {
    const res = generateDnsRemediation('SPF_MISSING', 'example.com');
    assert.ok(res);
    assert.match(res.snippet, /v=spf1/);
    assert.ok(res.compatibilityWarnings.some((w) => w.includes('CRITICAL: Do NOT publish this record without merging')));
  });
});

describe('Remediation Engine Resolution', () => {
  test('automatically routes to detected Nginx stack when confidence is high', () => {
    const mockReport = {
      hostname: 'example.com',
      findings: [{ id: 'HSTS_MISSING', channel: 'HSTS', status: 'FAIL', description: 'Missing' }],
      technologies: [{ name: 'Nginx', confidence: 0.95 }],
    };

    const rem = resolveRemediation(mockReport, 'HSTS_MISSING');
    assert.ok(rem);
    assert.strictEqual(rem.stack, 'Nginx');
    assert.strictEqual(rem.applicability, 'DIRECT');
  });

  test('honors preferredStack override when requested by user', () => {
    const mockReport = {
      hostname: 'example.com',
      findings: [{ id: 'HSTS_MISSING', channel: 'HSTS', status: 'FAIL', description: 'Missing' }],
      technologies: [{ name: 'Nginx', confidence: 0.95 }],
    };

    const rem = resolveRemediation(mockReport, 'HSTS_MISSING', 'apache');
    assert.ok(rem);
    assert.strictEqual(rem.stack, 'Apache');
  });

  test('routes SPF finding to DNS provider generator regardless of server stack', () => {
    const mockReport = {
      hostname: 'example.com',
      findings: [{ id: 'SPF_MISSING', channel: 'DNS', status: 'FAIL', description: 'Missing' }],
      technologies: [{ name: 'Next.js', confidence: 0.95 }],
    };

    const rem = resolveRemediation(mockReport, 'SPF_MISSING');
    assert.ok(rem);
    assert.match(rem.stack, /DNS Provider/i);
  });
});
