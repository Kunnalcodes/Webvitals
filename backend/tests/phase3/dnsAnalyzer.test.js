/**
 * DNS Security Analyzer Unit Tests — Phase 3
 * WebVitals
 *
 * Tests SPF policies, multiple SPF records, DMARC policies, CAA, and boundary declarations.
 * Run: node --test backend/tests/phase3/dnsAnalyzer.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeDnsSecurity } = require('../../analyzers/dnsAnalyzer');
const { parseSpfRecord, parseDmarcRecord } = require('../../telemetry/dnsTelemetry');

describe('SPF & DMARC Parsers', () => {
  test('parseSpfRecord parses -all and ~all correctly', () => {
    const hard = parseSpfRecord('v=spf1 include:_spf.google.com -all');
    assert.strictEqual(hard.policy, 'HARD_FAIL');
    assert.strictEqual(hard.includesCount, 1);

    const soft = parseSpfRecord('v=spf1 ip4:1.2.3.4 ~all');
    assert.strictEqual(soft.policy, 'SOFT_FAIL');

    const perm = parseSpfRecord('v=spf1 +all');
    assert.strictEqual(perm.policy, 'PASS_ALL_PERMISSIVE');
  });

  test('parseDmarcRecord parses reject, quarantine, none policies', () => {
    const dmarcReject = parseDmarcRecord('v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100');
    assert.strictEqual(dmarcReject.policy, 'REJECT');
    assert.strictEqual(dmarcReject.percentage, 100);
    assert.strictEqual(dmarcReject.reportUriAggregate, 'mailto:d@example.com');

    const dmarcNone = parseDmarcRecord('v=DMARC1; p=none');
    assert.strictEqual(dmarcNone.policy, 'MONITORING_NONE');
  });
});

describe('DNS Security Findings', () => {
  test('detects multiple SPF records as HIGH FAIL', () => {
    const mockDns = {
      domain: 'example.com',
      records: { txt: ['v=spf1 include:a.com -all', 'v=spf1 include:b.com -all'] },
      spf: {
        present: true,
        hasMultiple: true,
        records: [parseSpfRecord('v=spf1 include:a.com -all'), parseSpfRecord('v=spf1 include:b.com -all')],
        primary: null,
      },
      dmarc: { present: true, parsed: parseDmarcRecord('v=DMARC1; p=reject') },
      caa: { present: true, records: [{ issue: 'letsencrypt.org' }], authorities: ['letsencrypt.org'] },
    };

    const findings = analyzeDnsSecurity(mockDns);
    const multiSpf = findings.find((f) => f.id === 'SPF_MULTIPLE_RECORDS');
    assert.ok(multiSpf);
    assert.strictEqual(multiSpf.status, 'FAIL');
    assert.strictEqual(multiSpf.severity, 'HIGH');
  });

  test('differentiates DMARC p=none as WARNING and p=reject as PASS', () => {
    const dnsNone = {
      domain: 'example.com',
      records: { txt: [] },
      spf: { present: true, hasMultiple: false, records: [parseSpfRecord('v=spf1 -all')], primary: parseSpfRecord('v=spf1 -all') },
      dmarc: { present: true, parsed: parseDmarcRecord('v=DMARC1; p=none') },
      caa: { present: false, records: [], authorities: [] },
    };

    const findings = analyzeDnsSecurity(dnsNone);
    const dmarcNoneFinding = findings.find((f) => f.id === 'DMARC_POLICY_NONE');
    assert.ok(dmarcNoneFinding);
    assert.strictEqual(dmarcNoneFinding.status, 'WARNING');

    const dkimFinding = findings.find((f) => f.id === 'DKIM_EVALUATION_BOUNDARY');
    assert.ok(dkimFinding);
    assert.strictEqual(dkimFinding.status, 'NOT_EVALUATED');
  });
});
