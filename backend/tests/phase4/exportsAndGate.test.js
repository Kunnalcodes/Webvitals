/**
 * SARIF 2.1.0, Markdown Export, and CI/CD Quality Gate Unit Tests — Phase 4
 * WebVitals
 */

'use strict';

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const { exportToSarif } = require('../../exports/sarifExporter');
const { exportToMarkdown } = require('../../exports/markdownExporter');
const { evaluateQualityGate, getSarifReport, getMarkdownReport } = require('../../exports/exportService');
const { scanRepository } = require('../../storage/scanRepository');

describe('Exports & CI/CD Quality Gate', () => {
  const mockReport = {
    scanId: 'scan-export-456',
    hostname: 'export-test.com',
    requestedUrl: 'https://export-test.com',
    finalUrl: 'https://export-test.com',
    score: 85,
    grade: 'B',
    gradeLabel: 'Good Security',
    classification: 'LOW_RISK',
    scannerVersion: '3.0.0',
    scanMetadata: {
      startedAt: '2026-09-25T10:00:00Z',
      completedAt: '2026-09-25T10:00:05Z',
      durationMs: 5000,
    },
    technologies: [
      { name: 'Nginx', confidence: 0.95, category: 'Web Server', evidence: 'Server header' },
    ],
    findings: [
      {
        id: 'HSTS_MISSING',
        channel: 'HSTS',
        title: 'HSTS Header Missing',
        severity: 'HIGH',
        status: 'FAIL',
        confidence: 0.95,
        scoreImpact: -20,
        description: 'HTTP Strict Transport Security header was not found.',
        recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
      },
      {
        id: 'XFO_PASS',
        channel: 'CLICKJACKING',
        title: 'X-Frame-Options Present',
        severity: 'LOW',
        status: 'PASS',
        confidence: 1.0,
        scoreImpact: 0,
        description: 'Frame protection is active.',
      },
    ],
  };

  beforeEach(() => {
    scanRepository.saveScan(mockReport);
  });

  describe('SARIF 2.1.0 Exporter', () => {
    test('generates valid SARIF 2.1.0 JSON object', () => {
      const sarif = exportToSarif(mockReport);

      assert.equal(sarif.version, '2.1.0');
      assert.ok(sarif.$schema.includes('sarif-schema-2.1.0.json'));
      assert.ok(Array.isArray(sarif.runs));
      assert.equal(sarif.runs.length, 1);

      const run = sarif.runs[0];
      assert.equal(run.tool.driver.name, 'WebVitals Web Security Intelligence');
      assert.ok(run.tool.driver.rules.length >= 1);

      // Only failed / warning findings appear in results
      assert.equal(run.results.length, 1);
      assert.equal(run.results[0].ruleId, 'WEBVITALS-HSTS-001');
      assert.equal(run.results[0].level, 'error');
      assert.equal(run.results[0].locations[0].physicalLocation.artifactLocation.uri, 'https://export-test.com');
    });

    test('getSarifReport fetches from scan repository and exports correctly', () => {
      const sarif = getSarifReport('scan-export-456');
      assert.ok(sarif);
      assert.equal(sarif.version, '2.1.0');
    });
  });

  describe('Markdown Exporter', () => {
    test('generates clean, structured Markdown security audit report', () => {
      const md = exportToMarkdown(mockReport);

      assert.ok(typeof md === 'string');
      assert.ok(md.includes('# WebVitals Security Intelligence Audit Report'));
      assert.ok(md.includes('`export-test.com`'));
      assert.ok(md.includes('**85/100**'));
      assert.ok(md.includes('## 📊 Security Posture & Score'));
      assert.ok(md.includes('## 🛠️ Detected Technology Stack'));
      assert.ok(md.includes('Nginx'));
    });

    test('getMarkdownReport throws 404 for missing scanId', () => {
      assert.throws(() => getMarkdownReport('non-existent-scan'), {
        statusCode: 404,
      });
    });
  });

  describe('CI/CD Quality Gate', () => {
    test('passes when score >= minScore (HTTP 200)', () => {
      const gateResult = evaluateQualityGate('scan-export-456', 80);

      assert.equal(gateResult.passed, true);
      assert.equal(gateResult.statusCode, 200);
      assert.equal(gateResult.result.score, 85);
      assert.equal(gateResult.result.minimumScore, 80);
    });

    test('fails when score < minScore (HTTP 422)', () => {
      const gateResult = evaluateQualityGate('scan-export-456', 90);

      assert.equal(gateResult.passed, false);
      assert.equal(gateResult.statusCode, 422);
      assert.equal(gateResult.result.score, 85);
      assert.equal(gateResult.result.minimumScore, 90);
    });

    test('handles edge minScore values correctly', () => {
      const gateMin0 = evaluateQualityGate('scan-export-456', 0);
      assert.equal(gateMin0.passed, true);

      const gateMin100 = evaluateQualityGate('scan-export-456', 100);
      assert.equal(gateMin100.passed, false);
    });

    test('throws 404 for non-existent scan', () => {
      assert.throws(() => evaluateQualityGate('non-existent', 80), {
        statusCode: 404,
      });
    });
  });
});
