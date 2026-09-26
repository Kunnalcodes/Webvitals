/**
 * AI Service Unit Tests — Phase 4
 * WebVitals
 */

'use strict';

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const {
  explainFinding,
  generateExecutiveSummary,
  chatWithScan,
  resolveRemediation,
} = require('../../ai/aiService');
const { scanRepository } = require('../../storage/scanRepository');

describe('AI Service & Intelligence Coordinator', () => {
  const mockReport = {
    scanId: 'scan-ai-789',
    hostname: 'advisor-test.com',
    requestedUrl: 'https://advisor-test.com',
    finalUrl: 'https://advisor-test.com',
    score: 70,
    grade: 'C',
    scannerVersion: '3.0.0',
    technologies: [
      { name: 'Nginx', confidence: 0.95, category: 'Web Server' },
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
        description: 'The HTTP Strict-Transport-Security header is not present.',
        impact: 'Man-in-the-middle attackers can downgrade HTTPS connections.',
        recommendation: 'Configure HSTS header with max-age=31536000.',
      },
    ],
  };

  beforeEach(() => {
    scanRepository.saveScan(mockReport);
  });

  describe('Finding Explanation (Deterministic Offline Fallback)', () => {
    test('returns grounded explanation with offline fallback', async () => {
      const explanation = await explainFinding('scan-ai-789', 'HSTS_MISSING', 'developer');

      assert.ok(explanation);
      assert.equal(explanation.findingId, 'HSTS_MISSING');
      assert.equal(explanation.audience, 'developer');
      assert.equal(explanation.title, 'HSTS Header Missing');
      assert.ok(explanation.whyItMatters);
      assert.ok(explanation.attackScenario);
      assert.ok(explanation.validationSteps);
      assert.equal(typeof explanation.isAiGenerated, 'boolean');
    });

    test('throws 404 when scanId is missing', async () => {
      await assert.rejects(
        () => explainFinding('unknown-scan', 'HSTS_MISSING'),
        { statusCode: 404 }
      );
    });

    test('throws 404 when findingId is missing from scan', async () => {
      await assert.rejects(
        () => explainFinding('scan-ai-789', 'NON_EXISTENT_FINDING'),
        { statusCode: 404 }
      );
    });
  });

  describe('Remediation Playbook Resolution', () => {
    test('resolves technology-aware playbook for Nginx', () => {
      const remediation = resolveRemediation(mockReport, 'HSTS_MISSING');

      assert.ok(remediation);
      assert.equal(remediation.findingId, 'HSTS_MISSING');
      assert.equal(remediation.stack, 'Nginx');
      assert.equal(remediation.applicability, 'DIRECT');
      assert.ok(remediation.snippet.includes('add_header Strict-Transport-Security'));
      assert.ok(remediation.validationSteps);
      assert.ok(remediation.rollbackSteps);
    });
  });

  describe('Executive Summary Generation', () => {
    test('returns structured executive summary with fallback', async () => {
      const summary = await generateExecutiveSummary('scan-ai-789');

      assert.ok(summary);
      assert.equal(summary.target, 'advisor-test.com');
      assert.equal(summary.overallScore, 70);
      assert.equal(summary.grade, 'C');
      assert.ok(summary.postureHeadline);
      assert.ok(Array.isArray(summary.topPriorityActions));
    });
  });

  describe('Scan-Scoped AI Chat', () => {
    test('maintains scan-scoped conversation and answers security inquiries', async () => {
      const response = await chatWithScan('scan-ai-789', 'How do I fix the HSTS finding?');

      assert.ok(response);
      assert.equal(response.scanId, 'scan-ai-789');
      assert.ok(response.conversationId);
      assert.ok(response.reply);
      assert.equal(typeof response.isAiGenerated, 'boolean');
    });

    test('rejects empty chat prompts', async () => {
      await assert.rejects(
        () => chatWithScan('scan-ai-789', ''),
        { statusCode: 400 }
      );
    });

    test('isolates conversation history to the specific scanId', async () => {
      const res1 = await chatWithScan('scan-ai-789', 'First message');
      const convId = res1.conversationId;

      const res2 = await chatWithScan('scan-ai-789', 'Second message', convId);
      assert.equal(res2.conversationId, convId);
      assert.ok(res2.reply);
    });
  });
});
