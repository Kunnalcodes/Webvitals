/**
 * Sensitive File & Exposure Analyzer — Phase 3
 * WebVitals
 *
 * Implements multi-stage false-positive reduction:
 *   1. Establishes random 404 baseline profile
 *   2. Probes sensitive endpoints with strict bounded requests
 *   3. Compares response against baseline (body hash, structural hash, SPA routing)
 *   4. Applies byte/text content signature matching
 *   5. Discards HTML SPA shells
 *   6. Redacts secrets from evidence before reporting
 */

'use strict';

const { URL } = require('url');
const { SENSITIVE_PROBES } = require('../signatures/sensitiveFileSignatures');
const { establish404Baseline, isSoft404 } = require('../baselines/baselineEngine');
const { collectHttpTelemetry } = require('../telemetry/httpTelemetry');
const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');

/**
 * Scans for exposed sensitive files on target domain with false-positive elimination.
 *
 * @param {URL|string} baseUrl
 * @returns {Promise<{ findings: import('../evidence/evidenceModel').SecurityFinding[], summary: object }>}
 */
async function analyzeSensitiveFileExposures(baseUrl) {
  const urlObj = typeof baseUrl === 'string' ? new URL(baseUrl) : baseUrl;
  const findings = [];
  const exposedProbes = [];

  // Step 1: Establish baseline 404 behavior
  const baseline = await establish404Baseline(urlObj);

  // Step 2: Probe sensitive endpoints
  for (const probe of SENSITIVE_PROBES) {
    const probeUrl = new URL(probe.path, urlObj.origin);

    const telemetry = await collectHttpTelemetry(probeUrl, {
      method: 'GET',
      maxRedirects: 3,
      maxBodyBytes: 32 * 1024, // 32KB max
      timeoutMs: 6000,
    });

    // If status is not 200, file is not publicly exposed
    if (telemetry.status !== 200) {
      continue;
    }

    // Step 3: Check against soft-404 baseline
    const soft404Check = isSoft404(telemetry, baseline);
    if (soft404Check.isSoft404) {
      // Soft 404 or SPA fallback detected — discard to eliminate false positive
      continue;
    }

    // Step 4: Check MIME filtering (HTML rejection for binary/config files)
    const cType = (telemetry.contentType || '').toLowerCase();
    if (probe.disallowHtml && cType.includes('text/html')) {
      // Returned HTML for a .env / .git / .zip file -> SPA fallback / custom error -> discard
      continue;
    }

    // Step 5: Content signature verification
    const sigResult = probe.signatureCheck(telemetry.bodySnippet, telemetry.headers);
    if (!sigResult.matched) {
      // Content did not match expected structural signature -> discard
      continue;
    }

    // Verified genuine exposure!
    const evidence = createEvidence({
      source: EVIDENCE_SOURCE.PROBE,
      quality: EVIDENCE_QUALITY.CORROBORATED,
      request: { method: 'GET', url: probeUrl.toString() },
      response: {
        status: telemetry.status,
        contentType: telemetry.contentType,
        contentLength: telemetry.contentLength,
        bodyHash: telemetry.bodyHash,
      },
      observedValue: {
        matchedPath: probe.path,
        signature: sigResult.signature,
        redactedSnippet: sigResult.snippet,
      },
      signature: sigResult.signature,
      confidence: 0.98,
      notes: [
        'Verified against random 404 baseline (distinct body and structural hash)',
        'Content matched file-type signature; secrets were automatically redacted',
      ],
    });

    exposedProbes.push(probe.name);

    findings.push(createFinding({
      id: `EXPOSED_FILE_${probe.name.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
      channel: 'SENSITIVE_FILES',
      title: `Critical File Exposure: ${probe.name}`,
      status: DETERMINATION.FAIL,
      severity: probe.risk === 'CRITICAL' ? SEVERITY.CRITICAL : probe.risk === 'HIGH' ? SEVERITY.HIGH : SEVERITY.INFO,
      confidence: 0.98,
      scoreImpact: probe.risk === 'CRITICAL' ? -20 : probe.risk === 'HIGH' ? -10 : 0,
      description: `Publicly accessible sensitive file found at '${probe.path}'. The file was verified via signature matching (${sigResult.signature}) and confirmed distinct from server 404/SPA catch-all responses.`,
      evidence: [evidence],
      recommendation: `Restrict access to '${probe.path}' in your web server / reverse-proxy configuration immediately.`,
    }));
  }

  // If no sensitive files were exposed
  if (findings.length === 0) {
    findings.push(createFinding({
      id: 'SENSITIVE_FILES_PROTECTED',
      channel: 'SENSITIVE_FILES',
      title: 'No Exposed Sensitive Files Detected',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 0.95,
      scoreImpact: 5,
      description: 'Probed common sensitive paths (.env, .git, .htaccess, backup files). No exposures were detected, and soft-404 false alarms were filtered.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.PROBE,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: { checkedPaths: SENSITIVE_PROBES.map((p) => p.path), baselineActive: baseline.isSoft404Active },
      })],
      limitations: ['Black-box probing is restricted to standard sensitive paths and does not guarantee the absence of unindexed confidential endpoints.'],
    }));
  }

  return {
    findings,
    summary: {
      totalProbed: SENSITIVE_PROBES.length,
      exposedCount: exposedProbes.length,
      baselineSoft404: baseline.isSoft404Active,
      exposedFiles: exposedProbes,
    },
  };
}

module.exports = {
  analyzeSensitiveFileExposures,
};
