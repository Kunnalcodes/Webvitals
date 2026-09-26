/**
 * CORS Security Analyzer — Phase 3
 * WebVitals
 *
 * Evaluates dynamic CORS probe telemetry to determine cross-origin exposure risks:
 *   - Arbitrary origin reflection + credentials (CRITICAL)
 *   - Null origin reflection + credentials (HIGH)
 *   - Wildcard (*) with credentials (HIGH)
 *   - Public API wildcard without credentials (PASS / INFO)
 */

'use strict';

const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');

/**
 * Analyzes dynamic CORS telemetry and produces findings.
 *
 * @param {object} corsData - Output from collectCorsTelemetry
 * @returns {import('../evidence/evidenceModel').SecurityFinding[]}
 */
function analyzeCorsSecurity(corsData) {
  const findings = [];
  if (!corsData) return findings;

  const corsEvidence = createEvidence({
    source: EVIDENCE_SOURCE.CORS,
    quality: EVIDENCE_QUALITY.DIRECT,
    observedValue: {
      acao: corsData.acao,
      acac: corsData.acac,
      varyOrigin: corsData.varyOrigin,
      reflectsExternalOrigin: corsData.reflectsExternalOrigin,
      reflectsNullOrigin: corsData.reflectsNullOrigin,
      hasWildcardOrigin: corsData.hasWildcardOrigin,
      probes: corsData.probeResponses,
    },
    notes: [`Probe risk classification: ${corsData.riskType}`],
  });

  if (corsData.riskType === 'ARBITRARY_ORIGIN_REFLECTION_WITH_CREDENTIALS') {
    findings.push(createFinding({
      id: 'CORS_ARBITRARY_ORIGIN_CREDENTIALS',
      channel: 'CORS',
      title: 'Critical CORS Misconfiguration (Arbitrary Origin Reflection with Credentials)',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.CRITICAL,
      confidence: 1.0,
      scoreImpact: -15,
      description: 'The server dynamically reflects arbitrary unverified Origin headers and sets "Access-Control-Allow-Credentials: true". Any malicious website can send authenticated requests and read private user data.',
      evidence: [corsEvidence],
      recommendation: 'Replace dynamic origin reflection with a strict allowlist of authorized domain origins.',
    }));
  } else if (corsData.riskType === 'NULL_ORIGIN_REFLECTION_WITH_CREDENTIALS') {
    findings.push(createFinding({
      id: 'CORS_NULL_ORIGIN_CREDENTIALS',
      channel: 'CORS',
      title: 'CORS Misconfiguration: Null Origin Permitted With Credentials',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 1.0,
      scoreImpact: -10,
      description: 'The server allows Origin: null with credentials enabled. Attackers can trigger cross-origin requests from sandboxed iframes (data: URIs) and read user responses.',
      evidence: [corsEvidence],
      recommendation: 'Remove "null" from allowed CORS origins.',
    }));
  } else if (corsData.riskType === 'WILDCARD_WITH_CREDENTIALS') {
    findings.push(createFinding({
      id: 'CORS_WILDCARD_CREDENTIALS_INVALID',
      channel: 'CORS',
      title: 'Invalid CORS Policy: Wildcard (*) Combined With Credentials',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 1.0,
      scoreImpact: -10,
      description: 'The server returned "Access-Control-Allow-Origin: *" alongside "Access-Control-Allow-Credentials: true". Modern browsers reject this combination, but it demonstrates insecure CORS intent.',
      evidence: [corsEvidence],
      recommendation: 'Do not use wildcard (*) if credentials (cookies/auth headers) are required; declare specific trusted origins.',
    }));
  } else if (corsData.riskType === 'ARBITRARY_ORIGIN_REFLECTION_NO_CREDENTIALS') {
    findings.push(createFinding({
      id: 'CORS_ARBITRARY_ORIGIN_NO_CREDENTIALS',
      channel: 'CORS',
      title: 'Permissive CORS: Arbitrary Origin Reflected (No Credentials)',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 0.95,
      scoreImpact: -3,
      description: 'The server reflects untrusted origin headers without credentials. While cookies are not exposed, unauthenticated internal endpoints may be readable across origins.',
      evidence: [corsEvidence],
      recommendation: 'Ensure dynamic origin reflection is restricted to public API resources.',
    }));
  } else if (corsData.riskType === 'PUBLIC_WILDCARD_NO_CREDENTIALS') {
    findings.push(createFinding({
      id: 'CORS_PUBLIC_WILDCARD',
      channel: 'CORS',
      title: 'Public CORS Policy (Wildcard * Without Credentials)',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: 'The endpoint specifies "Access-Control-Allow-Origin: *" without allowing credentials. This is standard and expected for public APIs and CDN assets.',
      evidence: [corsEvidence],
      limitations: ['Public wildcard access is safe for public resources, but must not be used on authenticated endpoints.'],
    }));
  } else {
    findings.push(createFinding({
      id: 'CORS_RESTRICTED',
      channel: 'CORS',
      title: 'Cross-Origin Resource Sharing (CORS) Restricted',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: 'The server does not permit arbitrary untrusted cross-origin requests.',
      evidence: [corsEvidence],
    }));
  }

  return findings;
}

module.exports = {
  analyzeCorsSecurity,
};
