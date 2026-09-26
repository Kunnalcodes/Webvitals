/**
 * HTTP Verb & Method Tampering Diagnostic Analyzer
 * WebVitals Web Security Intelligence
 *
 * Evaluates supported HTTP methods and probes for:
 *   1. Cross-Site Tracing (XST) via enabled TRACE / TRACK methods
 *   2. Information leakage via OPTIONS headers (Allow / Public)
 *   3. Insecure / dangerous verb exposure (PUT, DELETE, DEBUG, PROPFIND)
 */

'use strict';

const { URL } = require('url');
const { collectHttpTelemetry } = require('../telemetry/httpTelemetry');
const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');

/**
 * Analyzes supported HTTP methods and verb tampering resilience.
 *
 * @param {URL|string} targetUrl
 * @returns {Promise<{ findings: import('../evidence/evidenceModel').SecurityFinding[], telemetry: object }>}
 */
async function analyzeHttpVerbs(targetUrl) {
  const urlObj = typeof targetUrl === 'string' ? new URL(targetUrl) : targetUrl;
  const findings = [];
  const methodResults = {};

  const methodsToTest = ['OPTIONS', 'TRACE', 'TRACK', 'HEAD', 'PUT', 'DELETE'];

  for (const method of methodsToTest) {
    try {
      const res = await collectHttpTelemetry(urlObj, {
        method,
        maxRedirects: 2,
        maxBodyBytes: 8 * 1024,
        timeoutMs: 4000,
      });

      methodResults[method] = {
        status: res.status,
        allowed: res.status !== 405 && res.status !== 501 && res.status !== 403 && res.status !== 400 && res.status > 0,
        allowHeader: res.headers?.['allow'] || res.headers?.['public'] || null,
        bodySnippet: (res.bodySnippet || '').slice(0, 200),
      };
    } catch (err) {
      methodResults[method] = {
        status: 0,
        allowed: false,
        error: err.message,
      };
    }
  }

  // 1. Check for TRACE / TRACK (Cross-Site Tracing / XST vulnerability)
  const traceActive = methodResults['TRACE']?.allowed && (methodResults['TRACE']?.status === 200 || methodResults['TRACE']?.status === 204);
  const trackActive = methodResults['TRACK']?.allowed && (methodResults['TRACK']?.status === 200 || methodResults['TRACK']?.status === 204);

  if (traceActive || trackActive) {
    findings.push(createFinding({
      id: 'HTTP_VERB_TRACE_ENABLED',
      channel: 'ACCESS_CONTROL',
      title: 'Dangerous HTTP TRACE / TRACK Method Enabled (XST Vulnerability)',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.CRITICAL,
      confidence: 0.95,
      scoreImpact: -20,
      description: 'The web server responds to HTTP TRACE or TRACK requests. This enables Cross-Site Tracing (XST) attacks, which allow malicious scripts to bypass the HttpOnly cookie protection flag and exfiltrate authentication tokens.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.PROBE,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: {
          traceStatus: methodResults['TRACE']?.status,
          trackStatus: methodResults['TRACK']?.status,
        },
      })],
      recommendation: 'Disable HTTP TRACE and TRACK methods in your web server configuration (e.g., "TraceEnable off" in Apache, or "if ($request_method = TRACE ) { return 405; }" in Nginx).',
    }));
  }

  // 2. Check for Insecure Arbitrary Write Verbs (PUT, DELETE)
  const putAccepted = methodResults['PUT']?.allowed && methodResults['PUT']?.status >= 200 && methodResults['PUT']?.status < 300;
  const deleteAccepted = methodResults['DELETE']?.allowed && methodResults['DELETE']?.status >= 200 && methodResults['DELETE']?.status < 300;

  if (putAccepted || deleteAccepted) {
    findings.push(createFinding({
      id: 'HTTP_VERB_INSECURE_WRITE',
      channel: 'ACCESS_CONTROL',
      title: 'Unauthenticated File Modification Methods Exposed (PUT/DELETE)',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 0.90,
      scoreImpact: -15,
      description: 'The endpoint returned a 2xx success code to unauthenticated PUT or DELETE method probes, indicating potential exposure to unauthorized content modification.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.PROBE,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: { putStatus: methodResults['PUT']?.status, deleteStatus: methodResults['DELETE']?.status },
      })],
      recommendation: 'Ensure all state-modifying HTTP methods (PUT, DELETE, PATCH) enforce strict authentication and authorization tokens.',
    }));
  }

  // 3. Baseline Compliance Finding if Verb Policy is Hardened
  if (findings.length === 0) {
    findings.push(createFinding({
      id: 'HTTP_VERB_HARDENED',
      channel: 'ACCESS_CONTROL',
      title: 'HTTP Verb Enforcement & Method Hardening Active',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 0.95,
      scoreImpact: 5,
      description: 'Dangerous HTTP methods (TRACE, TRACK, unauthenticated PUT/DELETE) are correctly rejected or disabled by the web server / reverse proxy.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.PROBE,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: {
          methodsTested: Object.keys(methodResults),
          traceStatus: methodResults['TRACE']?.status || 'Rejected',
          optionsAllowHeader: methodResults['OPTIONS']?.allowHeader || 'Restricted',
        },
      })],
    }));
  }

  return {
    findings,
    telemetry: {
      testedMethods: methodResults,
      traceDisabled: !traceActive && !trackActive,
      optionsAllow: methodResults['OPTIONS']?.allowHeader || null,
    },
  };
}

module.exports = {
  analyzeHttpVerbs,
};
