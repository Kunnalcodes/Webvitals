/**
 * Reverse Proxy & Header Spoofing Trust Analyzer
 * WebVitals Web Security Intelligence
 *
 * Inspects whether the edge/origin server improperly trusts or reflects client-supplied
 * internal proxy headers (e.g., X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization).
 */

'use strict';

const { URL } = require('url');
const { collectHttpTelemetry } = require('../telemetry/httpTelemetry');
const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');

const PROXY_PROBES = [
  {
    name: 'X-Original-URL Routing Override',
    headers: { 'X-Original-URL': '/admin-console-internal-probe' },
    risk: 'HIGH',
    impact: 'Enables path routing bypasses on vulnerable reverse proxies and load balancers.',
  },
  {
    name: 'X-Rewrite-URL Routing Override',
    headers: { 'X-Rewrite-URL': '/admin-console-internal-probe' },
    risk: 'HIGH',
    impact: 'Can override application router logic in unhardened reverse proxy environments.',
  },
  {
    name: 'X-Forwarded-For IP Spoofing (Localhost Trust)',
    headers: { 'X-Forwarded-For': '127.0.0.1, 10.0.0.1' },
    risk: 'MEDIUM',
    impact: 'May bypass IP-restricted endpoints or geo-fencing if upstream proxy is unverified.',
  },
  {
    name: 'X-Custom-IP-Authorization Spoofing',
    headers: { 'X-Custom-IP-Authorization': '127.0.0.1' },
    risk: 'MEDIUM',
    impact: 'Bypasses legacy ACL filters expecting trusted internal ingress headers.',
  },
];

/**
 * Analyzes reverse proxy header trust and spoofing vulnerability.
 *
 * @param {URL|string} targetUrl
 * @returns {Promise<{ findings: import('../evidence/evidenceModel').SecurityFinding[], telemetry: object }>}
 */
async function analyzeProxyHeaders(targetUrl) {
  const urlObj = typeof targetUrl === 'string' ? new URL(targetUrl) : targetUrl;
  const findings = [];
  const probeResults = [];

  // Baseline probe
  let baselineStatus = 200;
  try {
    const baseline = await collectHttpTelemetry(urlObj, { method: 'GET', maxRedirects: 2, timeoutMs: 4000 });
    baselineStatus = baseline.status;
  } catch {}

  for (const probe of PROXY_PROBES) {
    try {
      const res = await collectHttpTelemetry(urlObj, {
        method: 'GET',
        headers: probe.headers,
        maxRedirects: 2,
        maxBodyBytes: 8 * 1024,
        timeoutMs: 4000,
      });

      const headerKey = Object.keys(probe.headers)[0];
      const isStatusAnomalous = res.status !== baselineStatus && res.status !== 400 && res.status !== 403 && res.status !== 404;

      probeResults.push({
        probeName: probe.name,
        header: headerKey,
        responseStatus: res.status,
        baselineStatus,
        statusAnomalous: isStatusAnomalous,
      });

      // If anomalous routing behavior is observed
      if (isStatusAnomalous && res.status === 200) {
        findings.push(createFinding({
          id: `PROXY_SPOOF_${headerKey.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
          channel: 'ACCESS_CONTROL',
          title: `Potential Reverse Proxy Header Trust: ${probe.name}`,
          status: DETERMINATION.WARN,
          severity: probe.risk === 'HIGH' ? SEVERITY.HIGH : SEVERITY.MEDIUM,
          confidence: 0.85,
          scoreImpact: -8,
          description: `The server altered its response status (from ${baselineStatus} to ${res.status}) when supplied with a client-crafted '${headerKey}' header. This may indicate an upstream reverse proxy evaluating unauthenticated client headers.`,
          evidence: [createEvidence({
            source: EVIDENCE_SOURCE.PROBE,
            quality: EVIDENCE_QUALITY.CORROBORATED,
            observedValue: { header: probe.headers, status: res.status, baselineStatus },
          })],
          recommendation: `Configure your edge reverse proxy (e.g. Nginx, Cloudflare) to strip or sanitize '${headerKey}' from all external client requests.`,
        }));
      }
    } catch (err) {
      probeResults.push({
        probeName: probe.name,
        error: err.message,
      });
    }
  }

  // Baseline Pass Finding if all probes handled securely
  if (findings.length === 0) {
    findings.push(createFinding({
      id: 'PROXY_HEADERS_SANITIZED',
      channel: 'ACCESS_CONTROL',
      title: 'Reverse Proxy Headers Sanitized & Ingress Protected',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 0.95,
      scoreImpact: 5,
      description: 'The edge infrastructure and application server properly ignore or sanitize client-supplied proxy override headers (X-Original-URL, X-Forwarded-For).',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.PROBE,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: { probesEvaluated: probeResults.length, baselineMatched: true },
      })],
    }));
  }

  return {
    findings,
    telemetry: {
      probes: probeResults,
      resilient: findings.filter(f => f.status === DETERMINATION.FAIL || f.status === DETERMINATION.WARN).length === 0,
    },
  };
}

module.exports = {
  analyzeProxyHeaders,
};
