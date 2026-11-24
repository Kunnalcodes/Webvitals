/**
 * HTTP Security Headers Analyzer — Phase 3 & 4
 * WebVitals
 *
 * Decomposes and analyzes security headers with normalized evidence:
 *   - HSTS (Strict-Transport-Security): max-age, includeSubDomains, preload
 *   - CSP (Content-Security-Policy): directives, unsafe-inline/eval, wildcard controls
 *   - Clickjacking: dual-correlation of X-Frame-Options and CSP frame-ancestors
 *   - MIME Sniffing: X-Content-Type-Options: nosniff
 *   - Referrer-Policy & Permissions-Policy
 *   - Cross-Origin Isolation: COOP, COEP, CORP
 *   - Server info disclosure: Server, X-Powered-By
 */

'use strict';

const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');

/**
 * Parses HSTS header value into components.
 */
function parseHsts(header) {
  if (!header || typeof header !== 'string') return null;
  const directives = header.split(';').map((d) => d.trim().toLowerCase());
  let maxAge = null;
  let includeSubDomains = false;
  let preload = false;

  for (const d of directives) {
    if (d.startsWith('max-age=')) {
      maxAge = parseInt(d.replace('max-age=', ''), 10);
    } else if (d === 'includesubdomains') {
      includeSubDomains = true;
    } else if (d === 'preload') {
      preload = true;
    }
  }

  return { raw: header, maxAge, includeSubDomains, preload };
}

/**
 * Parses CSP directives into map.
 */
function parseCsp(header) {
  if (!header || typeof header !== 'string') return null;
  const directives = {};
  const parts = header.split(';').map((d) => d.trim()).filter(Boolean);

  for (const part of parts) {
    const tokens = part.split(/\s+/);
    const dirName = tokens[0].toLowerCase();
    const dirValues = tokens.slice(1);
    directives[dirName] = dirValues;
  }

  const scriptSrc = directives['script-src'] || directives['default-src'] || [];
  const objectSrc = directives['object-src'] || directives['default-src'] || [];
  const frameAncestors = directives['frame-ancestors'] || [];

  const hasUnsafeInline = scriptSrc.includes("'unsafe-inline'");
  const hasUnsafeEval = scriptSrc.includes("'unsafe-eval'");
  const hasWildcardScript = scriptSrc.includes('*') || scriptSrc.includes('http:');
  const blocksObjects = objectSrc.includes("'none'") || (objectSrc.length === 0 && directives['default-src']?.includes("'none'"));

  return {
    raw: header,
    directives,
    scriptSrc,
    objectSrc,
    frameAncestors,
    hasUnsafeInline,
    hasUnsafeEval,
    hasWildcardScript,
    blocksObjects,
  };
}

/**
 * Analyzes HTTP security headers and produces standardized findings.
 *
 * @param {Record<string, string|string[]>} rawHeaders
 * @param {boolean} isHttps
 * @returns {import('../evidence/evidenceModel').SecurityFinding[]}
 */
function analyzeSecurityHeaders(rawHeaders = {}, isHttps = true) {
  const findings = [];
  const headers = {};
  for (const [k, v] of Object.entries(rawHeaders)) {
    headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }

  // ── 1. HSTS (Strict-Transport-Security) ────────────────────────────────────
  const hstsRaw = headers['strict-transport-security'];
  const hsts = parseHsts(hstsRaw);

  if (hsts && isHttps) {
    const hstsEvidence = createEvidence({
      source: EVIDENCE_SOURCE.HTTP,
      quality: EVIDENCE_QUALITY.DIRECT,
      observedValue: hsts.raw,
      normalizedValue: { maxAge: hsts.maxAge, includeSubDomains: hsts.includeSubDomains, preload: hsts.preload },
    });

    if (hsts.maxAge !== null && hsts.maxAge >= 31536000) {
      findings.push(createFinding({
        id: 'HSTS_STRONG',
        channel: 'HSTS',
        title: 'Strong HSTS Policy Configured (>= 1 year)',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 1.0,
        scoreImpact: 10,
        description: `HSTS is configured with max-age=${hsts.maxAge}s (${Math.round(hsts.maxAge / 86400)} days)${hsts.includeSubDomains ? ', includeSubDomains' : ''}${hsts.preload ? ', preload' : ''}.`,
        evidence: [hstsEvidence],
      }));
    } else if (hsts.maxAge !== null && hsts.maxAge > 0) {
      findings.push(createFinding({
        id: 'HSTS_SHORT_MAX_AGE',
        channel: 'HSTS',
        title: 'HSTS Configured With Short max-age',
        status: DETERMINATION.WARNING,
        severity: SEVERITY.LOW,
        confidence: 1.0,
        scoreImpact: 5,
        description: `HSTS max-age is set to ${hsts.maxAge} seconds (< 1 year). Browsers will only enforce HTTPS for a brief window.`,
        evidence: [hstsEvidence],
        recommendation: 'Increase Strict-Transport-Security max-age to at least 31536000 (1 year).',
      }));
    } else {
      findings.push(createFinding({
        id: 'HSTS_ZERO_MAX_AGE',
        channel: 'HSTS',
        title: 'HSTS max-age Is Set to 0 (Disabled)',
        status: DETERMINATION.FAIL,
        severity: SEVERITY.MEDIUM,
        confidence: 1.0,
        scoreImpact: -5,
        description: 'Strict-Transport-Security header has max-age=0, which deletes the domain from the browser\'s HSTS cache and disables enforcement.',
        evidence: [hstsEvidence],
        recommendation: 'Set max-age to 31536000.',
      }));
    }
  } else if (isHttps) {
    findings.push(createFinding({
      id: 'HSTS_MISSING',
      channel: 'HSTS',
      title: 'HTTP Strict Transport Security (HSTS) Missing',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 1.0,
      scoreImpact: -10,
      description: 'The Strict-Transport-Security response header is absent. Browsers may allow initial unencrypted HTTP connections susceptible to SSL stripping attacks.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.HTTP,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: null,
        notes: ['Header Strict-Transport-Security was not returned by server'],
      })],
      recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to all HTTPS responses.',
    }));
  }

  // ── 2. CSP (Content-Security-Policy) ──────────────────────────────────────
  const cspRaw = headers['content-security-policy'];
  const csp = parseCsp(cspRaw);

  if (csp) {
    const cspEvidence = createEvidence({
      source: EVIDENCE_SOURCE.HTTP,
      quality: EVIDENCE_QUALITY.DIRECT,
      observedValue: csp.raw,
      normalizedValue: {
        hasUnsafeInline: csp.hasUnsafeInline,
        hasUnsafeEval: csp.hasUnsafeEval,
        hasWildcardScript: csp.hasWildcardScript,
        blocksObjects: csp.blocksObjects,
      },
    });

    if (!csp.hasUnsafeInline && !csp.hasUnsafeEval && !csp.hasWildcardScript) {
      findings.push(createFinding({
        id: 'CSP_STRONG',
        channel: 'CSP',
        title: 'Strong Content Security Policy (CSP) Active',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 1.0,
        scoreImpact: 15,
        description: 'Content-Security-Policy enforces strict source directives without \'unsafe-inline\', \'unsafe-eval\', or wildcards.',
        evidence: [cspEvidence],
      }));
    } else {
      const weaknesses = [];
      if (csp.hasUnsafeInline) weaknesses.push("'unsafe-inline'");
      if (csp.hasUnsafeEval) weaknesses.push("'unsafe-eval'");
      if (csp.hasWildcardScript) weaknesses.push("wildcard source (*)");

      findings.push(createFinding({
        id: 'CSP_PERMISSIVE',
        channel: 'CSP',
        title: 'Content Security Policy Contains Permissive Directives',
        status: DETERMINATION.WARNING,
        severity: SEVERITY.MEDIUM,
        confidence: 0.95,
        scoreImpact: 5,
        description: `CSP header is present but permits unsafe script execution: ${weaknesses.join(', ')}.`,
        evidence: [cspEvidence],
        recommendation: 'Refactor inline scripts to use cryptographic nonces or hashes (e.g. \'nonce-...\' or \'sha256-...\') and remove \'unsafe-inline\'.',
        limitations: ['Evaluates browser security directives; does not prove exploitability of specific endpoints.'],
      }));
    }
  } else {
    findings.push(createFinding({
      id: 'CSP_MISSING',
      channel: 'CSP',
      title: 'Content Security Policy (CSP) Missing',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 1.0,
      scoreImpact: -15,
      description: 'The Content-Security-Policy response header is absent. Browsers have no restrictions on script execution or resource loading, increasing impact if an XSS flaw exists.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.HTTP,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: null,
        notes: ['Header Content-Security-Policy was not returned by server'],
      })],
      recommendation: 'Deploy a Content-Security-Policy starting with "default-src \'self\'; script-src \'self\'; object-src \'none\';".',
      limitations: ['Evaluates defense-in-depth controls; missing CSP does not mean the application is actively vulnerable to XSS.'],
    }));
  }

  // ── 3. Clickjacking Protection (X-Frame-Options + frame-ancestors) ────────
  const xfo = (headers['x-frame-options'] || '').toUpperCase();
  const frameAncestors = csp?.frameAncestors || [];
  const hasCspFrameAncestors = frameAncestors.length > 0;
  const isCspFrameProtected = frameAncestors.includes("'none'") || frameAncestors.includes("'self'");

  const clickjackEvidence = createEvidence({
    source: EVIDENCE_SOURCE.HTTP,
    quality: EVIDENCE_QUALITY.DIRECT,
    observedValue: { xFrameOptions: xfo || null, frameAncestors: frameAncestors.length > 0 ? frameAncestors : null },
  });

  if (xfo === 'DENY' || xfo === 'SAMEORIGIN' || isCspFrameProtected) {
    findings.push(createFinding({
      id: 'CLICKJACKING_PROTECTED',
      channel: 'CLICKJACKING',
      title: 'Clickjacking Protection Active',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 10,
      description: `Framing is restricted via ${isCspFrameProtected ? 'CSP frame-ancestors (' + frameAncestors.join(' ') + ')' : 'X-Frame-Options: ' + xfo}.`,
      evidence: [clickjackEvidence],
    }));
  } else {
    findings.push(createFinding({
      id: 'CLICKJACKING_UNPROTECTED',
      channel: 'CLICKJACKING',
      title: 'Clickjacking Protection Missing (No Framing Restrictions)',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.MEDIUM,
      confidence: 1.0,
      scoreImpact: -10,
      description: 'Neither X-Frame-Options nor CSP frame-ancestors is configured. The website can be rendered inside an <iframe> on third-party domains, enabling clickjacking attacks.',
      evidence: [clickjackEvidence],
      recommendation: 'Add "X-Frame-Options: DENY" or "Content-Security-Policy: frame-ancestors \'none\';" to prevent unauthorized iframe embedding.',
    }));
  }

  // ── 4. MIME Sniffing Defense (X-Content-Type-Options) ──────────────────────
  const xcto = (headers['x-content-type-options'] || '').toLowerCase();
  const xctoEvidence = createEvidence({
    source: EVIDENCE_SOURCE.HTTP,
    quality: EVIDENCE_QUALITY.DIRECT,
    observedValue: xcto || null,
  });

  if (xcto === 'nosniff') {
    findings.push(createFinding({
      id: 'MIME_SNIFFING_PROTECTED',
      channel: 'MIME',
      title: 'MIME-Type Sniffing Protection Enabled (nosniff)',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: 'X-Content-Type-Options is set to "nosniff", instructing browsers to strictly adhere to declared MIME types.',
      evidence: [xctoEvidence],
    }));
  } else {
    findings.push(createFinding({
      id: 'MIME_SNIFFING_UNPROTECTED',
      channel: 'MIME',
      title: 'X-Content-Type-Options Missing (MIME Sniffing Risk)',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.LOW,
      confidence: 1.0,
      scoreImpact: -5,
      description: 'The X-Content-Type-Options: nosniff header is missing. Browsers may override declared content types and execute executable files masquerading as images/text.',
      evidence: [xctoEvidence],
      recommendation: 'Add "X-Content-Type-Options: nosniff" to all HTTP responses.',
    }));
  }

  // ── 5. Referrer-Policy ───────────────────────────────────────────────────
  const refPolicy = (headers['referrer-policy'] || '').toLowerCase();
  const safePolicies = ['no-referrer', 'strict-origin-when-cross-origin', 'strict-origin', 'no-referrer-when-downgrade', 'same-origin'];

  if (refPolicy && safePolicies.some((p) => refPolicy.includes(p))) {
    findings.push(createFinding({
      id: 'REFERRER_POLICY_CONFIGURED',
      channel: 'PRIVACY',
      title: 'Referrer-Policy Configured',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: `Referrer-Policy is configured to "${refPolicy}", preventing URL path and sensitive query token leakage to third parties.`,
      evidence: [createEvidence({ source: EVIDENCE_SOURCE.HTTP, quality: EVIDENCE_QUALITY.DIRECT, observedValue: refPolicy })],
    }));
  } else {
    findings.push(createFinding({
      id: 'REFERRER_POLICY_MISSING',
      channel: 'PRIVACY',
      title: 'Referrer-Policy Header Missing',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 1.0,
      scoreImpact: -2,
      description: 'The Referrer-Policy header is absent. Browsers default to sending full referrer URLs across requests.',
      evidence: [createEvidence({ source: EVIDENCE_SOURCE.HTTP, quality: EVIDENCE_QUALITY.DIRECT, observedValue: null })],
      recommendation: 'Add "Referrer-Policy: strict-origin-when-cross-origin".',
    }));
  }

  // ── 6. Permissions-Policy ────────────────────────────────────────────────
  const permPolicy = headers['permissions-policy'];
  if (permPolicy) {
    findings.push(createFinding({
      id: 'PERMISSIONS_POLICY_CONFIGURED',
      channel: 'PRIVACY',
      title: 'Permissions-Policy (Feature-Policy) Configured',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: 'Permissions-Policy is declared to restrict sensitive browser APIs (e.g. camera, microphone, geolocation).',
      evidence: [createEvidence({ source: EVIDENCE_SOURCE.HTTP, quality: EVIDENCE_QUALITY.DIRECT, observedValue: permPolicy })],
    }));
  } else {
    findings.push(createFinding({
      id: 'PERMISSIONS_POLICY_MISSING',
      channel: 'PRIVACY',
      title: 'Permissions-Policy Header Missing',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 1.0,
      scoreImpact: -1,
      description: 'No Permissions-Policy header found. Browser features like microphone and geolocation are not explicitly restricted.',
      evidence: [createEvidence({ source: EVIDENCE_SOURCE.HTTP, quality: EVIDENCE_QUALITY.DIRECT, observedValue: null })],
      recommendation: 'Consider adding "Permissions-Policy: camera=(), microphone=(), geolocation=()".',
    }));
  }

  // ── 7. Cross-Origin Opener Policy (COOP) ──────────────────────────────────
  const coop = (headers['cross-origin-opener-policy'] || '').toLowerCase();
  if (coop.includes('same-origin')) {
    findings.push(createFinding({
      id: 'COOP_CONFIGURED',
      channel: 'ISOLATION',
      title: 'Cross-Origin-Opener-Policy (COOP) Enforced',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: `COOP is set to "${coop}", isolating the browsing context from cross-origin popups and protecting against XS-Leaks/Spectre attacks.`,
      evidence: [createEvidence({ source: EVIDENCE_SOURCE.HTTP, quality: EVIDENCE_QUALITY.DIRECT, observedValue: coop })],
    }));
  } else {
    findings.push(createFinding({
      id: 'COOP_MISSING',
      channel: 'ISOLATION',
      title: 'Cross-Origin-Opener-Policy (COOP) Missing',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 1.0,
      scoreImpact: 0,
      description: 'Cross-Origin-Opener-Policy header is not configured. Cross-origin documents opened in the same browsing context group can retain window references.',
      evidence: [createEvidence({ source: EVIDENCE_SOURCE.HTTP, quality: EVIDENCE_QUALITY.DIRECT, observedValue: null })],
      recommendation: 'Add "Cross-Origin-Opener-Policy: same-origin" to isolate your application process and mitigate side-channel leakage.',
    }));
  }

  // ── 8. Cross-Origin Embedder Policy (COEP) ────────────────────────────────
  const coep = (headers['cross-origin-embedder-policy'] || '').toLowerCase();
  if (coep.includes('require-corp') || coep.includes('credentialless')) {
    findings.push(createFinding({
      id: 'COEP_CONFIGURED',
      channel: 'ISOLATION',
      title: 'Cross-Origin-Embedder-Policy (COEP) Enforced',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: `COEP is set to "${coep}", preventing the document from loading cross-origin resources without explicit permission.`,
      evidence: [createEvidence({ source: EVIDENCE_SOURCE.HTTP, quality: EVIDENCE_QUALITY.DIRECT, observedValue: coep })],
    }));
  }

  // ── 9. Server Information Disclosure ─────────────────────────────────────
  const server = headers['server'];
  const poweredBy = headers['x-powered-by'];
  if (server || poweredBy) {
    const leaked = [];
    if (server) leaked.push(`Server: ${server}`);
    if (poweredBy) leaked.push(`X-Powered-By: ${poweredBy}`);

    findings.push(createFinding({
      id: 'SERVER_HEADER_DISCLOSURE',
      channel: 'INFO_DISCLOSURE',
      title: 'Server Software Fingerprint Disclosed in Headers',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 1.0,
      scoreImpact: -2,
      description: `The web server discloses internal software information in HTTP response headers: ${leaked.join(', ')}.`,
      evidence: [createEvidence({ source: EVIDENCE_SOURCE.HTTP, quality: EVIDENCE_QUALITY.DIRECT, observedValue: { server, poweredBy } })],
      recommendation: 'Configure your web server to suppress or obscure the Server and X-Powered-By response headers.',
    }));
  }

  return findings;
}

module.exports = {
  analyzeSecurityHeaders,
  parseHsts,
  parseCsp,
};
