/**
 * HTTP Worker — WebVitals Modular Scan Engine
 *
 * Collects HTTP telemetry (status code, redirect hops, timings, headers)
 * and audits all HTTP security headers against modern AppSec standards.
 * Outputs standardized checks matching the Standard Result Schema.
 */

'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { createCheckResult } = require('../scan/checkSchema');
const { isRestrictedHost } = require('../middleware/abuseProtection');

/**
 * Executes HTTP telemetry and security header evaluations.
 *
 * @param {URL} targetUrlObj
 * @param {Object} [options={}]
 * @returns {Promise<{ checks: Object[], telemetry: Object }>}
 */
async function runHttpWorker(targetUrlObj, options = {}) {
  const startTime = Date.now();
  const maxRedirects = options.maxRedirects || 5;
  const timeoutMs = options.timeoutMs || 10000;

  const redirectChain = [];
  let currentUrl = targetUrlObj;
  let redirectsCount = 0;
  let responseHeaders = {};
  let statusCode = 200;
  let bodySnippet = '';
  let finalUrl = targetUrlObj.toString();

  while (redirectsCount <= maxRedirects) {
    if (isRestrictedHost(currentUrl.hostname)) {
      throw Object.assign(new Error(`SSRF blocked redirect target: ${currentUrl.hostname}`), { code: 'SSRF_BLOCKED' });
    }

    const stepStart = Date.now();
    const isHttps = currentUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const stepResult = await new Promise((resolve, reject) => {
      const req = client.get(
        currentUrl,
        {
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (WebVitals-Scanner/4.0)',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
          },
          timeout: timeoutMs,
          rejectUnauthorized: false,
        },
        (res) => {
          let buf = '';
          res.on('data', (chunk) => {
            if (buf.length < 512 * 1024) buf += chunk.toString('utf8');
          });
          res.on('end', () => {
            resolve({
              status: res.statusCode,
              headers: res.headers || {},
              body: buf,
              elapsed: Date.now() - stepStart,
            });
          });
        }
      );

      req.on('error', (err) => resolve({ status: null, headers: {}, body: '', error: err.message }));
      req.on('timeout', () => { req.destroy(); resolve({ status: null, headers: {}, body: '', error: 'Request timed out' }); });
    });

    redirectChain.push({
      url: currentUrl.toString(),
      status: stepResult.status,
      elapsedMs: stepResult.elapsed || 0,
    });

    if (stepResult.status >= 300 && stepResult.status < 400 && stepResult.headers.location) {
      redirectsCount++;
      try {
        currentUrl = new URL(stepResult.headers.location, currentUrl);
        finalUrl = currentUrl.toString();
        continue;
      } catch {
        break;
      }
    }

    statusCode = stepResult.status || 200;
    responseHeaders = stepResult.headers;
    bodySnippet = stepResult.body.slice(0, 4096);
    finalUrl = currentUrl.toString();
    break;
  }

  const durationMs = Date.now() - startTime;
  const isFinalHttps = finalUrl.startsWith('https://');
  const checks = [];

  // Helper for case-insensitive header lookup
  const getHeader = (name) => {
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(responseHeaders)) {
      if (k.toLowerCase() === lower) return Array.isArray(v) ? v.join(', ') : String(v);
    }
    return null;
  };

  const hsts = getHeader('Strict-Transport-Security');
  const csp = getHeader('Content-Security-Policy');
  const xfo = getHeader('X-Frame-Options');
  const xcto = getHeader('X-Content-Type-Options');
  const referrer = getHeader('Referrer-Policy');
  const permissions = getHeader('Permissions-Policy') || getHeader('Feature-Policy');
  const coop = getHeader('Cross-Origin-Opener-Policy');
  const coep = getHeader('Cross-Origin-Embedder-Policy');
  const corp = getHeader('Cross-Origin-Resource-Policy');
  const server = getHeader('Server');

  // Check 1: HTTPS & Redirect Hygiene
  if (isFinalHttps) {
    checks.push(createCheckResult({
      checkId: 'security.http.https',
      category: 'security',
      title: 'HTTPS Transport Enforcement',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Final endpoint securely serves encrypted traffic (${finalUrl})`,
      details: `Target was reached over encrypted transport after ${redirectChain.length - 1} redirect hop(s).`,
      evidence: { finalUrl, redirects: redirectChain },
      source: 'http-telemetry',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.http.https',
      category: 'security',
      title: 'HTTPS Transport Enforcement',
      status: 'finding',
      severity: 'critical',
      confidence: 1.0,
      summary: 'Endpoint serves unencrypted plaintext HTTP traffic',
      details: 'Traffic sent in plaintext can be intercepted, read, or modified by man-in-the-middle attackers.',
      evidence: { finalUrl },
      recommendation: 'Configure an immediate 301 redirect to force all traffic to HTTPS.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html'],
      source: 'http-telemetry',
      durationMs,
    }));
  }

  // Check 2: Strict-Transport-Security (HSTS)
  if (hsts) {
    const hasPreload = hsts.includes('preload');
    const hasSubdomains = hsts.includes('includeSubDomains');
    const maxAgeMatch = /max-age=(\d+)/i.exec(hsts);
    const maxAgeSecs = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    const isLongEnough = maxAgeSecs >= 15552000; // >= 180 days

    if (isLongEnough) {
      checks.push(createCheckResult({
        checkId: 'security.hsts',
        category: 'security',
        title: 'HTTP Strict Transport Security (HSTS)',
        status: 'pass',
        severity: 'none',
        confidence: 1.0,
        summary: `HSTS enforced with max-age=${maxAgeSecs}s${hasSubdomains ? ' (includeSubDomains)' : ''}${hasPreload ? ' (preload)' : ''}`,
        details: `Header: "${hsts}". Ensures browsers automatically upgrade all future requests to HTTPS, preventing SSL stripping.`,
        evidence: { headerValue: hsts, maxAgeSecs, hasSubdomains, hasPreload },
        source: 'http-header',
        durationMs,
      }));
    } else {
      checks.push(createCheckResult({
        checkId: 'security.hsts',
        category: 'security',
        title: 'HTTP Strict Transport Security (HSTS)',
        status: 'finding',
        severity: 'low',
        confidence: 1.0,
        summary: `HSTS max-age is short (${maxAgeSecs}s < 180 days recommended)`,
        details: `Header: "${hsts}". RFC 6797 suggests a duration of at least 15552000 seconds (6 months) for effective protection.`,
        evidence: { headerValue: hsts, maxAgeSecs },
        recommendation: 'Increase max-age to 31536000 (1 year) and consider adding includeSubDomains; preload.',
        references: ['https://datatracker.ietf.org/doc/html/rfc6797'],
        source: 'http-header',
        durationMs,
      }));
    }
  } else {
    checks.push(createCheckResult({
      checkId: 'security.hsts',
      category: 'security',
      title: 'HTTP Strict Transport Security (HSTS)',
      status: 'finding',
      severity: 'medium',
      confidence: 1.0,
      summary: 'Missing Strict-Transport-Security header',
      details: 'Clients connect without HSTS guidance, leaving the initial HTTP handshake vulnerable to downgrade attacks.',
      evidence: { headerValue: null },
      recommendation: 'Serve "Strict-Transport-Security: max-age=31536000; includeSubDomains".',
      references: ['https://datatracker.ietf.org/doc/html/rfc6797'],
      source: 'http-header',
      durationMs,
    }));
  }

  // Check 3: Content-Security-Policy (CSP)
  if (csp) {
    const hasUnsafeInline = csp.includes("'unsafe-inline'");
    const hasUnsafeEval = csp.includes("'unsafe-eval'");
    const hasWildcard = csp.includes(' *');

    if (hasUnsafeInline || hasUnsafeEval || hasWildcard) {
      checks.push(createCheckResult({
        checkId: 'security.csp',
        category: 'security',
        title: 'Content Security Policy (CSP)',
        status: 'finding',
        severity: 'medium',
        confidence: 1.0,
        summary: 'CSP active but contains permissive directives (unsafe-inline / unsafe-eval)',
        details: `Configured CSP: "${csp.slice(0, 120)}...". Directives like 'unsafe-inline' weaken defenses against Cross-Site Scripting (XSS).`,
        evidence: { csp, hasUnsafeInline, hasUnsafeEval, hasWildcard },
        recommendation: 'Migrate from unsafe-inline to cryptographic nonces or hashes for scripts and styles.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
        source: 'http-header',
        durationMs,
      }));
    } else {
      checks.push(createCheckResult({
        checkId: 'security.csp',
        category: 'security',
        title: 'Content Security Policy (CSP)',
        status: 'pass',
        severity: 'none',
        confidence: 1.0,
        summary: 'Strict Content-Security-Policy enforced',
        details: `Configured CSP: "${csp.slice(0, 100)}...". Restricts execution of unauthorized external scripts.`,
        evidence: { csp },
        source: 'http-header',
        durationMs,
      }));
    }
  } else {
    checks.push(createCheckResult({
      checkId: 'security.csp',
      category: 'security',
      title: 'Content Security Policy (CSP)',
      status: 'finding',
      severity: 'high',
      confidence: 1.0,
      summary: 'Missing Content-Security-Policy (CSP) header',
      details: 'Browsers will execute any script delivered on this origin, providing zero defense against injected XSS attacks.',
      evidence: { csp: null },
      recommendation: "Define a baseline CSP: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`.",
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
      source: 'http-header',
      durationMs,
    }));
  }

  // Check 4: X-Frame-Options (Clickjacking)
  if (xfo && (xfo.toUpperCase() === 'DENY' || xfo.toUpperCase() === 'SAMEORIGIN')) {
    checks.push(createCheckResult({
      checkId: 'security.xfo',
      category: 'security',
      title: 'Clickjacking Protection (X-Frame-Options)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `X-Frame-Options set to ${xfo.toUpperCase()}`,
      details: 'Prevents external third parties from embedding this page in hidden iframes (Clickjacking).',
      evidence: { headerValue: xfo },
      source: 'http-header',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.xfo',
      category: 'security',
      title: 'Clickjacking Protection (X-Frame-Options)',
      status: 'finding',
      severity: 'medium',
      confidence: 1.0,
      summary: 'Missing or invalid X-Frame-Options header',
      details: 'Without framing restrictions, malicious sites can embed this application inside an invisible frame to hijack user clicks.',
      evidence: { headerValue: xfo },
      recommendation: 'Add header "X-Frame-Options: SAMEORIGIN" or CSP frame-ancestors.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
      source: 'http-header',
      durationMs,
    }));
  }

  // Check 5: X-Content-Type-Options (MIME Sniffing)
  if (xcto && xcto.toLowerCase().includes('nosniff')) {
    checks.push(createCheckResult({
      checkId: 'security.xcto',
      category: 'security',
      title: 'MIME-Sniffing Prevention (X-Content-Type-Options)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: 'X-Content-Type-Options: nosniff enforced',
      details: 'Forces browsers to strictly honor the declared Content-Type, preventing executable MIME type confusion.',
      evidence: { headerValue: xcto },
      source: 'http-header',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.xcto',
      category: 'security',
      title: 'MIME-Sniffing Prevention (X-Content-Type-Options)',
      status: 'finding',
      severity: 'low',
      confidence: 1.0,
      summary: 'Missing X-Content-Type-Options: nosniff header',
      details: 'Allows browsers to sniff files away from the declared content-type, potentially executing text/plain as JavaScript.',
      evidence: { headerValue: xcto },
      recommendation: 'Set "X-Content-Type-Options: nosniff" on all responses.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
      source: 'http-header',
      durationMs,
    }));
  }

  // Check 6: Referrer-Policy
  if (referrer) {
    checks.push(createCheckResult({
      checkId: 'security.referrer',
      category: 'security',
      title: 'Referrer-Policy Privacy Directive',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Referrer-Policy configured: ${referrer}`,
      details: 'Prevents leakage of sensitive query strings and path names to external origins.',
      evidence: { headerValue: referrer },
      source: 'http-header',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.referrer',
      category: 'security',
      title: 'Referrer-Policy Privacy Directive',
      status: 'finding',
      severity: 'low',
      confidence: 1.0,
      summary: 'No Referrer-Policy published',
      details: 'Browsers default to sending the full origin on cross-origin navigation, potentially leaking internal URLs.',
      evidence: { headerValue: null },
      recommendation: 'Set "Referrer-Policy: strict-origin-when-cross-origin".',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
      source: 'http-header',
      durationMs,
    }));
  }

  // Check 7: Browser Isolation Policies (COOP, COEP, CORP)
  if (coop || coep || corp) {
    checks.push(createCheckResult({
      checkId: 'security.isolation',
      category: 'security',
      title: 'Cross-Origin Browser Isolation (COOP / COEP / CORP)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Cross-origin isolation configured (COOP: ${coop || 'None'}, COEP: ${coep || 'None'})`,
      details: 'Isolates browsing contexts and mitigates side-channel attacks such as Spectre.',
      evidence: { coop, coep, corp },
      source: 'http-header',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.isolation',
      category: 'security',
      title: 'Cross-Origin Browser Isolation (COOP / COEP / CORP)',
      status: 'info',
      severity: 'informational',
      confidence: 1.0,
      summary: 'Cross-Origin isolation headers not configured (COOP/COEP absent)',
      details: 'Recommended for applications processing high-security data to isolate web workers and memory contexts.',
      evidence: { coop: null, coep: null },
      recommendation: 'Consider setting "Cross-Origin-Opener-Policy: same-origin".',
      source: 'http-header',
      durationMs,
    }));
  }

  // Check 8: Information Disclosure in Server Header
  if (server && /[\d.]+/i.test(server)) {
    checks.push(createCheckResult({
      checkId: 'security.server_disclosure',
      category: 'security',
      title: 'Server Banner Version Disclosure',
      status: 'finding',
      severity: 'low',
      confidence: 1.0,
      summary: `Server banner discloses precise software version: ${server}`,
      details: 'Revealing specific version numbers aids attackers in profiling known CVE exploits.',
      evidence: { server },
      recommendation: 'Obfuscate or suppress version tokens in the Server HTTP response header.',
      source: 'http-header',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.server_disclosure',
      category: 'security',
      title: 'Server Banner Version Disclosure',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Server banner obfuscated (${server || 'Not Disclosed'})`,
      details: 'No granular software version numbers are advertised in response headers.',
      evidence: { server: server || 'None' },
      source: 'http-header',
      durationMs,
    }));
  }

  const telemetry = {
    statusCode,
    finalUrl,
    redirectChain,
    headers: responseHeaders,
    bodySnippet,
  };

  return { checks, telemetry };
}

module.exports = {
  runHttpWorker,
};
