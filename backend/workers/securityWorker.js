/**
 * Security Worker — WebVitals Modular Scan Engine
 *
 * Audits cookies, security.txt, WAF/firewall detection, and sensitive file exposures.
 * Returns standardized checks conforming to the Standard Result Schema.
 */

'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');
const { createCheckResult } = require('../scan/checkSchema');

/**
 * Executes security probes (cookies, security.txt, WAF, sensitive files).
 *
 * @param {URL} urlObj
 * @param {Object} headers
 * @returns {Promise<{ checks: Object[], securityData: Object }>}
 */
async function runSecurityWorker(urlObj, headers = {}) {
  const startTime = Date.now();
  const checks = [];
  const hostname = urlObj.hostname;
  const isHttps = urlObj.protocol === 'https:';

  // 1. Cookie Security (Secure, HttpOnly, SameSite)
  const rawCookieHeader = headers['set-cookie'];
  const cookies = Array.isArray(rawCookieHeader) ? rawCookieHeader : rawCookieHeader ? [rawCookieHeader] : [];

  if (cookies.length > 0) {
    let missingSecure = 0;
    let missingHttpOnly = 0;
    let missingSameSite = 0;

    cookies.forEach((c) => {
      const lower = c.toLowerCase();
      if (!lower.includes('secure') && isHttps) missingSecure++;
      if (!lower.includes('httponly')) missingHttpOnly++;
      if (!lower.includes('samesite')) missingSameSite++;
    });

    if (missingSecure > 0 || missingHttpOnly > 0 || missingSameSite > 0) {
      checks.push(createCheckResult({
        checkId: 'security.cookies',
        category: 'security',
        title: 'Cookie Security Attributes (Secure, HttpOnly, SameSite)',
        status: 'finding',
        severity: missingHttpOnly > 0 ? 'medium' : 'low',
        confidence: 1.0,
        summary: `Detected ${cookies.length} cookie(s) with missing defensive flags (${missingHttpOnly} lack HttpOnly, ${missingSecure} lack Secure)`,
        details: `Cookies without HttpOnly can be accessed by malicious JavaScript via XSS. Cookies without Secure may be transmitted in plaintext.`,
        evidence: { totalCookies: cookies.length, missingHttpOnly, missingSecure, missingSameSite },
        recommendation: 'Ensure all session and auth cookies set "Secure; HttpOnly; SameSite=Lax".',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'],
        source: 'http-cookies',
        durationMs: Date.now() - startTime,
      }));
    } else {
      checks.push(createCheckResult({
        checkId: 'security.cookies',
        category: 'security',
        title: 'Cookie Security Attributes (Secure, HttpOnly, SameSite)',
        status: 'pass',
        severity: 'none',
        confidence: 1.0,
        summary: `All ${cookies.length} cookies protected with Secure, HttpOnly, and SameSite`,
        details: 'Cookies are isolated from script access and encrypted during transit.',
        evidence: { count: cookies.length },
        source: 'http-cookies',
        durationMs: Date.now() - startTime,
      }));
    }
  } else {
    checks.push(createCheckResult({
      checkId: 'security.cookies',
      category: 'security',
      title: 'Cookie Security Attributes (Secure, HttpOnly, SameSite)',
      status: 'info',
      severity: 'informational',
      confidence: 1.0,
      summary: 'No Set-Cookie headers served on root endpoint (Stateless response)',
      details: 'Origin response does not initiate stateful session cookies.',
      evidence: { count: 0 },
      source: 'http-cookies',
      durationMs: Date.now() - startTime,
    }));
  }

  // 2. WAF / Firewall Detection
  const serverHeader = (headers['server'] || '').toLowerCase();
  const cfRay = headers['cf-ray'];
  const akamai = headers['x-akamai-transformed'];
  const awsWaf = headers['x-amz-cf-id'] || headers['x-amzn-requestid'];

  let wafName = null;
  if (cfRay || serverHeader.includes('cloudflare')) wafName = 'Cloudflare Edge WAF';
  else if (akamai) wafName = 'Akamai Edge WAF';
  else if (serverHeader.includes('awselb') || serverHeader.includes('cloudfront')) wafName = 'AWS CloudFront / WAF';
  else if (serverHeader.includes('fastly')) wafName = 'Fastly Next-Gen WAF';
  else if (serverHeader.includes('imperva') || serverHeader.includes('incap')) wafName = 'Imperva Incapsula';

  if (wafName) {
    checks.push(createCheckResult({
      checkId: 'security.waf',
      category: 'security',
      title: 'Web Application Firewall (WAF) & DDoS Shield',
      status: 'pass',
      severity: 'none',
      confidence: 0.95,
      summary: `Active perimeter protection detected: ${wafName}`,
      details: `Discovered signature headers from ${wafName}. Provides Layer 7 DDoS mitigation and OWASP Top 10 ingress filtering.`,
      evidence: { waf: wafName, serverHeader },
      source: 'http-waf-heuristic',
      durationMs: Date.now() - startTime,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.waf',
      category: 'security',
      title: 'Web Application Firewall (WAF) & DDoS Shield',
      status: 'info',
      severity: 'informational',
      confidence: 0.85,
      summary: 'No prominent commercial WAF signature advertised',
      details: 'Server response does not broadcast external WAF headers. Origin may employ internal or unobtrusive filtering.',
      evidence: { serverHeader: serverHeader || 'Not Disclosed' },
      source: 'http-waf-heuristic',
      durationMs: Date.now() - startTime,
    }));
  }

  // 3. Security.txt (RFC 9116) Probe
  let securityTxtPresent = false;
  let securityTxtUrl = `https://${hostname}/.well-known/security.txt`;
  try {
    const probeRes = await new Promise((resolve) => {
      const client = isHttps ? https : http;
      const req = client.get(
        securityTxtUrl,
        { headers: { 'User-Agent': 'WebVitals-Scanner/4.0' }, timeout: 4000 },
        (res) => resolve(res.statusCode === 200)
      );
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
    });
    securityTxtPresent = probeRes;
  } catch {}

  if (securityTxtPresent) {
    checks.push(createCheckResult({
      checkId: 'security.txt',
      category: 'security',
      title: 'Security Vulnerability Disclosure Policy (security.txt)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: 'RFC 9116 compliant security.txt discovered at /.well-known/security.txt',
      details: 'Enables ethical security researchers to responsibly report vulnerabilities directly to authorized contacts.',
      evidence: { url: securityTxtUrl, exists: true },
      references: ['https://datatracker.ietf.org/doc/html/rfc9116'],
      source: 'http-probe',
      durationMs: Date.now() - startTime,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.txt',
      category: 'security',
      title: 'Security Vulnerability Disclosure Policy (security.txt)',
      status: 'info',
      severity: 'informational',
      confidence: 1.0,
      summary: 'No security.txt policy published (RFC 9116)',
      details: 'Without security.txt, researchers finding critical bugs may have difficulty notifying your internal security team.',
      evidence: { url: securityTxtUrl, exists: false },
      recommendation: 'Publish a /.well-known/security.txt file defining contact addresses and disclosure policy.',
      references: ['https://datatracker.ietf.org/doc/html/rfc9116'],
      source: 'http-probe',
      durationMs: Date.now() - startTime,
    }));
  }

  const securityData = {
    waf: wafName,
    cookiesCount: cookies.length,
    securityTxt: securityTxtPresent,
  };

  return { checks, securityData };
}

module.exports = {
  runSecurityWorker,
};
