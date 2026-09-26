/**
 * Cookie Security Analyzer — Phase 3
 * WebVitals
 *
 * Inspects Set-Cookie directives with contextual classification:
 *   - Secure flag enforcement (HTTPS-only transmission)
 *   - HttpOnly flag (XSS session-hijacking defense)
 *   - SameSite attribute (CSRF mitigation: Strict, Lax, None)
 *   - Purpose inference (Session/Auth vs Analytics/Tracking vs Unknown)
 */

'use strict';

const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');

/**
 * Parses raw Set-Cookie header strings.
 * @param {string|string[]} rawCookies
 */
function parseSetCookieHeaders(rawCookies) {
  if (!rawCookies) return [];
  const list = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
  const cookies = [];

  for (const cookieStr of list) {
    if (!cookieStr || typeof cookieStr !== 'string') continue;
    const parts = cookieStr.split(';').map((p) => p.trim());
    if (parts.length === 0) continue;

    const firstEq = parts[0].indexOf('=');
    const name = firstEq > 0 ? parts[0].slice(0, firstEq).trim() : parts[0];
    const value = firstEq > 0 ? parts[0].slice(firstEq + 1).trim() : '';

    let secure = false;
    let httpOnly = false;
    let sameSite = null;
    let domain = null;
    let path = null;

    for (let i = 1; i < parts.length; i++) {
      const attr = parts[i];
      const lower = attr.toLowerCase();

      if (lower === 'secure') {
        secure = true;
      } else if (lower === 'httponly') {
        httpOnly = true;
      } else if (lower.startsWith('samesite=')) {
        sameSite = attr.slice(9).trim();
      } else if (lower.startsWith('domain=')) {
        domain = attr.slice(7).trim();
      } else if (lower.startsWith('path=')) {
        path = attr.slice(5).trim();
      }
    }

    // Heuristic purpose detection
    const nameLower = name.toLowerCase();
    let purpose = 'UNKNOWN';
    let isSession = false;

    if (/sess|session|auth|token|jwt|sid|phpsessid|jsessionid|asp\.net_sessionid/i.test(nameLower)) {
      purpose = 'AUTHENTICATION_SESSION';
      isSession = true;
    } else if (/_ga|_gid|_gat|utm_|amplitude|mixpanel|segment/i.test(nameLower)) {
      purpose = 'ANALYTICS_TRACKING';
    } else if (/theme|lang|pref|consent|cookie_notice/i.test(nameLower)) {
      purpose = 'PREFERENCE_CONSENT';
    }

    cookies.push({
      name,
      valueSnippet: value.length > 8 ? `${value.slice(0, 4)}••••` : '••••',
      secure,
      httpOnly,
      sameSite,
      domain,
      path,
      purpose,
      isSession,
      raw: cookieStr,
    });
  }

  return cookies;
}

/**
 * Analyzes Set-Cookie headers and produces standardized findings.
 *
 * @param {Record<string, string|string[]>} rawHeaders
 * @param {boolean} isHttps
 * @returns {import('../evidence/evidenceModel').SecurityFinding[]}
 */
function analyzeCookieSecurity(rawHeaders = {}, isHttps = true) {
  const findings = [];
  let cookieHeader = null;

  for (const [k, v] of Object.entries(rawHeaders)) {
    if (k.toLowerCase() === 'set-cookie') {
      cookieHeader = v;
      break;
    }
  }

  const cookies = parseSetCookieHeaders(cookieHeader);
  if (cookies.length === 0) {
    return findings; // No cookies set on response — neutral
  }

  const cookieEvidence = createEvidence({
    source: EVIDENCE_SOURCE.COOKIE,
    quality: EVIDENCE_QUALITY.DIRECT,
    observedValue: cookies.map((c) => ({
      name: c.name,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      purpose: c.purpose,
    })),
  });

  const missingHttpOnly = cookies.filter((c) => !c.httpOnly);
  const missingSecure = cookies.filter((c) => !c.secure);
  const missingSameSite = cookies.filter((c) => !c.sameSite || c.sameSite.toLowerCase() === 'none');

  const sessionMissingHttpOnly = missingHttpOnly.filter((c) => c.isSession);
  const sessionMissingSecure = missingSecure.filter((c) => c.isSession);

  // 1. HttpOnly Check
  if (sessionMissingHttpOnly.length > 0) {
    findings.push(createFinding({
      id: 'COOKIE_SESSION_HTTPONLY_MISSING',
      channel: 'COOKIES',
      title: 'Session / Authentication Cookie Missing HttpOnly Flag',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 0.95,
      scoreImpact: -8,
      description: `Authentication/Session cookie(s) [${sessionMissingHttpOnly.map((c) => c.name).join(', ')}] are created without the HttpOnly attribute. JavaScript can read these cookies, enabling session hijacking if an XSS vulnerability occurs.`,
      evidence: [cookieEvidence],
      recommendation: 'Add the HttpOnly flag to all session and authentication cookies.',
    }));
  } else if (missingHttpOnly.length > 0) {
    findings.push(createFinding({
      id: 'COOKIE_HTTPONLY_MISSING',
      channel: 'COOKIES',
      title: 'Cookies Missing HttpOnly Attribute',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 0.90,
      scoreImpact: -2,
      description: `Non-session cookie(s) [${missingHttpOnly.map((c) => c.name).join(', ')}] do not have the HttpOnly flag.`,
      evidence: [cookieEvidence],
      recommendation: 'Set the HttpOnly flag for all sensitive cookies.',
    }));
  } else {
    findings.push(createFinding({
      id: 'COOKIE_HTTPONLY_ENFORCED',
      channel: 'COOKIES',
      title: 'All Cookies Protected With HttpOnly Flag',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 4,
      description: 'All cookies set by the server include the HttpOnly attribute, blocking JavaScript access.',
      evidence: [cookieEvidence],
    }));
  }

  // 2. Secure Flag Check
  if (isHttps && sessionMissingSecure.length > 0) {
    findings.push(createFinding({
      id: 'COOKIE_SESSION_SECURE_MISSING',
      channel: 'COOKIES',
      title: 'Session Cookie Missing Secure Flag On HTTPS Site',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 1.0,
      scoreImpact: -8,
      description: `Session cookie(s) [${sessionMissingSecure.map((c) => c.name).join(', ')}] lack the Secure attribute. Browsers may transmit them over unencrypted plaintext HTTP connections.`,
      evidence: [cookieEvidence],
      recommendation: 'Add the Secure attribute to all cookies issued over HTTPS.',
    }));
  } else if (isHttps && missingSecure.length > 0) {
    findings.push(createFinding({
      id: 'COOKIE_SECURE_MISSING',
      channel: 'COOKIES',
      title: 'Cookies Missing Secure Attribute',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 1.0,
      scoreImpact: -2,
      description: `Cookie(s) [${missingSecure.map((c) => c.name).join(', ')}] are missing the Secure flag.`,
      evidence: [cookieEvidence],
      recommendation: 'Add the Secure attribute to all cookies on HTTPS websites.',
    }));
  } else if (isHttps) {
    findings.push(createFinding({
      id: 'COOKIE_SECURE_ENFORCED',
      channel: 'COOKIES',
      title: 'All Cookies Protected With Secure Attribute',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 3,
      description: 'All cookies include the Secure attribute, ensuring they are only transmitted over encrypted TLS channels.',
      evidence: [cookieEvidence],
    }));
  }

  // 3. SameSite Flag Check
  if (missingSameSite.length > 0) {
    findings.push(createFinding({
      id: 'COOKIE_SAMESITE_MISSING',
      channel: 'COOKIES',
      title: 'Cookies Missing Strict/Lax SameSite CSRF Protection',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 0.95,
      scoreImpact: -2,
      description: `Cookie(s) [${missingSameSite.map((c) => c.name).join(', ')}] do not specify SameSite=Lax or SameSite=Strict.`,
      evidence: [cookieEvidence],
      recommendation: 'Configure "SameSite=Lax" (or SameSite=Strict) to mitigate cross-site request forgery risks.',
    }));
  }

  return findings;
}

module.exports = {
  analyzeCookieSecurity,
  parseSetCookieHeaders,
};
