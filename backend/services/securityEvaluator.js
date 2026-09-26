/**
 * Security Evaluator & Scoring Engine — Phase 1
 * WebVitals
 *
 * Fixes P1-3: Proper weighted scoring formula.
 * Fixes P1-6: Full structured findings model with severity + evidence.
 *
 * Score formula:
 *   score = clamp( sum(earned_i * weight_i) / sum(weight_i) * 100, 0, 100 )
 *
 * Every channel produces a Finding with:
 *   id, channel, title, severity, status, score, maxScore,
 *   description, impact, evidence{}, recommendation, references[]
 */

'use strict';

// ─── Severity constants ───────────────────────────────────────────────────────
const SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };
const STATUS   = { PASS: 'PASS', WARN: 'WARN', FAIL: 'FAIL', NOT_EVALUATED: 'NOT_EVALUATED' };

// ─── Channel definitions ──────────────────────────────────────────────────────
// weight: relative importance (summed and used as denominator in weighted average)
const CHANNEL_WEIGHTS = {
  https:     10,
  tls:       10,
  hsts:      10,
  csp:       10,
  xfo:       8,
  xcto:      5,
  xss:       10,
  privacy:   5,
  cookies:   10,
  cors:      8,
  dns:       10,
  phishing:  10,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseCsp(cspHeader) {
  if (!cspHeader) return {};
  const directives = {};
  for (const part of cspHeader.split(';')) {
    const tokens = part.trim().split(/\s+/);
    if (tokens.length === 0 || !tokens[0]) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  return directives;
}

function clamp(val, min, max) {
  if (!Number.isFinite(val)) return min;
  return Math.max(min, Math.min(max, val));
}

function makeFinding(opts) {
  return {
    id:             opts.id,
    channel:        opts.channel,
    title:          opts.title,
    severity:       opts.severity,
    status:         opts.status,
    score:          opts.score,        // earned points for this channel (0–weight)
    maxScore:       opts.maxScore,     // maximum possible for this channel
    weight:         opts.weight,
    description:    opts.description,
    impact:         opts.impact || null,
    evidence:       opts.evidence || {},
    recommendation: opts.recommendation || null,
    references:     opts.references || [],
  };
}

// ─── Channel Evaluators ───────────────────────────────────────────────────────

function evalHttps({ scanResult }) {
  const usesHttps = scanResult.finalUrl?.protocol === 'https:';
  const tlsError  = scanResult.tlsError;
  const w = CHANNEL_WEIGHTS.https;

  if (tlsError) {
    return makeFinding({
      id: 'https', channel: 'HTTPS', title: 'HTTPS connection failed',
      severity: SEVERITY.HIGH, status: STATUS.WARN,
      score: Math.round(w * 0.3), maxScore: w, weight: w,
      description: 'The site uses HTTPS but the TLS handshake encountered an error.',
      impact: 'Users may see browser security warnings. Traffic may be partially encrypted.',
      evidence: { protocol: 'https:', tlsError },
      recommendation: 'Resolve the TLS certificate error. Check certificate validity and hostname match.',
      references: ['https://developer.mozilla.org/en-US/docs/Glossary/HTTPS'],
    });
  }

  if (usesHttps) {
    return makeFinding({
      id: 'https', channel: 'HTTPS', title: 'HTTPS is enabled',
      severity: SEVERITY.INFO, status: STATUS.PASS,
      score: w, maxScore: w, weight: w,
      description: 'The site is served over HTTPS, encrypting traffic between the browser and server.',
      evidence: { protocol: 'https:', finalUrl: scanResult.finalUrl?.toString() },
      recommendation: null,
      references: ['https://developer.mozilla.org/en-US/docs/Glossary/HTTPS'],
    });
  }

  return makeFinding({
    id: 'https', channel: 'HTTPS', title: 'HTTPS not used',
    severity: SEVERITY.HIGH, status: STATUS.FAIL,
    score: 0, maxScore: w, weight: w,
    description: 'The site is served over plain HTTP. All traffic is unencrypted and can be intercepted.',
    impact: 'Credentials, session tokens, and sensitive data transmitted over HTTP are visible to network observers.',
    evidence: { protocol: scanResult.finalUrl?.protocol || 'http:', finalUrl: scanResult.finalUrl?.toString() },
    recommendation: 'Enable HTTPS with a valid TLS certificate. Redirect all HTTP requests to HTTPS.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Glossary/HTTPS',
      'https://letsencrypt.org/',
    ],
  });
}

function evalTls({ scanResult, certInfo }) {
  const w = CHANNEL_WEIGHTS.tls;
  const isHttps = scanResult.finalUrl?.protocol === 'https:';

  if (!isHttps) {
    return makeFinding({
      id: 'tls', channel: 'TLS', title: 'TLS not applicable — site not served over HTTPS',
      severity: SEVERITY.INFO, status: STATUS.NOT_EVALUATED,
      score: 0, maxScore: w, weight: w,
      description: 'TLS certificate analysis requires HTTPS. The site does not use HTTPS.',
      evidence: {},
      recommendation: 'Enable HTTPS first.',
      references: [],
    });
  }

  if (!certInfo) {
    return makeFinding({
      id: 'tls', channel: 'TLS', title: 'TLS certificate could not be retrieved',
      severity: SEVERITY.MEDIUM, status: STATUS.WARN,
      score: Math.round(w * 0.4), maxScore: w, weight: w,
      description: 'The TLS certificate could not be inspected. The server may have a non-standard TLS configuration.',
      evidence: { tlsError: scanResult.tlsError || 'Could not connect via TLS' },
      recommendation: 'Verify your TLS certificate is correctly installed and the server supports standard TLS negotiation.',
      references: ['https://developer.mozilla.org/en-US/docs/Glossary/TLS'],
    });
  }

  const now = Date.now();
  const validTo = new Date(certInfo.validTo).getTime();
  const daysLeft = Number.isNaN(validTo) ? null : Math.round((validTo - now) / 86_400_000);

  if (!certInfo.authorized) {
    return makeFinding({
      id: 'tls', channel: 'TLS', title: 'TLS certificate is not trusted',
      severity: SEVERITY.HIGH, status: STATUS.FAIL,
      score: 0, maxScore: w, weight: w,
      description: `The certificate is not trusted by standard certificate authorities: ${certInfo.authError || 'unknown error'}.`,
      impact: 'Browsers will show a security warning. Connections may be susceptible to man-in-the-middle attacks.',
      evidence: {
        authorized: false, authError: certInfo.authError,
        issuer: certInfo.issuer, validFrom: certInfo.validFrom, validTo: certInfo.validTo,
        tlsVersion: certInfo.tlsVersion,
      },
      recommendation: 'Install a certificate from a trusted CA (e.g. Let\'s Encrypt). Verify hostname matches the certificate subject.',
      references: ['https://developer.mozilla.org/en-US/docs/Glossary/TLS'],
    });
  }

  if (daysLeft !== null && daysLeft < 0) {
    return makeFinding({
      id: 'tls', channel: 'TLS', title: 'TLS certificate has expired',
      severity: SEVERITY.HIGH, status: STATUS.FAIL,
      score: 0, maxScore: w, weight: w,
      description: `The certificate expired on ${certInfo.validTo}.`,
      impact: 'Browsers will show a security error. Users cannot safely visit the site.',
      evidence: { authorized: certInfo.authorized, validTo: certInfo.validTo, daysLeft, issuer: certInfo.issuer },
      recommendation: 'Renew the TLS certificate immediately.',
      references: [],
    });
  }

  if (daysLeft !== null && daysLeft < 30) {
    return makeFinding({
      id: 'tls', channel: 'TLS', title: `TLS certificate expires in ${daysLeft} days`,
      severity: SEVERITY.MEDIUM, status: STATUS.WARN,
      score: Math.round(w * 0.6), maxScore: w, weight: w,
      description: `The certificate is valid but will expire soon (${daysLeft} days remaining).`,
      evidence: { authorized: true, validTo: certInfo.validTo, daysLeft, issuer: certInfo.issuer, tlsVersion: certInfo.tlsVersion },
      recommendation: 'Renew the certificate before it expires to avoid service interruption.',
      references: [],
    });
  }

  return makeFinding({
    id: 'tls', channel: 'TLS', title: 'TLS certificate is valid',
    severity: SEVERITY.INFO, status: STATUS.PASS,
    score: w, maxScore: w, weight: w,
    description: `Valid certificate issued by ${certInfo.issuer}. TLS: ${certInfo.tlsVersion}. Expires: ${certInfo.validTo}.`,
    evidence: {
      authorized: true, issuer: certInfo.issuer, subject: certInfo.subject,
      validFrom: certInfo.validFrom, validTo: certInfo.validTo,
      tlsVersion: certInfo.tlsVersion, daysLeft,
    },
    recommendation: null,
    references: [],
  });
}

function evalHsts({ scanResult }) {
  const hsts = scanResult.headers?.['strict-transport-security'];
  const w = CHANNEL_WEIGHTS.hsts;

  if (!hsts) {
    return makeFinding({
      id: 'hsts', channel: 'HSTS', title: 'Strict-Transport-Security header is missing',
      severity: SEVERITY.MEDIUM, status: STATUS.FAIL,
      score: 0, maxScore: w, weight: w,
      description: 'No Strict-Transport-Security (HSTS) header found. Browsers will not automatically upgrade future requests to HTTPS.',
      impact: 'Users who navigate to the HTTP version of the site will not be automatically upgraded to HTTPS, enabling SSL-stripping attacks.',
      evidence: { header: 'Strict-Transport-Security', value: null, observedAt: new Date().toISOString() },
      recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        'https://hstspreload.org/',
      ],
    });
  }

  const maxAgeMatch = /max-age=(\d+)/i.exec(hsts);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hasIncludeSubDomains = /includeSubDomains/i.test(hsts);
  const hasPreload = /preload/i.test(hsts);

  if (maxAge >= 31536000 && hasIncludeSubDomains) {
    return makeFinding({
      id: 'hsts', channel: 'HSTS', title: 'HSTS is properly configured',
      severity: SEVERITY.INFO, status: STATUS.PASS,
      score: w, maxScore: w, weight: w,
      description: 'HSTS is enabled with a strong max-age and includeSubDomains.',
      evidence: { header: 'Strict-Transport-Security', value: hsts, maxAge, includeSubDomains: hasIncludeSubDomains, preload: hasPreload, observedAt: new Date().toISOString() },
      recommendation: hasPreload ? null : 'Consider adding "preload" and submitting to the HSTS preload list.',
      references: ['https://hstspreload.org/'],
    });
  }

  if (maxAge >= 15_552_000) { // 180 days
    return makeFinding({
      id: 'hsts', channel: 'HSTS', title: 'HSTS is present but could be stronger',
      severity: SEVERITY.LOW, status: STATUS.WARN,
      score: Math.round(w * 0.7), maxScore: w, weight: w,
      description: `HSTS is enabled (max-age=${maxAge}) but missing includeSubDomains or has a short max-age.`,
      evidence: { header: 'Strict-Transport-Security', value: hsts, maxAge, includeSubDomains: hasIncludeSubDomains, preload: hasPreload },
      recommendation: 'Increase max-age to 31536000 (1 year) and add includeSubDomains.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
    });
  }

  return makeFinding({
    id: 'hsts', channel: 'HSTS', title: 'HSTS max-age is too short',
    severity: SEVERITY.MEDIUM, status: STATUS.WARN,
    score: Math.round(w * 0.3), maxScore: w, weight: w,
    description: `HSTS is present but max-age=${maxAge} is below the recommended 180 days (15552000 seconds).`,
    evidence: { header: 'Strict-Transport-Security', value: hsts, maxAge, includeSubDomains: hasIncludeSubDomains },
    recommendation: 'Increase max-age to at least 31536000 seconds and add includeSubDomains.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
  });
}

function evalCsp({ scanResult }) {
  const csp = scanResult.headers?.['content-security-policy'];
  const w = CHANNEL_WEIGHTS.csp;

  if (!csp) {
    return makeFinding({
      id: 'csp', channel: 'CSP', title: 'Content-Security-Policy header is missing',
      severity: SEVERITY.HIGH, status: STATUS.FAIL,
      score: 0, maxScore: w, weight: w,
      description: 'No Content-Security-Policy header found. There is no defense-in-depth against injected scripts, frames, or resources.',
      impact: 'XSS attacks that inject script tags may execute without restriction.',
      evidence: { header: 'Content-Security-Policy', value: null, observedAt: new Date().toISOString() },
      recommendation: "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'",
      references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
        'https://csp.withgoogle.com/docs/index.html',
      ],
    });
  }

  const riskyPatterns = [];
  if (/unsafe-inline/i.test(csp))  riskyPatterns.push("'unsafe-inline'");
  if (/unsafe-eval/i.test(csp))    riskyPatterns.push("'unsafe-eval'");
  if (/\*/i.test(csp))             riskyPatterns.push('wildcard (*)');
  if (/data:/i.test(csp))          riskyPatterns.push("data: URI");

  if (riskyPatterns.length > 0) {
    return makeFinding({
      id: 'csp', channel: 'CSP', title: 'CSP is present but uses permissive directives',
      severity: SEVERITY.MEDIUM, status: STATUS.WARN,
      score: Math.round(w * 0.5), maxScore: w, weight: w,
      description: `Content-Security-Policy is present but contains directives that weaken its effectiveness: ${riskyPatterns.join(', ')}.`,
      impact: "Permissive CSP directives (e.g. 'unsafe-inline') allow script injection even with CSP enabled.",
      evidence: {
        header: 'Content-Security-Policy',
        value: csp.slice(0, 500),
        riskyPatterns,
        observedAt: new Date().toISOString(),
      },
      recommendation: "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for legitimate inline scripts.",
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'],
    });
  }

  return makeFinding({
    id: 'csp', channel: 'CSP', title: 'Content-Security-Policy is well-configured',
    severity: SEVERITY.INFO, status: STATUS.PASS,
    score: w, maxScore: w, weight: w,
    description: 'A restrictive CSP is in place with no detected unsafe directives.',
    evidence: { header: 'Content-Security-Policy', value: csp.slice(0, 500), observedAt: new Date().toISOString() },
    recommendation: null,
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
  });
}

function evalClickjacking({ scanResult }) {
  const csp = scanResult.headers?.['content-security-policy'];
  const xfo = scanResult.headers?.['x-frame-options'];
  const w   = CHANNEL_WEIGHTS.xfo;
  const cspDirectives = parseCsp(csp);
  const frameAncestors = cspDirectives['frame-ancestors'];

  if (frameAncestors) {
    const val = frameAncestors.join(' ').toLowerCase();
    if (val.includes("'none'") || val === 'none') {
      return makeFinding({
        id: 'xfo', channel: 'Clickjacking', title: 'Clickjacking protection via CSP frame-ancestors: none',
        severity: SEVERITY.INFO, status: STATUS.PASS,
        score: w, maxScore: w, weight: w,
        description: "CSP frame-ancestors 'none' prevents the page from being embedded in any iframe.",
        evidence: { header: 'Content-Security-Policy', directive: 'frame-ancestors', value: frameAncestors.join(' '), observedAt: new Date().toISOString() },
        recommendation: null,
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'],
      });
    }
    return makeFinding({
      id: 'xfo', channel: 'Clickjacking', title: 'CSP frame-ancestors allows some framing',
      severity: SEVERITY.LOW, status: STATUS.WARN,
      score: Math.round(w * 0.7), maxScore: w, weight: w,
      description: `CSP frame-ancestors is configured but allows framing from: ${frameAncestors.join(' ')}.`,
      evidence: { header: 'Content-Security-Policy', directive: 'frame-ancestors', value: frameAncestors.join(' ') },
      recommendation: "Use frame-ancestors 'none' for full clickjacking protection unless embedding is intentional.",
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'],
    });
  }

  if (xfo) {
    const v = xfo.toUpperCase().trim();
    if (v === 'DENY') {
      return makeFinding({
        id: 'xfo', channel: 'Clickjacking', title: 'Clickjacking protection via X-Frame-Options: DENY',
        severity: SEVERITY.INFO, status: STATUS.PASS,
        score: w, maxScore: w, weight: w,
        description: 'X-Frame-Options: DENY prevents the page from being embedded in any iframe.',
        evidence: { header: 'X-Frame-Options', value: xfo, observedAt: new Date().toISOString() },
        recommendation: null,
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
      });
    }
    if (v === 'SAMEORIGIN') {
      return makeFinding({
        id: 'xfo', channel: 'Clickjacking', title: 'X-Frame-Options: SAMEORIGIN — cross-origin framing blocked',
        severity: SEVERITY.LOW, status: STATUS.WARN,
        score: Math.round(w * 0.7), maxScore: w, weight: w,
        description: 'X-Frame-Options: SAMEORIGIN prevents cross-origin framing but allows same-origin framing.',
        evidence: { header: 'X-Frame-Options', value: xfo },
        recommendation: "Use X-Frame-Options: DENY or CSP frame-ancestors 'none' for the strongest protection.",
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
      });
    }
    return makeFinding({
      id: 'xfo', channel: 'Clickjacking', title: `X-Frame-Options has non-standard value: ${xfo}`,
      severity: SEVERITY.MEDIUM, status: STATUS.WARN,
      score: Math.round(w * 0.4), maxScore: w, weight: w,
      description: `X-Frame-Options is set to "${xfo}" which is not a standard value.`,
      evidence: { header: 'X-Frame-Options', value: xfo },
      recommendation: "Use X-Frame-Options: DENY.",
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
    });
  }

  return makeFinding({
    id: 'xfo', channel: 'Clickjacking', title: 'No clickjacking protection detected',
    severity: SEVERITY.HIGH, status: STATUS.FAIL,
    score: 0, maxScore: w, weight: w,
    description: 'Neither X-Frame-Options nor CSP frame-ancestors is present. The page can be embedded in an iframe on any site.',
    impact: 'Clickjacking attacks can trick users into performing unintended actions by overlaying the page in a hidden iframe.',
    evidence: { headerXFO: null, headerCSPFrameAncestors: null, observedAt: new Date().toISOString() },
    recommendation: "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
      'https://owasp.org/www-community/attacks/Clickjacking',
    ],
  });
}

function evalMimeSniffing({ scanResult }) {
  const xcto = scanResult.headers?.['x-content-type-options'];
  const w    = CHANNEL_WEIGHTS.xcto;
  const ok   = xcto?.toLowerCase().includes('nosniff');

  if (ok) {
    return makeFinding({
      id: 'xcto', channel: 'MIME Sniffing', title: 'X-Content-Type-Options: nosniff is set',
      severity: SEVERITY.INFO, status: STATUS.PASS,
      score: w, maxScore: w, weight: w,
      description: 'The browser is instructed not to MIME-type sniff responses.',
      evidence: { header: 'X-Content-Type-Options', value: xcto, observedAt: new Date().toISOString() },
      recommendation: null,
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
    });
  }

  return makeFinding({
    id: 'xcto', channel: 'MIME Sniffing', title: 'X-Content-Type-Options header is missing',
    severity: SEVERITY.LOW, status: STATUS.FAIL,
    score: 0, maxScore: w, weight: w,
    description: xcto
      ? `X-Content-Type-Options is set to "${xcto}" but does not include "nosniff".`
      : 'X-Content-Type-Options header is not present.',
    impact: 'Browsers may interpret files as a different MIME type, enabling MIME-type confusion attacks.',
    evidence: { header: 'X-Content-Type-Options', value: xcto || null, observedAt: new Date().toISOString() },
    recommendation: "Add the header: X-Content-Type-Options: nosniff",
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
  });
}

function evalXss({ scanResult }) {
  const csp = scanResult.headers?.['content-security-policy'];
  const xxp = scanResult.headers?.['x-xss-protection'];
  const w   = CHANNEL_WEIGHTS.xss;
  const cspDirectives = parseCsp(csp);
  const scriptSrc = cspDirectives['script-src'] || cspDirectives['default-src'];

  if (scriptSrc && !/unsafe-inline|\*/i.test(scriptSrc.join(' '))) {
    return makeFinding({
      id: 'xss', channel: 'XSS Defense', title: 'CSP restricts script execution',
      severity: SEVERITY.INFO, status: STATUS.PASS,
      score: w, maxScore: w, weight: w,
      description: `CSP script-src/default-src restricts script origins to: ${scriptSrc.join(' ')}.`,
      evidence: { header: 'Content-Security-Policy', directive: 'script-src', value: scriptSrc.join(' '), observedAt: new Date().toISOString() },
      recommendation: null,
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
    });
  }

  if (csp) {
    return makeFinding({
      id: 'xss', channel: 'XSS Defense', title: "CSP present but allows unsafe script execution",
      severity: SEVERITY.MEDIUM, status: STATUS.WARN,
      score: Math.round(w * 0.5), maxScore: w, weight: w,
      description: "CSP exists but the script-src directive allows 'unsafe-inline' or wildcard sources.",
      impact: "Injected inline scripts may execute despite CSP being present.",
      evidence: { header: 'Content-Security-Policy', scriptSrc: scriptSrc?.join(' ') || 'inherited from default-src', observedAt: new Date().toISOString() },
      recommendation: "Remove 'unsafe-inline' from script-src. Use nonces (script-src 'nonce-{random}') or hashes instead.",
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src'],
    });
  }

  if (xxp) {
    return makeFinding({
      id: 'xss', channel: 'XSS Defense', title: 'Legacy X-XSS-Protection detected (deprecated)',
      severity: SEVERITY.LOW, status: STATUS.WARN,
      score: Math.round(w * 0.3), maxScore: w, weight: w,
      description: `X-XSS-Protection: "${xxp}" is present but this header is deprecated and not a substitute for CSP.`,
      evidence: { header: 'X-XSS-Protection', value: xxp, observedAt: new Date().toISOString() },
      recommendation: "Implement a Content-Security-Policy with a restricted script-src instead.",
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'],
    });
  }

  return makeFinding({
    id: 'xss', channel: 'XSS Defense', title: 'No XSS mitigation detected',
    severity: SEVERITY.HIGH, status: STATUS.FAIL,
    score: 0, maxScore: w, weight: w,
    description: 'No Content-Security-Policy script-src restriction and no X-XSS-Protection header found.',
    impact: 'Reflected and stored XSS payloads may execute without any browser-level restriction.',
    evidence: { headerCSP: null, headerXXP: null, observedAt: new Date().toISOString() },
    recommendation: "Add a Content-Security-Policy with: script-src 'self' 'nonce-{random}'",
    references: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
    ],
  });
}

function evalPrivacy({ scanResult }) {
  const rp = scanResult.headers?.['referrer-policy'];
  const pp = scanResult.headers?.['permissions-policy'];
  const w  = CHANNEL_WEIGHTS.privacy;

  let earned = 0;
  if (rp && /no-referrer|strict-origin/i.test(rp)) earned += 3;
  else if (rp) earned += 1.5;
  if (pp) earned += 2;

  earned = Math.round(Math.min(earned, w));
  const status = earned >= w ? STATUS.PASS : earned > 0 ? STATUS.WARN : STATUS.FAIL;

  return makeFinding({
    id: 'privacy', channel: 'Privacy Headers', title: earned >= w
      ? 'Referrer-Policy and Permissions-Policy are configured'
      : 'Privacy headers are missing or weak',
    severity: earned === 0 ? SEVERITY.MEDIUM : earned < w ? SEVERITY.LOW : SEVERITY.INFO,
    status, score: earned, maxScore: w, weight: w,
    description: `Referrer-Policy: ${rp || 'missing'} | Permissions-Policy: ${pp ? 'present' : 'missing'}`,
    evidence: {
      'Referrer-Policy': rp || null,
      'Permissions-Policy': pp || null,
      observedAt: new Date().toISOString(),
    },
    recommendation: earned < w
      ? "Set Referrer-Policy: strict-origin-when-cross-origin and add a Permissions-Policy header."
      : null,
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
    ],
  });
}

function evalCookies({ cookieInfo }) {
  const w = CHANNEL_WEIGHTS.cookies;

  if (!cookieInfo || cookieInfo.totalCookies === 0) {
    return makeFinding({
      id: 'cookies', channel: 'Cookie Security', title: 'No cookies detected',
      severity: SEVERITY.INFO, status: STATUS.PASS,
      score: w, maxScore: w, weight: w,
      description: 'No cookies were set on the response. No cookie security issues to report.',
      evidence: { cookies: [], observedAt: new Date().toISOString() },
      recommendation: null,
      references: [],
    });
  }

  const score  = Math.round(clamp(cookieInfo.score || 0, 0, w));
  const status = score >= w ? STATUS.PASS : score >= Math.round(w * 0.5) ? STATUS.WARN : STATUS.FAIL;

  return makeFinding({
    id: 'cookies', channel: 'Cookie Security', title: cookieInfo.title || 'Cookie security issues detected',
    severity: status === STATUS.FAIL ? SEVERITY.HIGH : status === STATUS.WARN ? SEVERITY.MEDIUM : SEVERITY.INFO,
    status, score, maxScore: w, weight: w,
    description: cookieInfo.summary || `Analyzed ${cookieInfo.totalCookies} cookie(s).`,
    impact: status !== STATUS.PASS ? 'Improperly secured cookies can be stolen via XSS or transmitted over insecure connections.' : null,
    evidence: {
      cookies: cookieInfo.cookies || [],
      insecureFlags: cookieInfo.insecureFlags || [],
      observedAt: new Date().toISOString(),
    },
    recommendation: status !== STATUS.PASS
      ? 'Set Secure, HttpOnly, and SameSite=Strict on all session and authentication cookies.'
      : null,
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies',
      'https://owasp.org/www-community/controls/SecureCookieAttribute',
    ],
  });
}

function evalCors({ corsInfo }) {
  const w = CHANNEL_WEIGHTS.cors;

  if (!corsInfo) {
    return makeFinding({
      id: 'cors', channel: 'CORS', title: 'CORS headers not present',
      severity: SEVERITY.INFO, status: STATUS.PASS,
      score: w, maxScore: w, weight: w,
      description: 'No CORS headers detected. The server does not grant cross-origin access.',
      evidence: { observedAt: new Date().toISOString() },
      recommendation: null,
      references: [],
    });
  }

  const score  = Math.round(clamp(corsInfo.score || 0, 0, w));
  const status = score >= w ? STATUS.PASS : score >= Math.round(w * 0.5) ? STATUS.WARN : STATUS.FAIL;

  return makeFinding({
    id: 'cors', channel: 'CORS', title: corsInfo.title || 'CORS policy detected',
    severity: status === STATUS.FAIL ? SEVERITY.HIGH : status === STATUS.WARN ? SEVERITY.MEDIUM : SEVERITY.INFO,
    status, score, maxScore: w, weight: w,
    description: corsInfo.detail || 'CORS policy was analyzed.',
    impact: status !== STATUS.PASS ? 'Misconfigured CORS can allow unauthorized cross-origin access to sensitive data.' : null,
    evidence: {
      'Access-Control-Allow-Origin': corsInfo.acao || null,
      'Access-Control-Allow-Credentials': corsInfo.acac || null,
      issues: corsInfo.issues || [],
      observedAt: new Date().toISOString(),
    },
    recommendation: corsInfo.recommendation || null,
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
      'https://portswigger.net/web-security/cors',
    ],
  });
}

function evalDns({ dnsInfo }) {
  const w = CHANNEL_WEIGHTS.dns;

  if (!dnsInfo) {
    return makeFinding({
      id: 'dns', channel: 'DNS Security', title: 'DNS security records could not be resolved',
      severity: SEVERITY.MEDIUM, status: STATUS.NOT_EVALUATED,
      score: 0, maxScore: w, weight: w,
      description: 'SPF, DMARC, and CAA records could not be retrieved. This may indicate a DNS resolution failure.',
      evidence: { observedAt: new Date().toISOString() },
      recommendation: 'Ensure DNS is publicly resolvable and publish SPF, DMARC, and CAA records.',
      references: [],
    });
  }

  let earned = 0;
  if (dnsInfo.spf?.status  === STATUS.PASS) earned += 3.5;
  else if (dnsInfo.spf?.status === STATUS.WARN) earned += 2;
  if (dnsInfo.dmarc?.status === STATUS.PASS) earned += 4.5;
  else if (dnsInfo.dmarc?.status === STATUS.WARN) earned += 2.5;
  if (dnsInfo.caa?.status  === STATUS.PASS) earned += 2;

  earned = Math.round(Math.min(earned, w));
  const status = earned >= w * 0.8 ? STATUS.PASS : earned >= w * 0.4 ? STATUS.WARN : STATUS.FAIL;

  return makeFinding({
    id: 'dns', channel: 'DNS Security', title: status === STATUS.PASS
      ? 'DNS email security records are properly configured'
      : 'DNS email security records are missing or weak',
    severity: status === STATUS.FAIL ? SEVERITY.HIGH : status === STATUS.WARN ? SEVERITY.MEDIUM : SEVERITY.INFO,
    status, score: earned, maxScore: w, weight: w,
    description: `SPF: ${dnsInfo.spf?.status || 'FAIL'} | DMARC: ${dnsInfo.dmarc?.status || 'FAIL'} (policy: ${dnsInfo.dmarc?.policy || 'none'}) | CAA: ${dnsInfo.caa?.status || 'WARN'}`,
    impact: status !== STATUS.PASS ? 'Without SPF/DMARC, the domain can be spoofed to send phishing emails appearing to come from this domain.' : null,
    evidence: {
      spf:   { record: dnsInfo.spf?.record   || null, status: dnsInfo.spf?.status   || 'FAIL' },
      dmarc: { record: dnsInfo.dmarc?.record || null, status: dnsInfo.dmarc?.status || 'FAIL', policy: dnsInfo.dmarc?.policy || 'none' },
      caa:   { records: dnsInfo.caa?.records || [], status: dnsInfo.caa?.status || 'WARN' },
      observedAt: new Date().toISOString(),
    },
    recommendation: status !== STATUS.PASS
      ? 'Publish valid SPF (v=spf1 ... -all), DMARC (v=DMARC1; p=reject), and CAA records in DNS.'
      : null,
    references: [
      'https://dmarcian.com/what-is-spf/',
      'https://dmarc.org/',
      'https://datatracker.ietf.org/doc/html/rfc6844',
    ],
  });
}

function evalPhishing({ urlStructure }) {
  const w = CHANNEL_WEIGHTS.phishing;
  const { score: rawScore, flags } = urlStructure || { score: 10, flags: [] };
  const score  = Math.round(clamp(rawScore, 0, w));
  const status = score >= w * 0.8 ? STATUS.PASS : score >= w * 0.4 ? STATUS.WARN : STATUS.FAIL;

  return makeFinding({
    id: 'phishing', channel: 'Phishing Indicators', title: flags?.length
      ? `Suspicious URL patterns detected (${flags.length} indicator${flags.length > 1 ? 's' : ''})`
      : 'No suspicious URL patterns detected',
    severity: status === STATUS.FAIL ? SEVERITY.HIGH : status === STATUS.WARN ? SEVERITY.MEDIUM : SEVERITY.INFO,
    status, score, maxScore: w, weight: w,
    description: flags?.length
      ? `Heuristic analysis detected the following indicators: ${flags.join(' | ')}`
      : 'No IP-based hostnames, punycode, excessive subdomains, or suspicious keywords detected in URL.',
    impact: status !== STATUS.PASS
      ? 'These are HEURISTIC indicators only. Do not rely on this alone for phishing determination.'
      : null,
    evidence: {
      flags:    flags || [],
      type:     'HEURISTIC',
      observedAt: new Date().toISOString(),
    },
    recommendation: flags?.length
      ? 'Review the domain carefully. Verify it is the intended destination before entering credentials.'
      : null,
    references: [
      'https://developer.mozilla.org/en-US/docs/Glossary/Phishing',
    ],
  });
}

// ─── Main Entry ───────────────────────────────────────────────────────────────

/**
 * Evaluates all 12 security channels and returns the scored findings array.
 *
 * @param {{ scanResult, certInfo, urlStructure, cookieInfo, corsInfo, dnsInfo }} input
 * @returns {Finding[]}
 */
function evaluateChannels(input) {
  const evaluators = [
    () => evalHttps(input),
    () => evalTls(input),
    () => evalHsts(input),
    () => evalCsp(input),
    () => evalClickjacking(input),
    () => evalMimeSniffing(input),
    () => evalXss(input),
    () => evalPrivacy(input),
    () => evalCookies(input),
    () => evalCors(input),
    () => evalDns(input),
    () => evalPhishing(input),
  ];

  const findings = [];
  for (const fn of evaluators) {
    try {
      findings.push(fn());
    } catch (err) {
      // Defensive: one evaluator crashing should not destroy the entire scan
      console.error('[WebVitals] Channel evaluator error:', err.message);
    }
  }
  return findings;
}

/**
 * Computes the weighted overall security score from findings.
 * score = clamp( Σ(earned_i * weight_i) / Σ(weight_i) * 100, 0, 100 )
 *
 * @param {Finding[]} findings
 * @returns {number} integer 0–100
 */
function computeScore(findings) {
  if (!findings || findings.length === 0) return 0;

  const evaluatedFindings = findings.filter((f) => f.status !== STATUS.NOT_EVALUATED);
  if (evaluatedFindings.length === 0) return 0;

  const weightedSum  = evaluatedFindings.reduce((acc, f) => acc + (f.score  * f.weight), 0);
  const totalWeights = evaluatedFindings.reduce((acc, f) => acc + (f.maxScore * f.weight), 0);

  if (totalWeights === 0) return 0;

  const raw = (weightedSum / totalWeights) * 100;
  return Math.round(clamp(raw, 0, 100));
}

/**
 * Returns the letter grade and human-readable label for a score.
 */
function gradeFor(score) {
  if (score >= 90) return { grade: 'A', label: 'Excellent security posture' };
  if (score >= 80) return { grade: 'B', label: 'Good, with room to improve' };
  if (score >= 70) return { grade: 'C', label: 'Adequate — several gaps to close' };
  if (score >= 60) return { grade: 'D', label: 'Weak security configuration' };
  return { grade: 'F', label: 'Poor security posture' };
}

/**
 * Classifies the overall scan result.
 */
function classify(score, phishingScore) {
  if (phishingScore !== undefined && phishingScore <= 3) return 'High Risk';
  if (score >= 80) return 'Safe';
  if (score >= 50) return 'Needs Attention';
  return 'High Risk';
}

module.exports = {
  evaluateChannels,
  computeScore,
  gradeFor,
  classify,
  parseCsp,
  STATUS,
  SEVERITY,
  CHANNEL_WEIGHTS,
};
