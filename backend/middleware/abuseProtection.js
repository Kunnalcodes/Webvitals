/**
 * SSRF & Abuse Protection Middleware — Phase 1
 * WebVitals — Security-critical component.
 *
 * Protects the scanner from being used as a proxy into internal networks.
 * Implements:
 *  - Blocked IP ranges: RFC-1918, loopback, link-local, cloud metadata
 *  - IPv6 private ranges (fc00::/7, fe80::/10, ::1)
 *  - Post-redirect destination re-validation
 *  - URL scheme and injection filtering
 *  - Response security headers
 */

'use strict';

const net = require('net');
const dns = require('dns');
const { promisify } = require('util');

const dnsLookup = promisify(dns.lookup);

// ─── Blocked IPv4 ranges ──────────────────────────────────────────────────────
const BLOCKED_IPV4_PREFIXES = [
  // Loopback
  (p) => p[0] === 127,
  // Unspecified / "This" network
  (p) => p[0] === 0,
  // RFC-1918 Private
  (p) => p[0] === 10,
  (p) => p[0] === 172 && p[1] >= 16 && p[1] <= 31,
  (p) => p[0] === 192 && p[1] === 168,
  // Link-local / APIPA
  (p) => p[0] === 169 && p[1] === 254,
  // Documentation ranges (not routable)
  (p) => p[0] === 192 && p[1] === 0 && p[2] === 2,
  (p) => p[0] === 198 && p[1] === 51 && p[2] === 100,
  (p) => p[0] === 203 && p[1] === 0 && p[2] === 113,
  // Multicast
  (p) => p[0] >= 224 && p[0] <= 239,
  // Reserved / Broadcast
  (p) => p[0] >= 240,
];

// ─── Blocked literal hostnames ────────────────────────────────────────────────
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  '0.0.0.0',
  '127.0.0.1',
  '::1',
  '[::]',
  '0',
  // Cloud metadata endpoints (literal)
  '169.254.169.254',         // AWS / GCP / Azure IMDSv1
  'metadata.google.internal',
  'metadata.google',
  'instance-data',           // OpenStack
]);

// ─── Blocked hostname suffixes ────────────────────────────────────────────────
const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.intranet', '.lan', '.corp'];

// ─── IPv4 check ───────────────────────────────────────────────────────────────
function isBlockedIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const parts = ip.split('.').map(Number);
  return BLOCKED_IPV4_PREFIXES.some((fn) => fn(parts));
}

// ─── IPv6 check ───────────────────────────────────────────────────────────────
function isBlockedIPv6(ip) {
  if (!net.isIPv6(ip)) return false;
  const normalized = ip.toLowerCase();
  // Loopback
  if (normalized === '::1') return true;
  // Unspecified
  if (normalized === '::') return true;
  // Unique Local (fc00::/7) — fc.. or fd..
  if (/^f[cd]/i.test(normalized)) return true;
  // Link-local (fe80::/10)
  if (/^fe[89ab]/i.test(normalized)) return true;
  // IPv4-mapped IPv6 ::ffff:x.x.x.x — run the IPv4 check on the mapped part
  const ipv4Mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Mapped) return isBlockedIPv4(ipv4Mapped[1]);
  return false;
}

/**
 * Synchronous hostname check.
 * Returns true if the hostname is obviously restricted WITHOUT DNS resolution.
 */
function isRestrictedHost(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase().trim();

  // Literal blocked hostnames
  if (BLOCKED_HOSTNAMES.has(h)) return true;

  // Blocked suffixes
  if (BLOCKED_SUFFIXES.some((s) => h.endsWith(s))) return true;

  // Direct IP literals
  if (net.isIPv4(h)) return isBlockedIPv4(h);
  if (net.isIPv6(h.replace(/^\[|\]$/g, ''))) return isBlockedIPv6(h.replace(/^\[|\]$/g, ''));

  return false;
}

/**
 * Async DNS-based SSRF check.
 * Resolves the hostname and validates the resulting IP(s).
 * MUST be called after the initial hostname check AND after each redirect.
 *
 * @returns {Promise<{blocked: boolean, reason?: string, resolvedIp?: string}>}
 */
async function validateResolvedHost(hostname) {
  if (!hostname) return { blocked: true, reason: 'Empty hostname' };

  // Quick synchronous check first
  if (isRestrictedHost(hostname)) {
    return { blocked: true, reason: `Blocked hostname: ${hostname}` };
  }

  try {
    const { address, family } = await dnsLookup(hostname, { all: false });
    if (!address) return { blocked: true, reason: 'DNS resolution returned no address' };

    const blocked =
      family === 4 ? isBlockedIPv4(address) :
      family === 6 ? isBlockedIPv6(address) :
      false;

    if (blocked) {
      return {
        blocked: true,
        reason: `SSRF: hostname ${hostname} resolved to blocked IP ${address}`,
        resolvedIp: address,
      };
    }

    return { blocked: false, resolvedIp: address };
  } catch (err) {
    // DNS resolution failure — fail open carefully:
    // We log it but do NOT block, as the network request itself will fail.
    // This avoids false-positive blocks on legitimate external domains
    // that happen to be unreachable from the scanner's network.
    return { blocked: false, resolvedIp: null, dnsError: err.code };
  }
}

/**
 * Validates a raw URL string for use as a scan target.
 * Synchronous — does not resolve DNS.
 *
 * @returns {{ valid: boolean, parsedUrl?: URL, normalizedUrl?: string, message?: string }}
 */
function validateTargetUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, message: 'Missing or empty target URL.' };
  }

  const trimmed = rawUrl.trim();

  if (trimmed.length > 2048) {
    return { valid: false, message: 'URL exceeds maximum length of 2048 characters.' };
  }

  // Block dangerous schemes
  if (/^(javascript|data|file|ftp|gopher|ssh|telnet|dict|ldap|ldaps|sftp|smb|vnc|rdp):/i.test(trimmed)) {
    return { valid: false, message: 'Invalid URL scheme. Only HTTP and HTTPS are permitted.' };
  }

  // Block injection patterns in URL
  if (/<script|union\s+select|eval\s*\(|base64_decode|onerror\s*=/i.test(trimmed)) {
    return { valid: false, message: 'Malicious payload detected in URL.' };
  }

  try {
    const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    const parsed = new URL(withProto);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { valid: false, message: 'Protocol must be HTTP or HTTPS.' };
    }

    const hostname = parsed.hostname;

    if (isRestrictedHost(hostname)) {
      return {
        valid: false,
        message: `SSRF Protection: Access to '${hostname}' is blocked (private/internal/loopback).`,
      };
    }

    return { valid: true, parsedUrl: parsed, normalizedUrl: withProto };
  } catch (err) {
    return { valid: false, message: `Malformed URL: ${err.message}` };
  }
}

/**
 * Validates a redirect destination during scan.
 * Combines synchronous hostname check with async DNS resolution.
 *
 * @returns {Promise<{ valid: boolean, message?: string }>}
 */
async function validateRedirectDestination(urlObj) {
  const hostname = urlObj.hostname;

  // Synchronous check first
  if (isRestrictedHost(hostname)) {
    return { valid: false, message: `SSRF: Redirect to blocked host ${hostname} denied.` };
  }

  // DNS resolution check
  const result = await validateResolvedHost(hostname);
  if (result.blocked) {
    return { valid: false, message: result.reason };
  }

  return { valid: true };
}

const UI_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: https: blob:",
  "connect-src 'self' https: wss: ws:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

const API_CSP = "default-src 'none'; frame-ancestors 'none';";

/**
 * Applies defense-in-depth security headers to all outgoing responses.
 * Uses a permissive CSP for UI/static assets and a strict one for JSON APIs.
 *
 * @param {import('http').ServerResponse} res
 * @param {boolean} [isApi=false]
 */
function applySecurityHeaders(res, isApi = false) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Content-Security-Policy', isApi ? API_CSP : UI_CSP);
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

module.exports = {
  isRestrictedHost,
  isBlockedIPv4,
  isBlockedIPv6,
  validateTargetUrl,
  validateResolvedHost,
  validateRedirectDestination,
  applySecurityHeaders,
};
