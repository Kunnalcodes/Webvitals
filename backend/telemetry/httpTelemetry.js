/**
 * Centralized HTTP Telemetry Collector — Phase 3
 * WebVitals
 *
 * Safe, bounded HTTP/HTTPS telemetry collector with:
 *   - Strict per-hop SSRF validation on redirects
 *   - Max response size limits (prevents memory bomb attacks)
 *   - Configurable network timeouts
 *   - Case-normalized headers
 *   - Response hashing
 */

'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { validateResolvedHost } = require('../middleware/abuseProtection');
const { hashData } = require('../evidence/evidenceHasher');

const DEFAULT_TIMEOUT_MS   = 10000;
const MAX_BODY_BYTES       = 2 * 1024 * 1024; // 2MB safety limit
const MAX_REDIRECT_HOPS    = 5;

/**
 * Normalized HTTP Telemetry Data Structure
 * @typedef {object} HttpTelemetry
 * @property {string} requestedUrl
 * @property {string} finalUrl
 * @property {number} status
 * @property {Record<string, string|string[]>} headers
 * @property {string} contentType
 * @property {number} contentLength
 * @property {string} bodySnippet
 * @property {string} bodyHash
 * @property {number} elapsedMs
 * @property {string} protocol
 * @property {Array<{url: string, status: number, location?: string, error?: string}>} redirectChain
 * @property {string|null} connectionError
 */

/**
 * Fetches an HTTP/HTTPS URL with safe redirect following and limits.
 *
 * @param {URL|string} initialUrl
 * @param {object} [options]
 * @param {string} [options.method='GET']
 * @param {Record<string, string>} [options.headers]
 * @param {number} [options.maxRedirects=MAX_REDIRECT_HOPS]
 * @param {number} [options.timeoutMs=DEFAULT_TIMEOUT_MS]
 * @param {number} [options.maxBodyBytes=MAX_BODY_BYTES]
 * @returns {Promise<HttpTelemetry>}
 */
async function collectHttpTelemetry(initialUrl, options = {}) {
  const {
    method = 'GET',
    headers = {},
    maxRedirects = MAX_REDIRECT_HOPS,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBodyBytes = MAX_BODY_BYTES,
  } = options;

  let currentUrl = typeof initialUrl === 'string' ? new URL(initialUrl) : initialUrl;
  const redirectChain = [];
  const startTime = Date.now();

  for (let hop = 0; hop <= maxRedirects; hop++) {
    // SSRF Check on this hop
    const dnsCheck = await validateResolvedHost(currentUrl.hostname);
    if (dnsCheck.blocked) {
      const err = new Error(`SSRF Blocked on hop #${hop}: ${dnsCheck.reason}`);
      err.code = 'SSRF_BLOCKED';
      redirectChain.push({ url: currentUrl.toString(), status: null, error: err.message });
      return {
        requestedUrl: (typeof initialUrl === 'string' ? initialUrl : initialUrl.toString()),
        finalUrl: currentUrl.toString(),
        status: null,
        headers: {},
        contentType: '',
        contentLength: 0,
        bodySnippet: '',
        bodyHash: '',
        elapsedMs: Date.now() - startTime,
        protocol: currentUrl.protocol,
        redirectChain,
        connectionError: err.message,
      };
    }

    const isHttps = currentUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const requestHeaders = {
      'User-Agent': 'WebVitals-Audit-Engine/3.0 (+https://webvitals.dev/bot)',
      'Accept': 'text/html,application/xhtml+xml,application/json,*/*;q=0.9',
      'Accept-Language': 'en-US,en;q=0.8',
      'Connection': 'close',
      ...headers,
    };

    const reqOpts = {
      method,
      hostname: currentUrl.hostname,
      port: currentUrl.port || (isHttps ? 443 : 80),
      path: `${currentUrl.pathname || '/'}${currentUrl.search || ''}`,
      headers: requestHeaders,
      timeout: timeoutMs,
      // We explicitly capture TLS certs elsewhere, but avoid throwing on untrusted certs during plain HTTP telemetry
      rejectUnauthorized: false,
    };

    try {
      const hopResult = await new Promise((resolve, reject) => {
        const req = client.request(reqOpts, (res) => {
          let bodyChunks = [];
          let totalBytes = 0;
          let bodyTruncated = false;

          res.on('data', (chunk) => {
            totalBytes += chunk.length;
            if (totalBytes <= maxBodyBytes) {
              bodyChunks.push(chunk);
            } else if (!bodyTruncated) {
              bodyTruncated = true;
            }
          });

          res.on('end', () => {
            const rawBody = Buffer.concat(bodyChunks);
            const normalizedHeaders = {};
            for (const [k, v] of Object.entries(res.headers)) {
              normalizedHeaders[k.toLowerCase()] = v;
            }

            resolve({
              status: res.statusCode,
              headers: normalizedHeaders,
              rawBody,
              contentType: normalizedHeaders['content-type'] || '',
              contentLength: parseInt(normalizedHeaders['content-length'] || String(totalBytes), 10),
              location: res.headers.location || null,
            });
          });

          res.on('error', reject);
        });

        req.on('timeout', () => {
          req.destroy(new Error(`Connection timed out after ${timeoutMs}ms`));
        });

        req.on('error', reject);
        req.end();
      });

      const statusCode = hopResult.status;
      const isRedirect = [301, 302, 303, 307, 308].includes(statusCode) && hopResult.location;

      redirectChain.push({
        url: currentUrl.toString(),
        status: statusCode,
        location: hopResult.location || undefined,
      });

      if (isRedirect && hop < maxRedirects) {
        try {
          const nextUrl = new URL(hopResult.location, currentUrl.href);
          // Block non-http/https redirect schemes
          if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
            throw new Error(`Invalid redirect scheme: ${nextUrl.protocol}`);
          }
          currentUrl = nextUrl;
          continue; // Next hop
        } catch (redirErr) {
          return {
            requestedUrl: (typeof initialUrl === 'string' ? initialUrl : initialUrl.toString()),
            finalUrl: currentUrl.toString(),
            status: statusCode,
            headers: hopResult.headers,
            contentType: hopResult.contentType,
            contentLength: hopResult.contentLength,
            bodySnippet: hopResult.rawBody.toString('utf8', 0, 1024),
            bodyHash: hashData(hopResult.rawBody),
            elapsedMs: Date.now() - startTime,
            protocol: currentUrl.protocol,
            redirectChain,
            connectionError: `Malformed redirect location: ${redirErr.message}`,
          };
        }
      }

      // Terminal response reached
      const bodyStr = hopResult.rawBody.toString('utf8');
      return {
        requestedUrl: (typeof initialUrl === 'string' ? initialUrl : initialUrl.toString()),
        finalUrl: currentUrl.toString(),
        status: statusCode,
        headers: hopResult.headers,
        contentType: hopResult.contentType,
        contentLength: hopResult.contentLength,
        bodySnippet: bodyStr.slice(0, 4096),
        bodyHash: hashData(hopResult.rawBody),
        elapsedMs: Date.now() - startTime,
        protocol: currentUrl.protocol,
        redirectChain,
        connectionError: null,
      };

    } catch (err) {
      redirectChain.push({ url: currentUrl.toString(), status: null, error: err.message });
      return {
        requestedUrl: (typeof initialUrl === 'string' ? initialUrl : initialUrl.toString()),
        finalUrl: currentUrl.toString(),
        status: null,
        headers: {},
        contentType: '',
        contentLength: 0,
        bodySnippet: '',
        bodyHash: '',
        elapsedMs: Date.now() - startTime,
        protocol: currentUrl.protocol,
        redirectChain,
        connectionError: err.message,
      };
    }
  }

  // Exceeded redirect budget
  return {
    requestedUrl: (typeof initialUrl === 'string' ? initialUrl : initialUrl.toString()),
    finalUrl: currentUrl.toString(),
    status: null,
    headers: {},
    contentType: '',
    contentLength: 0,
    bodySnippet: '',
    bodyHash: '',
    elapsedMs: Date.now() - startTime,
    protocol: currentUrl.protocol,
    redirectChain,
    connectionError: `Exceeded maximum redirect limit of ${maxRedirects} hops`,
  };
}

module.exports = {
  collectHttpTelemetry,
  DEFAULT_TIMEOUT_MS,
  MAX_BODY_BYTES,
  MAX_REDIRECT_HOPS,
};
