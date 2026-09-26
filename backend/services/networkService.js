/**
 * Network Service — Phase 1
 * WebVitals
 *
 * Fixes P0-2: Redirects are now re-validated at each hop via SSRF check.
 * Fixes P1-4: rejectUnauthorized is true by default on the fetch layer
 *             (kept false only for TLS inspection in getCertInfo, which is intentional).
 */

'use strict';

const http  = require('http');
const https = require('https');
const tls   = require('tls');
const { URL } = require('url');
const { validateRedirectDestination } = require('../middleware/abuseProtection');
const { SCAN_TIMEOUT_MS, SCAN_MAX_REDIRECTS } = require('../config/env');

const USER_AGENT = 'WebVitals-Scanner/1.0 (+https://webvitals.dev; security-research)';

/**
 * Fetches a URL following redirects, validating each redirect destination for SSRF.
 *
 * @param {URL}    urlObj        - Target URL object
 * @param {number} maxRedirects  - Remaining redirect budget
 * @param {Array}  chain         - Accumulated redirect chain
 * @param {number} startTime     - Original request start timestamp
 * @returns {Promise<ScanResult>}
 */
async function fetchWithRedirects(urlObj, maxRedirects = SCAN_MAX_REDIRECTS, chain = [], startTime = Date.now()) {
  return new Promise((resolve, reject) => {
    const lib = urlObj.protocol === 'http:' ? http : https;

    const requestOptions = {
      method:  'GET',
      timeout: SCAN_TIMEOUT_MS,
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close',
      },
      // Keep rejectUnauthorized TRUE on the fetch layer.
      // We still inspect TLS separately via getCertInfo (which intentionally uses false
      // to collect evidence about broken certs rather than refuse the connection).
      rejectUnauthorized: true,
    };

    const req = lib.request(urlObj, requestOptions, (res) => {
      chain.push({
        url:    urlObj.toString(),
        status: res.statusCode,
        finalProtocol: urlObj.protocol,
      });

      // Discard body — we only need headers
      res.resume();

      res.on('end', async () => {
        const locationHeader = res.headers.location;
        const isRedirect = [301, 302, 303, 307, 308].includes(res.statusCode) && locationHeader;

        if (isRedirect && maxRedirects > 0) {
          let nextUrl;
          try {
            nextUrl = new URL(locationHeader, urlObj);
          } catch {
            // Malformed Location header — stop following
            return resolve(buildResult(urlObj, res, chain, startTime));
          }

          // ─── P0-2 Fix: Validate redirect destination ──────────────────────
          try {
            const ssrfCheck = await validateRedirectDestination(nextUrl);
            if (!ssrfCheck.valid) {
              return reject(new Error(`SSRF: ${ssrfCheck.message}`));
            }
          } catch (ssrfErr) {
            return reject(ssrfErr);
          }

          // Recurse with decremented budget
          try {
            resolve(await fetchWithRedirects(nextUrl, maxRedirects - 1, chain, startTime));
          } catch (err) {
            reject(err);
          }
        } else {
          resolve(buildResult(urlObj, res, chain, startTime));
        }
      });
    });

    req.on('timeout', () => req.destroy(new Error(`Request timed out after ${SCAN_TIMEOUT_MS}ms`)));
    req.on('error', (err) => {
      // If TLS validation fails (self-signed, expired, mismatch), we still want
      // to record the attempt in the chain. Create a partial result.
      if (err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
          err.code === 'CERT_HAS_EXPIRED' ||
          err.code === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
          err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
        chain.push({ url: urlObj.toString(), status: null, tlsError: err.code });
        resolve({
          finalUrl:     urlObj,
          status:       null,
          headers:      {},
          chain,
          elapsedMs:    Date.now() - startTime,
          protocolUsed: urlObj.protocol,
          tlsError:     err.code,
        });
      } else {
        reject(err);
      }
    });
    req.end();
  });
}

function buildResult(urlObj, res, chain, startTime) {
  return {
    finalUrl:     urlObj,
    status:       res.statusCode,
    headers:      res.headers,
    chain,
    elapsedMs:    Date.now() - startTime,
    protocolUsed: urlObj.protocol,
    tlsError:     null,
  };
}

/**
 * Inspects TLS certificate details via a raw TLS handshake.
 * Intentionally uses rejectUnauthorized: false to gather evidence
 * about broken/expired/mismatched certs rather than refuse the connection.
 *
 * @param {string} hostname
 * @param {number} [port=443]
 * @returns {Promise<CertInfo|null>}
 */
function getCertInfo(hostname, port = 443) {
  return new Promise((resolve) => {
    let settled = false;

    const socket = tls.connect(
      {
        host:              hostname,
        port,
        servername:        hostname,
        timeout:           6000,
        rejectUnauthorized: false, // intentional — we want to inspect broken certs
      },
      () => {
        if (settled) return;
        settled = true;

        const cert     = socket.getPeerCertificate();
        const authorized = socket.authorized;
        const authError  = socket.authorizationError ? String(socket.authorizationError) : null;
        const protocol   = socket.getProtocol ? socket.getProtocol() : null;
        socket.end();

        if (!cert || Object.keys(cert).length === 0) return resolve(null);

        resolve({
          issuer:      cert.issuer?.O || cert.issuer?.CN || 'Unknown',
          issuerCN:    cert.issuer?.CN || 'Unknown',
          subject:     cert.subject?.CN || hostname,
          subjectAltNames: cert.subjectaltname || null,
          serialNumber: cert.serialNumber || null,
          fingerprint: cert.fingerprint || null,
          validFrom:   cert.valid_from || null,
          validTo:     cert.valid_to   || null,
          authorized,
          authError,
          tlsVersion:  protocol || 'Unknown',
        });
      }
    );

    const cleanup = (reason) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(null); // treat as "could not retrieve"
    };

    socket.on('timeout', () => cleanup('timeout'));
    socket.on('error',   () => cleanup('error'));
  });
}

module.exports = { fetchWithRedirects, getCertInfo };
