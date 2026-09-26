/**
 * TLS / SSL Telemetry Collector — Phase 3
 * WebVitals
 *
 * Direct, live TLS inspection via Node.js native `tls.connect()`.
 * Validates SANs hostname matching, cipher suites, protocol versions,
 * certificate expiration, and self-signed certificate status.
 */

'use strict';

const tls = require('tls');
const { validateResolvedHost } = require('../middleware/abuseProtection');

const TLS_TIMEOUT_MS = 8000;

/**
 * Validates if a hostname matches any SAN or Common Name (including wildcards).
 *
 * @param {string} hostname - Target hostname (e.g. 'sub.example.com')
 * @param {string[]} sans - Subject Alternative Names (e.g. ['*.example.com', 'example.com'])
 * @param {string} [commonName] - Subject CN
 * @returns {boolean}
 */
function matchesHostname(hostname, sans = [], commonName = '') {
  const cleanHost = hostname.toLowerCase();
  const candidates = [...sans];
  if (commonName && !candidates.includes(commonName)) {
    candidates.push(commonName);
  }

  for (const pattern of candidates) {
    const cleanPattern = pattern.toLowerCase();
    if (cleanPattern === cleanHost) return true;

    // Wildcard matching (*.example.com)
    if (cleanPattern.startsWith('*.')) {
      const suffix = cleanPattern.slice(2);
      const hostParts = cleanHost.split('.');
      const patternParts = suffix.split('.');
      // Wildcard only matches single subdomain level
      if (hostParts.length === patternParts.length + 1) {
        if (cleanHost.endsWith(`.${suffix}`)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Inspects the live TLS certificate and connection parameters for a host.
 *
 * @param {string} hostname
 * @param {number} [port=443]
 * @param {object} [options]
 * @param {number} [options.timeoutMs=TLS_TIMEOUT_MS]
 * @returns {Promise<object>}
 */
async function collectTlsTelemetry(hostname, port = 443, options = {}) {
  const { timeoutMs = TLS_TIMEOUT_MS } = options;

  // SSRF check on hostname
  const dnsCheck = await validateResolvedHost(hostname);
  if (dnsCheck.blocked) {
    return {
      connected: false,
      error: `SSRF Blocked: ${dnsCheck.reason}`,
      hostname,
      port,
    };
  }

  return new Promise((resolve) => {
    let settled = false;

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname, // SNI is critical
        rejectUnauthorized: false, // We inspect authorizationError manually
        timeout: timeoutMs,
      },
      () => {
        if (settled) return;
        settled = true;

        try {
          const cert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();
          const authorized = socket.authorized;
          const authError = socket.authorizationError || null;

          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            return resolve({
              connected: true,
              hasCert: false,
              protocol,
              cipher: cipher ? cipher.name : null,
              authorized: false,
              error: 'No peer certificate presented by server',
            });
          }

          // Parse SANs
          const rawSan = cert.subjectaltname || '';
          const sans = rawSan
            .split(',')
            .map((s) => s.trim().replace(/^DNS:/i, ''))
            .filter(Boolean);

          const validFrom = cert.valid_from;
          const validTo = cert.valid_to;
          const expiryDate = validTo ? new Date(validTo) : null;
          const now = Date.now();
          const daysRemaining = expiryDate ? Math.round((expiryDate.getTime() - now) / (1000 * 60 * 60 * 24)) : null;

          const cn = cert.subject?.CN || '';
          const isHostnameMatch = matchesHostname(hostname, sans, cn);

          // Check for self-signed
          const isSelfSigned = cert.issuer && cert.subject &&
            cert.issuer.CN === cert.subject.CN &&
            cert.issuer.O === cert.subject.O;

          // Certificate chain depth
          let chainLength = 1;
          let currentCert = cert;
          const issuers = [];
          if (cert.issuer) issuers.push(cert.issuer.O || cert.issuer.CN || 'Unknown');

          while (currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert) {
            chainLength++;
            currentCert = currentCert.issuerCertificate;
            if (currentCert.issuer) {
              issuers.push(currentCert.issuer.O || currentCert.issuer.CN || 'Unknown');
            }
            if (chainLength > 10) break; // cycle protection
          }

          socket.destroy();

          resolve({
            connected: true,
            hasCert: true,
            hostname,
            port,
            protocol, // e.g. 'TLSv1.3'
            cipher: {
              name: cipher?.name || 'UNKNOWN',
              standardName: cipher?.standardName || cipher?.name || 'UNKNOWN',
              version: cipher?.version || protocol,
            },
            subject: cert.subject || {},
            issuer: cert.issuer || {},
            issuersChain: issuers,
            chainLength,
            commonName: cn,
            subjectAltNames: sans,
            validFrom,
            validTo,
            daysRemaining,
            isExpired: daysRemaining !== null && daysRemaining <= 0,
            isNearExpiry: daysRemaining !== null && daysRemaining > 0 && daysRemaining <= 30,
            isHostnameMatch,
            isSelfSigned: Boolean(isSelfSigned),
            authorized,
            authorizationError: authError ? String(authError) : null,
            fingerprint256: cert.fingerprint256 || cert.fingerprint || null,
            serialNumber: cert.serialNumber || null,
          });

        } catch (err) {
          socket.destroy();
          resolve({
            connected: true,
            hasCert: false,
            error: `Failed to inspect certificate: ${err.message}`,
          });
        }
      }
    );

    socket.on('timeout', () => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve({
          connected: false,
          error: `TLS connection timed out after ${timeoutMs}ms`,
          hostname,
          port,
        });
      }
    });

    socket.on('error', (err) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve({
          connected: false,
          error: err.message,
          hostname,
          port,
        });
      }
    });
  });
}

module.exports = {
  collectTlsTelemetry,
  matchesHostname,
  TLS_TIMEOUT_MS,
};
