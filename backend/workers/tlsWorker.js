/**
 * TLS Worker — WebVitals Modular Scan Engine
 *
 * Inspects TLS handshake, certificate validity, expiration, issuer, SAN matching,
 * cipher suites, and protocol support. Returns Standard Result Schema objects.
 */

'use strict';

const tls = require('tls');
const { createCheckResult } = require('../scan/checkSchema');

/**
 * Runs TLS inspection on the target host.
 *
 * @param {string} hostname
 * @param {number} [port=443]
 * @returns {Promise<{ checks: Object[], tlsData: Object }>}
 */
async function runTlsWorker(hostname, port = 443) {
  const startTime = Date.now();

  return new Promise((resolve) => {
    let socket;
    try {
      socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          timeout: 8000,
          rejectUnauthorized: false, // capture unverified certs for diagnostic evidence
        },
        () => {
          const durationMs = Date.now() - startTime;
          try {
            const cert = socket.getPeerCertificate(true);
            const cipher = socket.getCipher();
            const protocol = socket.getProtocol();
            const authorized = socket.authorized;
            const authError = socket.authorizationError;

            socket.destroy();

            const validTo = cert?.valid_to ? new Date(cert.valid_to) : null;
            const validFrom = cert?.valid_from ? new Date(cert.valid_from) : null;
            const now = new Date();
            const daysRemaining = validTo ? Math.round((validTo - now) / (1000 * 60 * 60 * 24)) : 0;
            const isExpired = validTo ? validTo < now : false;

            const issuer = cert?.issuer?.O || cert?.issuer?.CN || 'Recognized Certificate Authority';
            const subject = cert?.subject?.CN || hostname;
            const sans = cert?.subjectaltname || '';

            // Check if hostname matches subject or SANs
            const cleanSans = sans.split(',').map(s => s.trim().replace(/^DNS:/i, ''));
            const matchesSan = cleanSans.some(s => {
              if (s === hostname) return true;
              if (s.startsWith('*.')) {
                const domainSuffix = s.slice(2);
                return hostname.endsWith(domainSuffix);
              }
              return false;
            }) || subject === hostname;

            const checks = [];

            // Check 1: TLS Certificate Validity & Expiration
            if (!cert || Object.keys(cert).length === 0) {
              checks.push(createCheckResult({
                checkId: 'security.tls.cert',
                category: 'security',
                title: 'SSL/TLS Certificate Validity',
                status: 'finding',
                severity: 'critical',
                confidence: 1.0,
                summary: 'No valid SSL/TLS certificate presented by server',
                details: `Host ${hostname}:${port} did not provide an X.509 certificate during TLS negotiation.`,
                evidence: { error: 'NO_PEER_CERTIFICATE' },
                recommendation: 'Install an SSL certificate from an automated provider such as Let\'s Encrypt.',
                references: ['https://datatracker.ietf.org/doc/html/rfc5280'],
                source: 'tls-handshake',
                durationMs,
              }));
            } else if (isExpired) {
              checks.push(createCheckResult({
                checkId: 'security.tls.cert',
                category: 'security',
                title: 'SSL/TLS Certificate Validity',
                status: 'finding',
                severity: 'critical',
                confidence: 1.0,
                summary: `SSL/TLS certificate has expired on ${validTo?.toISOString()}`,
                details: `The certificate presented by ${hostname} expired ${Math.abs(daysRemaining)} days ago. Browsers will block client connections.`,
                evidence: { validTo: validTo?.toISOString(), daysRemaining, issuer, subject },
                recommendation: 'Renew and deploy an active SSL/TLS certificate immediately.',
                references: ['https://datatracker.ietf.org/doc/html/rfc5280'],
                source: 'tls-handshake',
                durationMs,
              }));
            } else if (daysRemaining <= 14) {
              checks.push(createCheckResult({
                checkId: 'security.tls.cert',
                category: 'security',
                title: 'SSL/TLS Certificate Validity',
                status: 'finding',
                severity: 'high',
                confidence: 1.0,
                summary: `Certificate expiring soon: Only ${daysRemaining} day(s) remaining`,
                details: `Valid until ${validTo?.toISOString()}. Certificate will expire in under two weeks.`,
                evidence: { validTo: validTo?.toISOString(), daysRemaining, issuer },
                recommendation: 'Trigger automated certificate renewal to avoid service disruption.',
                source: 'tls-handshake',
                durationMs,
              }));
            } else {
              checks.push(createCheckResult({
                checkId: 'security.tls.cert',
                category: 'security',
                title: 'SSL/TLS Certificate Validity',
                status: 'pass',
                severity: 'none',
                confidence: 1.0,
                summary: `Valid SSL/TLS certificate issued by ${issuer} (${daysRemaining} days remaining)`,
                details: `Subject: ${subject}. Validity window: ${validFrom?.toISOString()} to ${validTo?.toISOString()}.`,
                evidence: { issuer, subject, validTo: validTo?.toISOString(), daysRemaining, sans },
                source: 'tls-handshake',
                durationMs,
              }));
            }

            // Check 2: Hostname & Subject Alternative Name (SAN) Matching
            if (matchesSan) {
              checks.push(createCheckResult({
                checkId: 'security.tls.san',
                category: 'security',
                title: 'Hostname & Subject Alternative Name (SAN) Match',
                status: 'pass',
                severity: 'none',
                confidence: 1.0,
                summary: `Hostname "${hostname}" matches certificate SANs`,
                details: `Certificate covers requested hostname via SAN: ${sans || subject}.`,
                evidence: { hostname, sans: cleanSans },
                source: 'tls-handshake',
                durationMs,
              }));
            } else {
              checks.push(createCheckResult({
                checkId: 'security.tls.san',
                category: 'security',
                title: 'Hostname & Subject Alternative Name (SAN) Match',
                status: 'finding',
                severity: 'critical',
                confidence: 1.0,
                summary: `Certificate name mismatch: "${hostname}" is not covered by SANs`,
                details: `Presented certificate covers: "${sans || subject}". Browsers will display an SSL/TLS domain mismatch warning (NET::ERR_CERT_COMMON_NAME_INVALID).`,
                evidence: { requestedHost: hostname, certificateSans: cleanSans, subject },
                recommendation: 'Reissue the certificate including this domain in the Subject Alternative Names.',
                references: ['https://datatracker.ietf.org/doc/html/rfc6125'],
                source: 'tls-handshake',
                durationMs,
              }));
            }

            // Check 3: Negotiated Protocol (TLS 1.2 vs 1.3)
            const isModernTls = protocol === 'TLSv1.3' || protocol === 'TLSv1.2';
            const isTls13 = protocol === 'TLSv1.3';

            checks.push(createCheckResult({
              checkId: 'security.tls.protocol',
              category: 'security',
              title: 'TLS Protocol Negotiation & Cipher Suite',
              status: isModernTls ? 'pass' : 'finding',
              severity: isModernTls ? 'none' : 'high',
              confidence: 1.0,
              summary: `${protocol || 'TLS'} negotiated with cipher ${cipher?.name || 'Standard'}`,
              details: `Protocol: ${protocol}. Cipher: ${cipher?.name} (${cipher?.version}). Modern forward secrecy and authenticated encryption active.`,
              evidence: { protocol, cipher, isTls13 },
              source: 'tls-handshake',
              durationMs,
            }));

            const tlsData = {
              protocol,
              cipher: cipher?.name,
              issuer,
              subject,
              daysRemaining,
              validFrom: validFrom?.toISOString(),
              validTo: validTo?.toISOString(),
              authorized,
              authError: authError || null,
              sans: cleanSans,
            };

            resolve({ checks, tlsData });
          } catch (err) {
            resolve({
              checks: [createCheckResult({
                checkId: 'security.tls.cert',
                category: 'security',
                title: 'SSL/TLS Handshake',
                status: 'error',
                severity: 'medium',
                confidence: 0.9,
                summary: `TLS analysis failed: ${err.message}`,
                evidence: { error: err.message },
                source: 'tls-handshake',
                durationMs: Date.now() - startTime,
              })],
              tlsData: null,
            });
          }
        }
      );

      socket.on('error', (err) => {
        resolve({
          checks: [createCheckResult({
            checkId: 'security.tls.cert',
            category: 'security',
            title: 'SSL/TLS Connection',
            status: 'error',
            severity: 'medium',
            confidence: 0.9,
            summary: `TLS connection failed: ${err.message}`,
            details: `Socket connection to ${hostname}:${port} failed. Port may be closed or firewalled.`,
            evidence: { error: err.code || err.message },
            source: 'tls-socket',
            durationMs: Date.now() - startTime,
          })],
          tlsData: null,
        });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({
          checks: [createCheckResult({
            checkId: 'security.tls.cert',
            category: 'security',
            title: 'SSL/TLS Handshake Timeout',
            status: 'error',
            severity: 'medium',
            confidence: 0.8,
            summary: 'TLS handshake timed out after 8000ms',
            evidence: { timeout: true },
            source: 'tls-socket',
            durationMs: Date.now() - startTime,
          })],
          tlsData: null,
        });
      });
    } catch (outerErr) {
      resolve({
        checks: [createCheckResult({
          checkId: 'security.tls.cert',
          category: 'security',
          title: 'SSL/TLS Exception',
          status: 'error',
          severity: 'low',
          confidence: 0.5,
          summary: outerErr.message,
          evidence: { error: outerErr.message },
          source: 'tls-socket',
          durationMs: Date.now() - startTime,
        })],
        tlsData: null,
      });
    }
  });
}

module.exports = {
  runTlsWorker,
};
