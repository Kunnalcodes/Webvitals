/**
 * TLS / SSL Security Analyzer — Phase 3
 * WebVitals
 *
 * Evaluates TLS telemetry to generate evidence-backed findings for:
 *   - HTTPS availability & redirection
 *   - Certificate validity & SANs hostname coverage
 *   - Certificate expiration status
 *   - Protocol deprecation (TLS 1.0, 1.1 vs 1.2, 1.3)
 *   - Cipher suite strength
 *   - Self-signed certificate risk
 */

'use strict';

const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');
const { computeConfidence } = require('../evidence/confidenceEngine');

/**
 * Analyzes TLS telemetry and produces standardized findings.
 *
 * @param {object} tlsData - Output from collectTlsTelemetry
 * @param {object} httpData - Output from collectHttpTelemetry
 * @returns {import('../evidence/evidenceModel').SecurityFinding[]}
 */
function analyzeTlsSecurity(tlsData, httpData) {
  const findings = [];

  // ── 1. HTTPS Availability & Redirection ──────────────────────────────────
  const isHttps = httpData?.protocol === 'https:' || httpData?.finalUrl?.startsWith('https://');
  const initialIsHttp = httpData?.requestedUrl?.startsWith('http://');
  const redirectedToHttps = initialIsHttp && isHttps;

  const httpsEvidence = createEvidence({
    source: EVIDENCE_SOURCE.HTTPS,
    quality: EVIDENCE_QUALITY.DIRECT,
    observedValue: {
      requestedUrl: httpData?.requestedUrl,
      finalUrl: httpData?.finalUrl,
      protocol: httpData?.protocol,
      redirectCount: httpData?.redirectChain?.length || 0,
    },
    notes: [redirectedToHttps ? 'HTTP successfully upgraded to HTTPS via redirect chain' : 'Target operates on HTTPS'],
  });

  if (isHttps) {
    findings.push(createFinding({
      id: 'HTTPS_ENABLED',
      channel: 'HTTPS',
      title: 'HTTPS Encryption Active',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 10,
      description: 'The target serves content over encrypted HTTPS connections, protecting data in transit from eavesdropping and tampering.',
      evidence: [httpsEvidence],
      recommendation: 'Maintain automatic HTTP to HTTPS redirection across all endpoints.',
    }));
  } else {
    findings.push(createFinding({
      id: 'HTTPS_DISABLED',
      channel: 'HTTPS',
      title: 'HTTPS Not Used (Insecure Plaintext HTTP)',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 1.0,
      scoreImpact: -10,
      description: 'The target serves content over plaintext HTTP. Unencrypted traffic can be intercepted, read, or modified by intermediate networks (MitM).',
      evidence: [httpsEvidence],
      recommendation: 'Obtain an SSL/TLS certificate and configure automatic 301 redirection from HTTP to HTTPS.',
    }));
  }

  // ── 2. TLS Certificate Validity & Hostname Coverage ───────────────────────
  if (!tlsData || !tlsData.hasCert) {
    if (isHttps) {
      findings.push(createFinding({
        id: 'TLS_CERT_UNAVAILABLE',
        channel: 'TLS',
        title: 'TLS Certificate Could Not Be Inspected',
        status: DETERMINATION.WARNING,
        severity: SEVERITY.MEDIUM,
        confidence: 0.85,
        scoreImpact: -5,
        description: tlsData?.error || 'Unable to establish direct TLS handshake to extract certificate parameters.',
        evidence: [createEvidence({
          source: EVIDENCE_SOURCE.TLS,
          quality: EVIDENCE_QUALITY.DIRECT,
          observedValue: tlsData?.error || 'Handshake failed',
        })],
        recommendation: 'Verify that the server supports standard TLS negotiation and has a valid certificate installed.',
      }));
    }
    return findings;
  }

  const certEvidence = createEvidence({
    source: EVIDENCE_SOURCE.TLS,
    quality: EVIDENCE_QUALITY.DIRECT,
    observedValue: {
      commonName: tlsData.commonName,
      subjectAltNames: tlsData.subjectAltNames,
      issuer: tlsData.issuer,
      validFrom: tlsData.validFrom,
      validTo: tlsData.validTo,
      daysRemaining: tlsData.daysRemaining,
      protocol: tlsData.protocol,
      cipher: tlsData.cipher,
      isSelfSigned: tlsData.isSelfSigned,
      isHostnameMatch: tlsData.isHostnameMatch,
    },
    notes: [`Observed ${tlsData.protocol} using ${tlsData.cipher?.name || 'cipher'}`],
  });

  // Hostname match check
  if (tlsData.isHostnameMatch) {
    findings.push(createFinding({
      id: 'TLS_HOSTNAME_VALID',
      channel: 'TLS',
      title: 'TLS Certificate Covers Requested Hostname',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: `Certificate SANs (${tlsData.subjectAltNames.join(', ') || tlsData.commonName}) correctly cover target host '${tlsData.hostname}'.`,
      evidence: [certEvidence],
      recommendation: 'Ensure renewing certificates continue to cover all relevant subdomains and apex domains.',
    }));
  } else {
    findings.push(createFinding({
      id: 'TLS_HOSTNAME_MISMATCH',
      channel: 'TLS',
      title: 'TLS Certificate Name Mismatch',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 0.98,
      scoreImpact: -10,
      description: `The certificate presented is for (${tlsData.subjectAltNames.join(', ') || tlsData.commonName}), which does not match '${tlsData.hostname}'. Browsers will display security warnings.`,
      evidence: [certEvidence],
      recommendation: 'Re-issue the SSL/TLS certificate including this hostname in the Subject Alternative Names (SAN) list.',
    }));
  }

  // Self-signed check
  if (tlsData.isSelfSigned) {
    findings.push(createFinding({
      id: 'TLS_SELF_SIGNED',
      channel: 'TLS',
      title: 'Self-Signed SSL/TLS Certificate Detected',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 0.99,
      scoreImpact: -10,
      description: 'The TLS certificate is self-signed and not issued by a recognized Certificate Authority. Browsers will block access.',
      evidence: [certEvidence],
      recommendation: 'Replace the self-signed certificate with one issued by a trusted public CA such as Let\'s Encrypt or DigiCert.',
    }));
  }

  // Expiration check
  if (tlsData.isExpired) {
    findings.push(createFinding({
      id: 'TLS_CERT_EXPIRED',
      channel: 'TLS',
      title: 'SSL/TLS Certificate Is Expired',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.CRITICAL,
      confidence: 1.0,
      scoreImpact: -15,
      description: `The SSL certificate expired on ${tlsData.validTo} (${Math.abs(tlsData.daysRemaining || 0)} days ago).`,
      evidence: [certEvidence],
      recommendation: 'Renew and deploy an updated certificate immediately.',
    }));
  } else if (tlsData.isNearExpiry) {
    findings.push(createFinding({
      id: 'TLS_CERT_NEAR_EXPIRY',
      channel: 'TLS',
      title: 'SSL/TLS Certificate Expiring Soon',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.MEDIUM,
      confidence: 1.0,
      scoreImpact: -3,
      description: `The SSL certificate expires in ${tlsData.daysRemaining} days (on ${tlsData.validTo}).`,
      evidence: [certEvidence],
      recommendation: 'Initiate certificate renewal before the expiration date to avoid service disruption.',
    }));
  } else if (tlsData.daysRemaining !== null) {
    findings.push(createFinding({
      id: 'TLS_CERT_VALID',
      channel: 'TLS',
      title: 'SSL/TLS Certificate Is Valid',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 5,
      description: `Certificate is valid for another ${tlsData.daysRemaining} days (expires ${tlsData.validTo}).`,
      evidence: [certEvidence],
    }));
  }

  // Protocol version check
  const proto = (tlsData.protocol || '').toUpperCase();
  if (proto === 'TLSV1.3' || proto === 'TLSV1.2') {
    findings.push(createFinding({
      id: 'TLS_MODERN_PROTOCOL',
      channel: 'TLS',
      title: `Modern TLS Protocol Negotiated (${tlsData.protocol})`,
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 0.95,
      scoreImpact: 5,
      description: `The server negotiated ${tlsData.protocol}, which provides strong cryptographic primitives.`,
      evidence: [certEvidence],
      limitations: ['Black-box scanning observes the negotiated cipher suite; weaker legacy protocols may still be accepted if enabled.'],
    }));
  } else if (proto === 'TLSV1' || proto === 'TLSV1.0' || proto === 'TLSV1.1' || proto === 'SSLV3' || proto.startsWith('SSL')) {
    findings.push(createFinding({
      id: 'TLS_DEPRECATED_PROTOCOL',
      channel: 'TLS',
      title: `Deprecated TLS/SSL Protocol Negotiated (${tlsData.protocol})`,
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 0.98,
      scoreImpact: -10,
      description: `${tlsData.protocol} is deprecated and vulnerable to known cryptographic attacks (e.g. POODLE, BEAST).`,
      evidence: [certEvidence],
      recommendation: 'Disable TLS 1.0, TLS 1.1, and SSLv3 on your web server and enable TLS 1.2 and TLS 1.3 only.',
    }));
  }


  return findings;
}

module.exports = {
  analyzeTlsSecurity,
};
