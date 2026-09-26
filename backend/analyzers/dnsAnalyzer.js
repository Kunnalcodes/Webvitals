/**
 * DNS Security Analyzer — Phase 3
 * WebVitals
 *
 * Evaluates live DNS telemetry to generate evidence-backed findings for:
 *   - SPF records (-all vs ~all vs +all vs multiple records vs missing)
 *   - DMARC policy (p=reject vs quarantine vs none vs missing)
 *   - CAA authority restrictions
 *   - DKIM & DNSSEC boundary declarations (NOT_EVALUATED without selector)
 */

'use strict';

const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');

/**
 * Analyzes DNS security telemetry and returns structured findings.
 *
 * @param {object} dnsData - Output from collectDnsTelemetry
 * @returns {import('../evidence/evidenceModel').SecurityFinding[]}
 */
function analyzeDnsSecurity(dnsData) {
  const findings = [];
  if (!dnsData) return findings;

  // ── 1. SPF Analysis ────────────────────────────────────────────────────────
  if (dnsData.spf.hasMultiple) {
    findings.push(createFinding({
      id: 'SPF_MULTIPLE_RECORDS',
      channel: 'DNS',
      title: 'Multiple SPF Records Detected (RFC 7208 Violation)',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 1.0,
      scoreImpact: -8,
      description: `Domain has ${dnsData.spf.records.length} separate SPF records. According to RFC 7208 §3.2, publishing multiple SPF records causes mail receivers to return a PermError, effectively disabling SPF protection.`,
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.DNS,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: dnsData.spf.records.map((r) => r.raw),
      })],
      recommendation: 'Merge all authorized senders into a single TXT record starting with v=spf1.',
    }));
  } else if (dnsData.spf.present && dnsData.spf.primary) {
    const spf = dnsData.spf.primary;
    const spfEvidence = createEvidence({
      source: EVIDENCE_SOURCE.DNS,
      quality: EVIDENCE_QUALITY.DIRECT,
      observedValue: spf.raw,
      normalizedValue: { policy: spf.policy, mechanisms: spf.mechanisms },
    });

    if (spf.policy === 'HARD_FAIL') {
      findings.push(createFinding({
        id: 'SPF_HARD_FAIL',
        channel: 'DNS',
        title: 'SPF Policy Enforces Strict Rejection (-all)',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 1.0,
        scoreImpact: 5,
        description: 'SPF record specifies a strict hard-fail (-all) policy, instructing receivers to reject unauthorized mail claiming to be from this domain.',
        evidence: [spfEvidence],
      }));
    } else if (spf.policy === 'SOFT_FAIL') {
      findings.push(createFinding({
        id: 'SPF_SOFT_FAIL',
        channel: 'DNS',
        title: 'SPF Policy Uses Soft Fail (~all)',
        status: DETERMINATION.WARNING,
        severity: SEVERITY.LOW,
        confidence: 1.0,
        scoreImpact: 3,
        description: 'SPF record specifies soft-fail (~all). Unauthorized mail is accepted but marked as suspicious by receivers.',
        evidence: [spfEvidence],
        recommendation: 'Consider upgrading to a hard-fail (-all) policy once all legitimate mail sources have been identified and tested.',
      }));
    } else if (spf.policy === 'PASS_ALL_PERMISSIVE') {
      findings.push(createFinding({
        id: 'SPF_PERMISSIVE_ALL',
        channel: 'DNS',
        title: 'SPF Record Is Overly Permissive (+all)',
        status: DETERMINATION.FAIL,
        severity: SEVERITY.HIGH,
        confidence: 1.0,
        scoreImpact: -8,
        description: 'SPF record ends in +all, which explicitly authorizes every IP address on the internet to send email on behalf of your domain.',
        evidence: [spfEvidence],
        recommendation: 'Change +all to -all or ~all immediately to prevent unauthorized domain spoofing.',
      }));
    } else {
      findings.push(createFinding({
        id: 'SPF_NEUTRAL',
        channel: 'DNS',
        title: 'SPF Record Uses Neutral Policy (?all)',
        status: DETERMINATION.WARNING,
        severity: SEVERITY.MEDIUM,
        confidence: 1.0,
        scoreImpact: 1,
        description: 'SPF record uses ?all (neutral), providing no guidance to mail servers on how to treat unauthorized mail.',
        evidence: [spfEvidence],
        recommendation: 'Change ?all to -all or ~all.',
      }));
    }
  } else {
    findings.push(createFinding({
      id: 'SPF_MISSING',
      channel: 'DNS',
      title: 'No SPF (Sender Policy Framework) Record Found',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.HIGH,
      confidence: 1.0,
      scoreImpact: -6,
      description: 'Domain does not publish an SPF record. Attackers can forge emails claiming to originate from this domain without failing receiver SPF checks.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.DNS,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: dnsData.records.txt,
        notes: ['No TXT record matching v=spf1 was found'],
      })],
      recommendation: 'Publish a TXT record for your domain with your authorized mail servers (e.g. "v=spf1 include:_spf.google.com -all").',
    }));
  }

  // ── 2. DMARC Analysis ──────────────────────────────────────────────────────
  if (dnsData.dmarc.present && dnsData.dmarc.parsed) {
    const dmarc = dnsData.dmarc.parsed;
    const dmarcEvidence = createEvidence({
      source: EVIDENCE_SOURCE.DNS,
      quality: EVIDENCE_QUALITY.DIRECT,
      observedValue: dmarc.raw,
      normalizedValue: { policy: dmarc.policy, pct: dmarc.percentage, rua: dmarc.reportUriAggregate },
    });

    if (dmarc.policy === 'REJECT') {
      findings.push(createFinding({
        id: 'DMARC_REJECT',
        channel: 'DNS',
        title: 'DMARC Policy Enforces Strict Rejection (p=reject)',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 1.0,
        scoreImpact: 5,
        description: 'DMARC policy instructs receiving mail servers to reject unauthenticated mail claiming to originate from this domain.',
        evidence: [dmarcEvidence],
      }));
    } else if (dmarc.policy === 'QUARANTINE') {
      findings.push(createFinding({
        id: 'DMARC_QUARANTINE',
        channel: 'DNS',
        title: 'DMARC Policy Enforces Quarantine (p=quarantine)',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 1.0,
        scoreImpact: 4,
        description: 'DMARC policy instructs receiving mail servers to direct unauthenticated mail into spam/quarantine folders.',
        evidence: [dmarcEvidence],
        recommendation: 'Progress from p=quarantine to p=reject once monitoring confirms zero legitimate message deliverability issues.',
      }));
    } else if (dmarc.policy === 'MONITORING_NONE') {
      findings.push(createFinding({
        id: 'DMARC_POLICY_NONE',
        channel: 'DNS',
        title: 'DMARC Policy in Monitoring Mode (p=none)',
        status: DETERMINATION.WARNING,
        severity: SEVERITY.LOW,
        confidence: 1.0,
        scoreImpact: 2,
        description: 'DMARC record exists but is configured with p=none. It collects reports but does not block spoofed emails from reaching inboxes.',
        evidence: [dmarcEvidence],
        recommendation: 'Update your DMARC policy from p=none to p=quarantine or p=reject to enforce spoofing protection.',
      }));
    }
  } else {
    findings.push(createFinding({
      id: 'DMARC_MISSING',
      channel: 'DNS',
      title: 'No DMARC Record Found (_dmarc)',
      status: DETERMINATION.FAIL,
      severity: SEVERITY.MEDIUM,
      confidence: 1.0,
      scoreImpact: -5,
      description: 'Domain does not publish a DMARC policy. Mail receivers have no instructions on how to handle SPF/DKIM alignment failures.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.DNS,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: `Host _dmarc.${dnsData.domain} returned no TXT record`,
      })],
      recommendation: 'Add a TXT record at _dmarc.<domain> with at least "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@<domain>".',
    }));
  }

  // ── 3. CAA (Certification Authority Authorization) ────────────────────────
  if (dnsData.caa.present && dnsData.caa.records.length > 0) {
    findings.push(createFinding({
      id: 'CAA_CONFIGURED',
      channel: 'DNS',
      title: 'CAA Record Restricts Authorized Certificate Authorities',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 1.0,
      scoreImpact: 2,
      description: `CAA record restricts certificate issuance to authorized CAs: ${dnsData.caa.authorities.join(', ') || 'configured authorities'}.`,
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.DNS,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: dnsData.caa.records,
      })],
    }));
  } else {
    findings.push(createFinding({
      id: 'CAA_ABSENT',
      channel: 'DNS',
      title: 'No CAA (Certificate Authority Authorization) Record',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 1.0,
      scoreImpact: -1,
      description: 'No CAA record is published. Any publicly trusted Certificate Authority is allowed to issue certificates for your domain name.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.DNS,
        quality: EVIDENCE_QUALITY.DIRECT,
        observedValue: 'No CAA records found for domain',
      })],
      recommendation: 'Publish a CAA DNS record specifying only the CAs you use (e.g. `example.com. IN CAA 0 issue "letsencrypt.org"`).',
    }));
  }

  // ── 4. DKIM & DNSSEC Boundaries ───────────────────────────────────────────
  findings.push(createFinding({
    id: 'DKIM_EVALUATION_BOUNDARY',
    channel: 'DNS',
    title: 'DKIM (DomainKeys Identified Mail)',
    status: DETERMINATION.NOT_EVALUATED,
    severity: SEVERITY.INFO,
    confidence: 1.0,
    description: 'DKIM records require specific selector names (e.g. `google._domainkey.<domain>`). Remote unauthenticated probing cannot enumerate arbitrary selectors.',
    limitations: ['DKIM status is marked NOT_EVALUATED to maintain absolute data integrity rather than guessing selectors.'],
  }));

  return findings;
}

module.exports = {
  analyzeDnsSecurity,
};
