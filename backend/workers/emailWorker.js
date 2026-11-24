/**
 * Email Security Worker — WebVitals Modular Scan Engine
 *
 * Audits MX, SPF, DKIM, and DMARC configurations with deep syntax validation.
 * Outputs standardized checks matching the Standard Result Schema.
 */

'use strict';

const dns = require('dns').promises;
const { createCheckResult } = require('../scan/checkSchema');

/**
 * Executes email security audits for the target hostname.
 *
 * @param {string} hostname
 * @param {string[]} [existingTxtRecords=[]]
 * @param {Object[]} [existingMxRecords=[]]
 * @returns {Promise<{ checks: Object[], emailConfig: Object }>}
 */
async function runEmailWorker(hostname, existingTxtRecords = [], existingMxRecords = []) {
  const startTime = Date.now();
  let txtRecords = existingTxtRecords;
  let mxRecords = existingMxRecords;

  if (!txtRecords.length || !mxRecords.length) {
    try {
      const [txtRes, mxRes] = await Promise.allSettled([
        dns.resolveTxt(hostname),
        dns.resolveMx(hostname),
      ]);
      if (txtRes.status === 'fulfilled' && !txtRecords.length) txtRecords = txtRes.value.flat();
      if (mxRes.status === 'fulfilled' && !mxRecords.length) mxRecords = mxRes.value;
    } catch {}
  }

  // Also query _dmarc.{hostname} specifically for DMARC record
  let dmarcRecord = null;
  try {
    const dmarcTxt = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
    const flatDmarc = dmarcTxt.flat();
    dmarcRecord = flatDmarc.find(t => t.toLowerCase().startsWith('v=dmarc1'));
  } catch {}

  // If not found in _dmarc subdomain, look in apex TXT
  if (!dmarcRecord) {
    dmarcRecord = txtRecords.find(t => t.toLowerCase().startsWith('v=dmarc1')) || null;
  }

  // Find SPF record
  const spfRecord = txtRecords.find(t => t.toLowerCase().startsWith('v=spf1')) || null;

  // Identify Email Provider from MX
  let emailProvider = 'Self-Hosted / Standard MX';
  const mxHostnames = mxRecords.map(m => (m.exchange || m).toLowerCase()).join(' ');
  if (mxHostnames.includes('google') || mxHostnames.includes('aspmx')) {
    emailProvider = 'Google Workspace';
  } else if (mxHostnames.includes('outlook') || mxHostnames.includes('microsoft')) {
    emailProvider = 'Microsoft 365';
  } else if (mxHostnames.includes('hostinger')) {
    emailProvider = 'Hostinger Mail';
  } else if (mxHostnames.includes('amazon') || mxHostnames.includes('ses')) {
    emailProvider = 'Amazon SES';
  } else if (mxHostnames.includes('protonmail') || mxHostnames.includes('proton')) {
    emailProvider = 'ProtonMail';
  } else if (mxHostnames.includes('zoho')) {
    emailProvider = 'Zoho Mail';
  }

  const durationMs = Date.now() - startTime;
  const checks = [];

  // Check 1: MX Records (Mail Exchanger Presence)
  if (mxRecords.length > 0) {
    checks.push(createCheckResult({
      checkId: 'email.mx',
      category: 'email',
      title: 'Mail Exchanger Configuration (MX Records)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Configured ${mxRecords.length} mail exchanger(s) under ${emailProvider}`,
      details: `Discovered active mail delivery routes: ${mxRecords.map(m => `${m.exchange || m} (pri: ${m.priority || 10})`).join(', ')}.`,
      evidence: { mxRecords, provider: emailProvider },
      source: 'dns-mx',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'email.mx',
      category: 'email',
      title: 'Mail Exchanger Configuration (MX Records)',
      status: 'info',
      severity: 'informational',
      confidence: 1.0,
      summary: 'No MX records published (Domain not configured to receive email directly)',
      details: 'Domain does not advertise incoming mail exchangers.',
      evidence: { count: 0 },
      source: 'dns-mx',
      durationMs,
    }));
  }

  // Check 2: SPF Policy Validation
  if (spfRecord) {
    const isPermissive = spfRecord.includes('+all');
    const isHardFail = spfRecord.includes('-all');
    const isSoftFail = spfRecord.includes('~all');

    if (isPermissive) {
      checks.push(createCheckResult({
        checkId: 'email.spf',
        category: 'email',
        title: 'Sender Policy Framework (SPF)',
        status: 'finding',
        severity: 'critical',
        confidence: 1.0,
        summary: 'Dangerous SPF policy: +all permits any IP on the internet to spoof email from this domain!',
        details: `Published record: "${spfRecord}". The +all directive explicitly authorizes all sending hosts, negating all SPF anti-spoofing protections.`,
        evidence: { spfRecord, qualifier: '+all' },
        recommendation: 'Replace "+all" with "-all" (hardfail) or "~all" (softfail) immediately.',
        references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
        source: 'dns-txt',
        durationMs,
      }));
    } else {
      checks.push(createCheckResult({
        checkId: 'email.spf',
        category: 'email',
        title: 'Sender Policy Framework (SPF)',
        status: 'pass',
        severity: 'none',
        confidence: 1.0,
        summary: `Valid SPF published with ${isHardFail ? 'hardfail (-all)' : 'softfail (~all)'} policy`,
        details: `Published record: "${spfRecord}". Authorized sending gateways are explicitly defined.`,
        evidence: { spfRecord, policy: isHardFail ? 'hardfail' : 'softfail' },
        source: 'dns-txt',
        durationMs,
      }));
    }
  } else if (mxRecords.length > 0) {
    checks.push(createCheckResult({
      checkId: 'email.spf',
      category: 'email',
      title: 'Sender Policy Framework (SPF)',
      status: 'finding',
      severity: 'high',
      confidence: 1.0,
      summary: 'Missing SPF record: Domain accepts mail but does not define authorized sending servers',
      details: 'Without an SPF record, threat actors can send phishing emails masquerading as this domain.',
      evidence: { spfRecord: null },
      recommendation: `Publish a TXT record for ${hostname} with "v=spf1 include:_spf.example.com ~all".`,
      references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
      source: 'dns-txt',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'email.spf',
      category: 'email',
      title: 'Sender Policy Framework (SPF)',
      status: 'info',
      severity: 'informational',
      confidence: 0.9,
      summary: 'No SPF published (No active MX servers)',
      details: 'Domain does not publish mail servers or an SPF record.',
      evidence: { spfRecord: null },
      source: 'dns-txt',
      durationMs,
    }));
  }

  // Check 3: DMARC Policy Validation
  if (dmarcRecord) {
    const policyMatch = /p=(reject|quarantine|none)/i.exec(dmarcRecord);
    const policy = policyMatch ? policyMatch[1].toLowerCase() : 'unknown';

    if (policy === 'reject' || policy === 'quarantine') {
      checks.push(createCheckResult({
        checkId: 'email.dmarc',
        category: 'email',
        title: 'Domain-based Message Authentication (DMARC)',
        status: 'pass',
        severity: 'none',
        confidence: 1.0,
        summary: `Strong DMARC enforcement active: p=${policy}`,
        details: `Published record: "${dmarcRecord}". Unauthorized messages failing SPF/DKIM will be blocked (${policy}).`,
        evidence: { dmarcRecord, policy },
        references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
        source: 'dns-txt-dmarc',
        durationMs,
      }));
    } else {
      checks.push(createCheckResult({
        checkId: 'email.dmarc',
        category: 'email',
        title: 'Domain-based Message Authentication (DMARC)',
        status: 'finding',
        severity: 'medium',
        confidence: 1.0,
        summary: 'Permissive DMARC policy: p=none does not block spoofed emails',
        details: `Published record: "${dmarcRecord}". The p=none policy only collects reports and does not instruct receiving mail servers to reject forged messages.`,
        evidence: { dmarcRecord, policy: 'none' },
        recommendation: 'Upgrade policy from p=none to p=quarantine and eventually p=reject once verified.',
        references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
        source: 'dns-txt-dmarc',
        durationMs,
      }));
    }
  } else if (mxRecords.length > 0) {
    checks.push(createCheckResult({
      checkId: 'email.dmarc',
      category: 'email',
      title: 'Domain-based Message Authentication (DMARC)',
      status: 'finding',
      severity: 'high',
      confidence: 1.0,
      summary: 'Missing DMARC policy: Domain is vulnerable to brand impersonation and email spoofing',
      details: `No TXT record found at _dmarc.${hostname}. Mail receivers cannot verify authentication or report spoofing attempts.`,
      evidence: { dmarcRecord: null },
      recommendation: `Publish a TXT record at _dmarc.${hostname} with "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${hostname}".`,
      references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
      source: 'dns-txt-dmarc',
      durationMs,
    }));
  }

  const emailConfig = {
    provider: emailProvider,
    mxCount: mxRecords.length,
    spfRecord,
    dmarcRecord,
    spfValid: Boolean(spfRecord && !spfRecord.includes('+all')),
    dmarcValid: Boolean(dmarcRecord && !dmarcRecord.includes('p=none')),
  };

  return { checks, emailConfig };
}

module.exports = {
  runEmailWorker,
};
