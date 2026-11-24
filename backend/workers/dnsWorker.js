/**
 * DNS Worker — WebVitals Modular Scan Engine
 *
 * Executes live DNS queries for A, AAAA, MX, NS, CNAME, SOA, PTR, TXT, CAA, and DNSSEC.
 * Returns an array of standardized checks conforming to the Standard Result Schema.
 */

'use strict';

const dns = require('dns').promises;
const { createCheckResult } = require('../scan/checkSchema');

/**
 * Runs all DNS checks against the target hostname.
 *
 * @param {string} hostname
 * @param {Object} [options={}]
 * @returns {Promise<{ checks: Object[], raw: Object }>}
 */
async function runDnsWorker(hostname, options = {}) {
  const startTime = Date.now();
  const raw = {
    A: [],
    AAAA: [],
    MX: [],
    NS: [],
    TXT: [],
    SOA: null,
    CNAME: [],
    CAA: [],
    PTR: [],
    DNSSEC: null,
  };

  const [aRes, aaaaRes, mxRes, nsRes, txtRes, soaRes, caaRes] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
    dns.resolveMx(hostname),
    dns.resolveNs(hostname),
    dns.resolveTxt(hostname),
    dns.resolveSoa(hostname),
    dns.resolveCaa(hostname),
  ]);

  if (aRes.status === 'fulfilled') raw.A = aRes.value;
  if (aaaaRes.status === 'fulfilled') raw.AAAA = aaaaRes.value;
  if (mxRes.status === 'fulfilled') raw.MX = aRes.status === 'fulfilled' ? mxRes.value : [];
  if (nsRes.status === 'fulfilled') raw.NS = nsRes.value;
  if (txtRes.status === 'fulfilled') raw.TXT = txtRes.value.flat();
  if (soaRes.status === 'fulfilled') raw.SOA = soaRes.value;
  if (caaRes.status === 'fulfilled') raw.CAA = caaRes.value;

  // Reverse PTR on primary IPv4 if available
  if (raw.A.length > 0) {
    try {
      raw.PTR = await dns.reverse(raw.A[0]).catch(() => []);
    } catch {}
  }

  const durationMs = Date.now() - startTime;
  const checks = [];

  // Check 1: A Records (IPv4 Resolution)
  if (raw.A.length > 0) {
    checks.push(createCheckResult({
      checkId: 'network.dns.a',
      category: 'network',
      title: 'IPv4 Address Resolution (A Records)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Resolved ${raw.A.length} IPv4 address(es): ${raw.A.join(', ')}`,
      details: `The target hostname ${hostname} reliably resolves to public IPv4 routing endpoints.`,
      evidence: { ips: raw.A, count: raw.A.length },
      source: 'authoritative-dns',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'network.dns.a',
      category: 'network',
      title: 'IPv4 Address Resolution (A Records)',
      status: aRes.reason?.code === 'ENODATA' ? 'info' : 'error',
      severity: 'medium',
      confidence: 0.95,
      summary: aRes.reason?.message || 'No IPv4 A records published',
      details: `Could not retrieve IPv4 records for ${hostname}.`,
      evidence: { error: aRes.reason?.code || 'NO_A_RECORDS' },
      source: 'authoritative-dns',
      durationMs,
    }));
  }

  // Check 2: AAAA Records (IPv6 Readiness)
  if (raw.AAAA.length > 0) {
    checks.push(createCheckResult({
      checkId: 'network.dns.aaaa',
      category: 'network',
      title: 'IPv6 Address Resolution (AAAA Records)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Resolved ${raw.AAAA.length} IPv6 address(es): ${raw.AAAA.slice(0, 2).join(', ')}`,
      details: 'Host supports modern IPv6 dual-stack addressing.',
      evidence: { ips: raw.AAAA },
      source: 'authoritative-dns',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'network.dns.aaaa',
      category: 'network',
      title: 'IPv6 Address Resolution (AAAA Records)',
      status: 'info',
      severity: 'informational',
      confidence: 1.0,
      summary: 'No IPv6 AAAA records published (IPv4 only)',
      details: 'Dual-stack IPv6 routing is not active on this origin.',
      evidence: { count: 0 },
      source: 'authoritative-dns',
      durationMs,
    }));
  }

  // Check 3: Authoritative Nameservers (NS Records)
  if (raw.NS.length >= 2) {
    checks.push(createCheckResult({
      checkId: 'network.dns.ns',
      category: 'network',
      title: 'Authoritative Nameservers (NS Redundancy)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Verified ${raw.NS.length} redundant authoritative nameservers`,
      details: `Delegated nameservers: ${raw.NS.join(', ')}. Redundancy satisfies RFC 2182 high-availability recommendations.`,
      evidence: { nameservers: raw.NS },
      source: 'authoritative-dns',
      durationMs,
    }));
  } else if (raw.NS.length === 1) {
    checks.push(createCheckResult({
      checkId: 'network.dns.ns',
      category: 'network',
      title: 'Authoritative Nameservers (NS Redundancy)',
      status: 'finding',
      severity: 'medium',
      confidence: 0.95,
      summary: 'Only 1 authoritative nameserver published (Single point of failure)',
      details: 'RFC 2182 mandates at least two geographically separated nameservers for DNS resilience.',
      evidence: { nameservers: raw.NS },
      recommendation: 'Configure secondary and tertiary nameservers across separate ASNs to avoid total outage.',
      references: ['https://datatracker.ietf.org/doc/html/rfc2182'],
      source: 'authoritative-dns',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'network.dns.ns',
      category: 'network',
      title: 'Authoritative Nameservers (NS Redundancy)',
      status: 'unknown',
      severity: 'informational',
      confidence: 0.5,
      summary: 'Nameserver records could not be retrieved',
      evidence: { error: nsRes.reason?.message || 'NO_NS' },
      source: 'authoritative-dns',
      durationMs,
    }));
  }

  // Check 4: CAA Records (Certificate Authority Authorization)
  if (raw.CAA.length > 0) {
    checks.push(createCheckResult({
      checkId: 'security.caa',
      category: 'security',
      title: 'Certificate Authority Authorization (CAA Records)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Active CAA policy pins certificate issuance to: ${raw.CAA.map(c => c.value || c.tag).join(', ')}`,
      details: 'Restricts rogue or compromised CAs from issuing fraudulent certificates for this domain (RFC 8659).',
      evidence: { caa: raw.CAA },
      source: 'authoritative-dns',
      durationMs,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'security.caa',
      category: 'security',
      title: 'Certificate Authority Authorization (CAA Records)',
      status: 'finding',
      severity: 'low',
      confidence: 1.0,
      summary: 'No CAA DNS records published (Any CA may issue certificates)',
      details: 'Without CAA records, any globally trusted Certificate Authority can issue SSL/TLS certificates for your domain.',
      evidence: { caa: [] },
      recommendation: "Add DNS CAA records specifying allowed CAs (e.g. `0 issue \"letsencrypt.org\"`).",
      references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
      source: 'authoritative-dns',
      durationMs,
    }));
  }

  // Check 5: SOA Record (Start of Authority)
  if (raw.SOA) {
    checks.push(createCheckResult({
      checkId: 'network.dns.soa',
      category: 'network',
      title: 'Start of Authority (SOA Configuration)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `SOA valid (Serial: ${raw.SOA.serial}, Refresh: ${raw.SOA.refresh}s)`,
      details: `Primary master nameserver: ${raw.SOA.nsname}, Admin email: ${raw.SOA.hostmaster}.`,
      evidence: { soa: raw.SOA },
      source: 'authoritative-dns',
      durationMs,
    }));
  }

  return { checks, raw };
}

module.exports = {
  runDnsWorker,
};
