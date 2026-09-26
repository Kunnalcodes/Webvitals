/**
 * DNS Security Telemetry Collector — Phase 3
 * WebVitals
 *
 * Direct DNS resolution via Node.js native `dns.promises`.
 * Analyzes SPF records (qualifiers, multiple records, mechanisms),
 * DMARC policy (_dmarc.<domain>), CAA authority restrictions, and MX/NS posture.
 */

'use strict';

const dns = require('dns').promises;

/**
 * Parses an SPF TXT string into structured mechanisms and policy.
 *
 * @param {string} spfText
 * @returns {object}
 */
function parseSpfRecord(spfText) {
  const parts = spfText.trim().split(/\s+/);
  const mechanisms = [];
  let policy = 'NEUTRAL'; // default if unspecified
  let rawPolicy = '?all';

  for (const part of parts) {
    if (part.toLowerCase().startsWith('v=spf1')) continue;

    const lower = part.toLowerCase();
    if (lower === '-all') {
      policy = 'HARD_FAIL';
      rawPolicy = '-all';
    } else if (lower === '~all') {
      policy = 'SOFT_FAIL';
      rawPolicy = '~all';
    } else if (lower === '?all') {
      policy = 'NEUTRAL';
      rawPolicy = '?all';
    } else if (lower === '+all' || lower === 'all') {
      policy = 'PASS_ALL_PERMISSIVE'; // dangerous
      rawPolicy = '+all';
    } else {
      mechanisms.push(part);
    }
  }

  return {
    raw: spfText,
    policy,
    rawPolicy,
    mechanisms,
    includesCount: mechanisms.filter((m) => m.toLowerCase().startsWith('include:')).length,
  };
}

/**
 * Parses a DMARC TXT record into structured tags.
 *
 * @param {string} dmarcText
 * @returns {object}
 */
function parseDmarcRecord(dmarcText) {
  const tags = {};
  const pairs = dmarcText.split(';').map((s) => s.trim()).filter(Boolean);

  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx > 0) {
      const k = pair.slice(0, eqIdx).trim().toLowerCase();
      const v = pair.slice(eqIdx + 1).trim();
      tags[k] = v;
    }
  }

  const rawPolicy = (tags['p'] || 'missing').toLowerCase();
  let policy = 'MISSING';
  if (rawPolicy === 'reject') policy = 'REJECT';
  else if (rawPolicy === 'quarantine') policy = 'QUARANTINE';
  else if (rawPolicy === 'none') policy = 'MONITORING_NONE';

  return {
    raw: dmarcText,
    policy,
    rawPolicy,
    subdomainPolicy: tags['sp'] || null,
    percentage: parseInt(tags['pct'] || '100', 10),
    reportUriAggregate: tags['rua'] || null,
    reportUriForensic: tags['ruf'] || null,
    alignmentDkim: tags['adkim'] || 'r',
    alignmentSpf: tags['aspf'] || 'r',
    tags,
  };
}

/**
 * Collects complete live DNS security telemetry for a hostname.
 *
 * @param {string} domain - Domain name (e.g. 'example.com')
 * @returns {Promise<object>}
 */
async function collectDnsTelemetry(domain) {
  const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  const results = {
    domain: cleanDomain,
    records: {
      a: [],
      aaaa: [],
      txt: [],
      caa: [],
      mx: [],
      ns: [],
    },
    spf: {
      present: false,
      hasMultiple: false,
      records: [],
      primary: null,
    },
    dmarc: {
      present: false,
      record: null,
      parsed: null,
    },
    caa: {
      present: false,
      records: [],
      authorities: [],
    },
    dkim: {
      status: 'NOT_EVALUATED',
      reason: 'DKIM evaluation requires specific selector names which cannot be enumerated via unauthenticated remote queries.',
    },
    dnssec: {
      status: 'NOT_EVALUATED',
      reason: 'Native Node.js DNS stub resolver does not expose DO (DNSSEC OK) validation flags directly.',
    },
    errors: [],
  };

  // 1. Fetch TXT records (for SPF & general domain records)
  try {
    const rawTxt = await dns.resolveTxt(cleanDomain);
    const flattenedTxt = rawTxt.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
    results.records.txt = flattenedTxt;

    const spfRecords = flattenedTxt.filter((t) => t.trim().toLowerCase().startsWith('v=spf1'));
    if (spfRecords.length > 0) {
      results.spf.present = true;
      results.spf.hasMultiple = spfRecords.length > 1;
      results.spf.records = spfRecords.map(parseSpfRecord);
      results.spf.primary = results.spf.records[0];
    }
  } catch (err) {
    if (err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
      results.errors.push(`TXT query error: ${err.message}`);
    }
  }

  // 2. Fetch DMARC record (_dmarc.domain)
  try {
    const dmarcHost = `_dmarc.${cleanDomain}`;
    const rawDmarc = await dns.resolveTxt(dmarcHost);
    const flattenedDmarc = rawDmarc.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
    const dmarcRecord = flattenedDmarc.find((t) => t.trim().toLowerCase().startsWith('v=dmarc1'));

    if (dmarcRecord) {
      results.dmarc.present = true;
      results.dmarc.record = dmarcRecord;
      results.dmarc.parsed = parseDmarcRecord(dmarcRecord);
    }
  } catch (err) {
    if (err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
      results.errors.push(`DMARC query error: ${err.message}`);
    }
  }

  // 3. Fetch CAA records
  try {
    const caa = await dns.resolveCaa(cleanDomain);
    if (Array.isArray(caa) && caa.length > 0) {
      results.records.caa = caa;
      results.caa.present = true;
      results.caa.records = caa;
      results.caa.authorities = caa
        .filter((c) => c.issue || c.issuewild)
        .map((c) => c.issue || c.issuewild);
    }
  } catch (err) {
    if (err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
      results.errors.push(`CAA query error: ${err.message}`);
    }
  }

  // 4. Fetch MX records
  try {
    const mx = await dns.resolveMx(cleanDomain);
    results.records.mx = Array.isArray(mx) ? mx : [];
  } catch (err) {
    if (err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
      results.errors.push(`MX query error: ${err.message}`);
    }
  }

  // 5. Fetch NS records
  try {
    const ns = await dns.resolveNs(cleanDomain);
    results.records.ns = Array.isArray(ns) ? ns : [];
  } catch (err) {
    if (err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
      results.errors.push(`NS query error: ${err.message}`);
    }
  }

  return results;
}

module.exports = {
  collectDnsTelemetry,
  parseSpfRecord,
  parseDmarcRecord,
};
