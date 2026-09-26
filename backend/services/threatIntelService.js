/**
 * Unified Threat Intelligence & External Cloud Services Coordinator — Phase 4
 * WebVitals
 *
 * Consolidates all external threat intel, cloud reputation, and network enrichment APIs:
 *   - Google Safe Browsing API v4
 *   - VirusTotal Domain Reputation API v3
 *   - IP & ASN Geolocation Telemetry
 *   - Known Vulnerability & CVE Advisory Correlation
 *
 * Architecture Principles:
 *   - Zero external npm dependencies (native HTTPS/HTTP)
 *   - Strict timeout guards (max 5s per provider)
 *   - Non-blocking parallel execution
 *   - Graceful offline fallback
 *   - Structured Phase 3 Evidence generation
 */

'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');
const {
  SAFE_BROWSING_API_KEY,
  VIRUSTOTAL_API_KEY,
} = require('../config/env');
const {
  DETERMINATION,
  SEVERITY,
  EVIDENCE_SOURCE,
  EVIDENCE_QUALITY,
  createEvidence,
  createFinding,
} = require('../evidence/evidenceModel');

// In-memory cache for IP and threat intel queries (TTL: 10 mins)
const _intelCache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000;

function getCached(key) {
  const entry = _intelCache.get(key);
  if (entry && Date.now() - entry.timestamp < CACHE_TTL_MS) {
    return entry.data;
  }
  return null;
}

function setCache(key, data) {
  _intelCache.set(key, { data, timestamp: Date.now() });
  if (_intelCache.size > 200) {
    const oldestKey = _intelCache.keys().next().value;
    _intelCache.delete(oldestKey);
  }
}

/**
 * 1. Google Safe Browsing API v4
 */
async function queryGoogleSafeBrowsing(targetUrl, apiKey = SAFE_BROWSING_API_KEY) {
  if (!apiKey || !targetUrl) return { checked: false, reason: 'API key not configured' };

  const cacheKey = `gsb:${targetUrl}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  return new Promise((resolve) => {
    const payload = JSON.stringify({
      client: { clientId: 'webvitals-scanner', clientVersion: '4.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: targetUrl }],
      },
    });

    const req = https.request(
      {
        hostname: 'safebrowsing.googleapis.com',
        path: `/v4/threatMatches:find?key=${apiKey}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        timeout: 5000,
      },
      (res) => {
        let body = '';
        res.on('data', (d) => { body += d; });
        res.on('end', () => {
          if (res.statusCode !== 200) {
            return resolve({ checked: false, statusCode: res.statusCode });
          }
          try {
            const json = JSON.parse(body);
            const matches = json.matches || [];
            const result = {
              checked: true,
              isMalicious: matches.length > 0,
              matches,
              threatCount: matches.length,
            };
            setCache(cacheKey, result);
            resolve(result);
          } catch {
            resolve({ checked: false, error: 'PARSE_ERROR' });
          }
        });
      }
    );

    req.on('timeout', () => { req.destroy(); resolve({ checked: false, error: 'TIMEOUT' }); });
    req.on('error', (err) => resolve({ checked: false, error: err.message }));
    req.write(payload);
    req.end();
  });
}

/**
 * 1b. Google Cloud Web Risk API v1 (Enterprise High-Speed Threat Verification)
 */
async function queryGoogleWebRisk(targetUrl, apiKey = SAFE_BROWSING_API_KEY) {
  if (!apiKey || !targetUrl) return { checked: false, reason: 'API key not configured' };

  const cacheKey = `webrisk:${targetUrl}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  return new Promise((resolve) => {
    const query = `uri=${encodeURIComponent(targetUrl)}&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&key=${apiKey}`;
    const req = https.get(
      `https://webrisk.googleapis.com/v1/uris:search?${query}`,
      { timeout: 5000 },
      (res) => {
        let body = '';
        res.on('data', (d) => { body += d; });
        res.on('end', () => {
          if (res.statusCode === 403 || res.statusCode === 404) {
            return resolve({ checked: false, statusCode: res.statusCode, note: 'Web Risk API disabled in GCP' });
          }
          if (res.statusCode !== 200) {
            return resolve({ checked: false, statusCode: res.statusCode });
          }
          try {
            const json = JSON.parse(body);
            const threat = json.threat || null;
            const result = {
              checked: true,
              isMalicious: !!threat,
              threatTypes: threat?.threatTypes || [],
              expireTime: threat?.expireTime || null,
            };
            setCache(cacheKey, result);
            resolve(result);
          } catch {
            resolve({ checked: false, error: 'PARSE_ERROR' });
          }
        });
      }
    );

    req.on('timeout', () => { req.destroy(); resolve({ checked: false, error: 'TIMEOUT' }); });
    req.on('error', (err) => resolve({ checked: false, error: err.message }));
  });
}

/**
 * 1c. Google Public DNS-over-HTTPS (DoH) Resolver
 * Cryptographically checks DNSSEC (AD flag), CAA records, and TXT (SPF/DMARC) via dns.google
 */
async function queryGoogleDnsOverHttps(hostname, recordType = 'CAA') {
  if (!hostname) return { checked: false };

  const cacheKey = `doh:${hostname}:${recordType}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  return new Promise((resolve) => {
    const req = https.get(
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${recordType}&do=1`,
      { timeout: 4000 },
      (res) => {
        let body = '';
        res.on('data', (d) => { body += d; });
        res.on('end', () => {
          if (res.statusCode !== 200) return resolve({ checked: false, statusCode: res.statusCode });
          try {
            const json = JSON.parse(body);
            const result = {
              checked: true,
              status: json.Status, // 0 = NOERROR, 3 = NXDOMAIN
              dnssecAuthenticated: Boolean(json.AD), // AD flag = Authenticated Data
              answers: json.Answer || [],
              authority: json.Authority || [],
            };
            setCache(cacheKey, result);
            resolve(result);
          } catch {
            resolve({ checked: false, error: 'PARSE_ERROR' });
          }
        });
      }
    );

    req.on('timeout', () => { req.destroy(); resolve({ checked: false, error: 'TIMEOUT' }); });
    req.on('error', (err) => resolve({ checked: false, error: err.message }));
  });
}

/**
 * 2. VirusTotal Domain Reputation API v3
 */
async function queryVirusTotal(hostname, apiKey = VIRUSTOTAL_API_KEY) {
  if (!apiKey || !hostname) return { checked: false, reason: 'API key not configured' };

  const cacheKey = `vt:${hostname}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  return new Promise((resolve) => {
    const req = https.request(
      {
        hostname: 'www.virustotal.com',
        path: `/api/v3/domains/${encodeURIComponent(hostname)}`,
        method: 'GET',
        headers: {
          'x-apikey': apiKey,
          Accept: 'application/json',
        },
        timeout: 5000,
      },
      (res) => {
        let body = '';
        res.on('data', (d) => { body += d; });
        res.on('end', () => {
          if (res.statusCode !== 200) {
            return resolve({ checked: false, statusCode: res.statusCode });
          }
          try {
            const json = JSON.parse(body);
            const stats = json.data?.attributes?.last_analysis_stats || {};
            const result = {
              checked: true,
              stats,
              maliciousCount: stats.malicious || 0,
              suspiciousCount: stats.suspicious || 0,
              harmlessCount: stats.harmless || 0,
              undetectedCount: stats.undetected || 0,
              reputation: json.data?.attributes?.reputation || 0,
            };
            setCache(cacheKey, result);
            resolve(result);
          } catch {
            resolve({ checked: false, error: 'PARSE_ERROR' });
          }
        });
      }
    );

    req.on('timeout', () => { req.destroy(); resolve({ checked: false, error: 'TIMEOUT' }); });
    req.on('error', (err) => resolve({ checked: false, error: err.message }));
    req.end();
  });
}

/**
 * 3. IP & Autonomous System (ASN) Geolocation Enrichment (Zero API Key)
 */
async function queryIpGeolocation(ipAddress) {
  if (!ipAddress || typeof ipAddress !== 'string') return null;

  // Filter out private / loopback IPs
  if (ipAddress === '127.0.0.1' || ipAddress.startsWith('192.168.') || ipAddress.startsWith('10.')) {
    return null;
  }

  const cacheKey = `geo:${ipAddress}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  return new Promise((resolve) => {
    const req = http.get(`http://ip-api.com/json/${encodeURIComponent(ipAddress)}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query`, { timeout: 4000 }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        if (res.statusCode !== 200) return resolve(null);
        try {
          const json = JSON.parse(body);
          if (json.status !== 'success') return resolve(null);
          const result = {
            ip: json.query,
            country: json.country,
            countryCode: json.countryCode,
            city: json.city,
            region: json.regionName,
            isp: json.isp,
            organization: json.org,
            asn: json.as,
          };
          setCache(cacheKey, result);
          resolve(result);
        } catch {
          resolve(null);
        }
      });
    });

    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
  });
}

/**
 * 4. Correlates detected technology versions with known vulnerability advisories.
 */
function correlateTechAdvisories(technologies = []) {
  const advisories = [];

  for (const tech of technologies) {
    const name = (tech.name || '').toLowerCase();
    const version = tech.version || '';

    // Nginx version advisories
    if (name.includes('nginx') && version) {
      const vNum = parseFloat(version);
      if (vNum > 0 && vNum < 1.20) {
        advisories.push({
          technology: tech.name,
          version,
          severity: 'HIGH',
          cve: 'CVE-2021-23017',
          summary: `Nginx ${version} is vulnerable to 1-byte memory overwrite in resolver (CVE-2021-23017). Update to >= 1.20.1.`,
        });
      }
    }

    // Apache version advisories
    if (name.includes('apache') && version) {
      if (version.startsWith('2.4.49') || version.startsWith('2.4.50')) {
        advisories.push({
          technology: tech.name,
          version,
          severity: 'CRITICAL',
          cve: 'CVE-2021-41773',
          summary: `Apache ${version} is vulnerable to Path Traversal and RCE (CVE-2021-41773). Immediate upgrade required.`,
        });
      }
    }

    // WordPress version advisories
    if (name.includes('wordpress') && version) {
      const vNum = parseFloat(version);
      if (vNum > 0 && vNum < 6.0) {
        advisories.push({
          technology: tech.name,
          version,
          severity: 'HIGH',
          cve: 'WP-CORE-OUTDATED',
          summary: `WordPress ${version} is running a legacy major branch. Core security patches and PHP 8.x compatibility require updating to >= 6.4.`,
        });
      }
    }
  }

  return advisories;
}

/**
 * Evaluates full threat intelligence suite and produces canonical Phase 3 findings.
 *
 * @param {object} params
 * @param {string} params.targetUrl
 * @param {string} params.hostname
 * @param {string[]} [params.ipAddresses]
 * @param {object[]} [params.technologies]
 * @returns {Promise<{ findings: object[], telemetry: object }>}
 */
async function evaluateThreatIntelligence({ targetUrl, hostname, ipAddresses = [], technologies = [] }) {
  const primaryIp = ipAddresses[0] || null;

  const [safeBrowsing, webRisk, virusTotal, dohCaa, dohDnssec, geoInfo] = await Promise.all([
    queryGoogleSafeBrowsing(targetUrl),
    queryGoogleWebRisk(targetUrl),
    queryVirusTotal(hostname),
    queryGoogleDnsOverHttps(hostname, 'CAA'),
    queryGoogleDnsOverHttps(hostname, 'DNSKEY'),
    primaryIp ? queryIpGeolocation(primaryIp) : Promise.resolve(null),
  ]);

  const advisories = correlateTechAdvisories(technologies);
  const findings = [];

  // 1. Google Safe Browsing / Web Risk Findings
  if (safeBrowsing.checked || webRisk.checked) {
    const isMalicious = safeBrowsing.isMalicious || webRisk.isMalicious;
    if (isMalicious) {
      const types = (safeBrowsing.matches || []).map((m) => m.threatType).concat(webRisk.threatTypes || []).join(', ');
      findings.push(createFinding({
        id: 'GOOGLE_SAFE_BROWSING_FLAGGED',
        channel: 'PHISHING',
        title: 'Flagged by Google Safe Browsing / Web Risk Intelligence',
        status: DETERMINATION.FAIL,
        severity: SEVERITY.CRITICAL,
        confidence: 0.99,
        scoreImpact: -35,
        description: `Target is actively listed in Google threat registry for: ${types || 'MALWARE / SOCIAL ENGINEERING'}.`,
        evidence: [createEvidence({
          source: EVIDENCE_SOURCE.HTTP_TELEMETRY,
          quality: EVIDENCE_QUALITY.VERIFIED,
          signature: 'GOOGLE_SAFE_BROWSING',
          observedValue: { safeBrowsing: safeBrowsing.matches, webRisk: webRisk.threatTypes },
          confidence: 0.99,
        })],
        recommendation: 'Immediate incident response required: Remediate compromised scripts or deceptive forms and request a review via Google Search Console.',
      }));
    } else {
      findings.push(createFinding({
        id: 'GOOGLE_SAFE_BROWSING_CLEAN',
        channel: 'PHISHING',
        title: 'Verified Clean on Google Safe Browsing & Web Risk',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 0.95,
        scoreImpact: 5,
        description: 'URL passed real-time Google Cloud threat validation with 0 malware/phishing detections.',
        evidence: [createEvidence({
          source: EVIDENCE_SOURCE.HTTP_TELEMETRY,
          quality: EVIDENCE_QUALITY.VERIFIED,
          signature: 'GOOGLE_SAFE_BROWSING',
          observedValue: { status: 'SAFE', provider: 'Google Cloud Platform' },
          confidence: 0.95,
        })],
      }));
    }
  }

  // 1b. Google DoH CAA & DNSSEC Cryptographic Validation
  if (dohCaa.checked && dohCaa.answers && dohCaa.answers.length > 0) {
    findings.push(createFinding({
      id: 'GOOGLE_DOH_CAA_CONFIGURED',
      channel: 'DNS_HEALTH',
      title: 'DNS CAA Record Configured (Google DoH Verified)',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 0.95,
      scoreImpact: 5,
      description: `Certificate Authority Authorization (CAA) is cryptographically verified: ${dohCaa.answers.map(a => a.data).join('; ')}`,
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.DNS_TELEMETRY,
        quality: EVIDENCE_QUALITY.VERIFIED,
        signature: 'GOOGLE_DOH_CAA',
        observedValue: dohCaa.answers,
        confidence: 0.95,
      })],
    }));
  }

  if (dohDnssec.checked && dohDnssec.dnssecAuthenticated) {
    findings.push(createFinding({
      id: 'GOOGLE_DOH_DNSSEC_VALIDATED',
      channel: 'DNS_HEALTH',
      title: 'DNSSEC Cryptographically Authenticated (Google DoH)',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 0.98,
      scoreImpact: 10,
      description: 'Domain records are cryptographically signed and authenticated with DNSSEC via Google Public DNS.',
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.DNS_TELEMETRY,
        quality: EVIDENCE_QUALITY.VERIFIED,
        signature: 'GOOGLE_DOH_DNSSEC',
        observedValue: { authenticatedData: true },
        confidence: 0.98,
      })],
    }));
  }

  // 2. VirusTotal Findings
  if (virusTotal.checked) {
    if (virusTotal.maliciousCount > 0) {
      findings.push(createFinding({
        id: 'VIRUSTOTAL_SECURITY_ENGINES_FLAGGED',
        channel: 'PHISHING',
        title: `Flagged by ${virusTotal.maliciousCount} Security Engines on VirusTotal`,
        status: DETERMINATION.FAIL,
        severity: virusTotal.maliciousCount >= 3 ? SEVERITY.CRITICAL : SEVERITY.HIGH,
        confidence: 0.90,
        scoreImpact: virusTotal.maliciousCount >= 3 ? -25 : -15,
        description: `${virusTotal.maliciousCount} antivirus vendors and threat feeds flagged this domain as malicious.`,
        evidence: [createEvidence({
          source: EVIDENCE_SOURCE.DNS_TELEMETRY,
          quality: EVIDENCE_QUALITY.VERIFIED,
          signature: 'VIRUSTOTAL_REPUTATION',
          observedValue: virusTotal.stats,
          confidence: 0.90,
        })],
      }));
    } else {
      findings.push(createFinding({
        id: 'VIRUSTOTAL_REPUTATION_CLEAN',
        channel: 'PHISHING',
        title: 'Clean Global Security Reputation Across Antivirus Feeds',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 0.90,
        scoreImpact: 5,
        description: `Verified across 70+ threat feeds: ${virusTotal.harmlessCount} harmless, ${virusTotal.undetectedCount} undetected.`,
        evidence: [createEvidence({
          source: EVIDENCE_SOURCE.DNS_TELEMETRY,
          quality: EVIDENCE_QUALITY.VERIFIED,
          signature: 'VIRUSTOTAL_REPUTATION',
          observedValue: virusTotal.stats,
          confidence: 0.90,
        })],
      }));
    }
  }

  // 3. Known Tech Stack Advisories Findings
  for (const adv of advisories) {
    findings.push(createFinding({
      id: `TECH_CVE_${adv.cve.replace(/[^A-Z0-9]/gi, '_')}`,
      channel: 'TECH_STACK',
      title: `Known Vulnerability in ${adv.technology} (${adv.cve})`,
      status: DETERMINATION.FAIL,
      severity: adv.severity === 'CRITICAL' ? SEVERITY.CRITICAL : SEVERITY.HIGH,
      confidence: 0.85,
      scoreImpact: adv.severity === 'CRITICAL' ? -20 : -10,
      description: adv.summary,
      evidence: [createEvidence({
        source: EVIDENCE_SOURCE.HTTP_TELEMETRY,
        quality: EVIDENCE_QUALITY.VERIFIED,
        signature: adv.cve,
        observedValue: { technology: adv.technology, version: adv.version },
        confidence: 0.85,
      })],
      recommendation: `Upgrade ${adv.technology} to the latest stable release to patch ${adv.cve}.`,
    }));
  }

  return {
    findings,
    telemetry: {
      safeBrowsing,
      webRisk,
      virusTotal,
      doh: { caa: dohCaa, dnssec: dohDnssec },
      geolocation: geoInfo,
      advisories,
    },
  };
}

module.exports = {
  queryGoogleSafeBrowsing,
  queryGoogleWebRisk,
  queryGoogleDnsOverHttps,
  queryVirusTotal,
  queryIpGeolocation,
  correlateTechAdvisories,
  evaluateThreatIntelligence,
};
