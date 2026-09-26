/**
 * Phishing & Homograph Heuristic Analyzer — Phase 3
 * WebVitals
 *
 * Multi-signal URL structure analyzer with false-positive suppression:
 *   - Shannon entropy analysis of hostname
 *   - Punycode / IDN homograph checks (xn--)
 *   - Subdomain depth and hyphen frequency
 *   - Brand imitation detection (without penalizing legitimate login.* subdomains)
 *   - Explicit uncertainty declaration & conservative confidence
 */

'use strict';

const { URL } = require('url');
const { DETERMINATION, SEVERITY, EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence, createFinding } = require('../evidence/evidenceModel');

/**
 * Calculates Shannon entropy of a string (measures randomness/obfuscation).
 * @param {string} str
 * @returns {number}
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

// Common legitimate brand apex domains
const TRUSTED_APEX_DOMAINS = [
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'github.com', 'paypal.com', 'cloudflare.com', 'mozilla.org',
];

/**
 * Analyzes URL and hostname structure for phishing and lookalike indicators.
 *
 * @param {URL|string} urlInput
 * @param {string} [originalRawInput]
 * @returns {import('../evidence/evidenceModel').SecurityFinding[]}
 */
function analyzePhishingHeuristics(urlInput, originalRawInput = '') {
  const findings = [];
  const urlObj = typeof urlInput === 'string' ? new URL(urlInput) : urlInput;
  const hostname = urlObj.hostname.toLowerCase();

  const signals = [];
  let riskScore = 0; // 0 = low risk, higher = suspicious

  // 1. IP Address Host
  const isRawIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith('[');
  if (isRawIp) {
    signals.push('Hostname is a raw IP address instead of a registered domain name');
    riskScore += 3;
  }

  // 2. Punycode / IDN
  const hasPunycode = hostname.includes('xn--');
  if (hasPunycode) {
    signals.push('Punycode / IDN detected (xn--) — possible Unicode homograph lookalike');
    riskScore += 3;
  }

  // 3. Userinfo / Embedded Credentials in URL
  if (originalRawInput && originalRawInput.includes('@')) {
    signals.push('URL contains "@" character which can conceal the true destination host');
    riskScore += 4;
  }

  // 4. Subdomain Depth & Entropy
  const domainParts = hostname.split('.');
  const subdomainCount = Math.max(0, domainParts.length - 2);
  const entropy = calculateShannonEntropy(hostname);

  if (subdomainCount >= 4) {
    signals.push(`Excessive subdomain nesting depth (${subdomainCount} subdomains)`);
    riskScore += 2;
  }

  if (entropy > 3.8 && hostname.length > 20) {
    signals.push(`High hostname Shannon entropy (${entropy}), suggesting randomized/DGA domain`);
    riskScore += 2;
  }

  // 5. Hyphen Density
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    signals.push(`High number of hyphens in hostname (${hyphenCount} hyphens)`);
    riskScore += 2;
  }

  // 6. Sensitive Keyword / Brand Imitation Check (with legitimate apex exception)
  const isTrustedApex = TRUSTED_APEX_DOMAINS.some((apex) => hostname === apex || hostname.endsWith(`.${apex}`));
  const sensitiveKeywords = ['login', 'verify', 'update', 'banking', 'secure', 'signin', 'wallet', 'password', 'support', 'auth'];

  if (!isTrustedApex) {
    const hits = sensitiveKeywords.filter((k) => hostname.includes(k));
    if (hits.length > 0 && hyphenCount > 1) {
      signals.push(`Suspicious combination of sensitive keyword(s) [${hits.join(', ')}] with hyphenation in unregistered domain`);
      riskScore += 3;
    }
  }

  const evidence = createEvidence({
    source: EVIDENCE_SOURCE.HEURISTIC,
    quality: EVIDENCE_QUALITY.HEURISTIC,
    observedValue: {
      hostname,
      isRawIp,
      hasPunycode,
      entropy,
      subdomainCount,
      hyphenCount,
      signals,
    },
    confidence: 0.75, // Explicitly bounded heuristic confidence
  });

  if (riskScore >= 6) {
    findings.push(createFinding({
      id: 'PHISHING_HEURISTIC_HIGH_RISK',
      channel: 'PHISHING',
      title: 'High Risk URL Structural Indicators Detected',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.HIGH,
      confidence: 0.75,
      scoreImpact: -10,
      description: `URL structure displays multiple high-risk anomalies: ${signals.join('; ')}.`,
      evidence: [evidence],
      recommendation: 'Verify domain ownership and reputation before entering credentials or interacting with this site.',
      limitations: ['Structural heuristics indicate anomaly likelihood; they do not constitute definitive proof of malicious intent.'],
    }));
  } else if (riskScore >= 3) {
    findings.push(createFinding({
      id: 'PHISHING_HEURISTIC_SUSPICIOUS',
      channel: 'PHISHING',
      title: 'Suspicious URL Structure Characteristics',
      status: DETERMINATION.WARNING,
      severity: SEVERITY.LOW,
      confidence: 0.70,
      scoreImpact: -3,
      description: `URL structure exhibits minor anomalies: ${signals.join('; ')}.`,
      evidence: [evidence],
      limitations: ['Heuristic observation only; some legitimate services use complex routing or hyphenated infrastructure.'],
    }));
  } else {
    findings.push(createFinding({
      id: 'PHISHING_HEURISTIC_CLEAN',
      channel: 'PHISHING',
      title: 'URL Structure Conforms to Standard Patterns',
      status: DETERMINATION.PASS,
      severity: SEVERITY.INFO,
      confidence: 0.85,
      scoreImpact: 5,
      description: 'No homograph (Punycode), DGA entropy, or deceptive URL structure anomalies were identified.',
      evidence: [evidence],
    }));
  }

  return findings;
}

const https = require('https');

/**
 * Queries Google Safe Browsing API v4 for real-time malware and social engineering listings.
 *
 * @param {string} targetUrl
 * @param {string} apiKey
 * @returns {Promise<object|null>}
 */
async function checkGoogleSafeBrowsing(targetUrl, apiKey) {
  if (!apiKey || !targetUrl) return null;

  return new Promise((resolve) => {
    const payload = JSON.stringify({
      client: { clientId: 'webvitals-security-platform', clientVersion: '4.0.0' },
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
        timeout: 6000,
      },
      (res) => {
        let body = '';
        res.on('data', (d) => { body += d; });
        res.on('end', () => {
          if (res.statusCode !== 200) return resolve(null);
          try {
            const json = JSON.parse(body);
            resolve({
              checked: true,
              matches: json.matches || [],
              isMalicious: (json.matches || []).length > 0,
            });
          } catch {
            resolve(null);
          }
        });
      }
    );

    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.write(payload);
    req.end();
  });
}

/**
 * Queries VirusTotal v3 domain reputation report.
 *
 * @param {string} hostname
 * @param {string} apiKey
 * @returns {Promise<object|null>}
 */
async function checkVirusTotal(hostname, apiKey) {
  if (!apiKey || !hostname) return null;

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
        timeout: 6000,
      },
      (res) => {
        let body = '';
        res.on('data', (d) => { body += d; });
        res.on('end', () => {
          if (res.statusCode !== 200) return resolve(null);
          try {
            const json = JSON.parse(body);
            const stats = json.data?.attributes?.last_analysis_stats || {};
            resolve({
              checked: true,
              stats,
              maliciousCount: stats.malicious || 0,
              suspiciousCount: stats.suspicious || 0,
              harmlessCount: stats.harmless || 0,
              undetectedCount: stats.undetected || 0,
            });
          } catch {
            resolve(null);
          }
        });
      }
    );

    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

/**
 * Combined structural heuristics and live Cloud Threat Intelligence evaluation.
 *
 * @param {URL|string} urlInput
 * @param {string} originalRawInput
 * @param {object} [options]
 * @returns {Promise<{ findings: import('../evidence/evidenceModel').SecurityFinding[], threatIntel: object }>}
 */
async function analyzePhishingAndThreatIntel(urlInput, originalRawInput = '', options = {}) {
  const urlObj = typeof urlInput === 'string' ? new URL(urlInput) : urlInput;
  const findings = analyzePhishingHeuristics(urlObj, originalRawInput);

  const safeBrowsingKey = options.safeBrowsingKey || null;
  const virusTotalKey = options.virusTotalKey || null;

  const [safeBrowsing, virusTotal] = await Promise.all([
    safeBrowsingKey ? checkGoogleSafeBrowsing(urlObj.toString(), safeBrowsingKey) : Promise.resolve(null),
    virusTotalKey ? checkVirusTotal(urlObj.hostname, virusTotalKey) : Promise.resolve(null),
  ]);

  // Evaluate Google Safe Browsing finding
  if (safeBrowsing && safeBrowsing.checked) {
    if (safeBrowsing.isMalicious) {
      const threatTypes = safeBrowsing.matches.map((m) => m.threatType).join(', ');
      findings.push(createFinding({
        id: 'GOOGLE_SAFE_BROWSING_FLAGGED',
        channel: 'PHISHING',
        title: 'Flagged on Google Safe Browsing Malicious Registry',
        status: DETERMINATION.FAIL,
        severity: SEVERITY.CRITICAL,
        confidence: 0.99,
        scoreImpact: -35,
        description: `Target URL is actively registered on Google Safe Browsing threat database (${threatTypes}).`,
        evidence: [createEvidence({
          source: EVIDENCE_SOURCE.HTTP_TELEMETRY,
          quality: EVIDENCE_QUALITY.VERIFIED,
          signature: 'GOOGLE_SAFE_BROWSING',
          observedValue: { matches: safeBrowsing.matches },
          confidence: 0.99,
        })],
        recommendation: 'Immediate incident response required: Remediate malware payload or deceptive phishing content and submit review request in Google Search Console.',
      }));
    } else {
      findings.push(createFinding({
        id: 'GOOGLE_SAFE_BROWSING_CLEAN',
        channel: 'PHISHING',
        title: 'Verified Clean on Google Safe Browsing Registry',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 0.95,
        scoreImpact: 5,
        description: 'Target URL is clean and not listed in Google Safe Browsing threat databases.',
        evidence: [createEvidence({
          source: EVIDENCE_SOURCE.HTTP_TELEMETRY,
          quality: EVIDENCE_QUALITY.VERIFIED,
          signature: 'GOOGLE_SAFE_BROWSING',
          observedValue: { status: 'SAFE' },
          confidence: 0.95,
        })],
      }));
    }
  }

  // Evaluate VirusTotal finding
  if (virusTotal && virusTotal.checked) {
    if (virusTotal.maliciousCount > 0) {
      findings.push(createFinding({
        id: 'VIRUSTOTAL_SECURITY_ENGINES_FLAGGED',
        channel: 'PHISHING',
        title: `Flagged by ${virusTotal.maliciousCount} Security Engines on VirusTotal`,
        status: DETERMINATION.FAIL,
        severity: virusTotal.maliciousCount >= 3 ? SEVERITY.CRITICAL : SEVERITY.HIGH,
        confidence: 0.90,
        scoreImpact: virusTotal.maliciousCount >= 3 ? -25 : -15,
        description: `${virusTotal.maliciousCount} antivirus and security reputation engines flagged this domain as malicious.`,
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
        title: 'Clean Threat Reputation Across Global Security Engines',
        status: DETERMINATION.PASS,
        severity: SEVERITY.INFO,
        confidence: 0.90,
        scoreImpact: 5,
        description: `No security engines on VirusTotal flagged this domain as malicious (${virusTotal.harmlessCount} harmless, ${virusTotal.undetectedCount} undetected).`,
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

  return {
    findings,
    threatIntel: {
      safeBrowsing: safeBrowsing || { checked: false },
      virusTotal: virusTotal || { checked: false },
    },
  };
}

module.exports = {
  analyzePhishingHeuristics,
  analyzePhishingAndThreatIntel,
  checkGoogleSafeBrowsing,
  checkVirusTotal,
  calculateShannonEntropy,
};
