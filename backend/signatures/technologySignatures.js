/**
 * Technology Signatures & Fingerprinting — Phase 3
 * WebVitals
 *
 * Evidence-backed technology detection based on live headers, cookies, and HTML structures.
 */

'use strict';

const { EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence } = require('../evidence/evidenceModel');

const TECH_SIGNATURES = [
  {
    name: 'Next.js',
    category: 'Framework',
    match: (headers, html) => {
      const hasNextData = html && html.includes('__NEXT_DATA__');
      const hasNextStatic = html && html.includes('/_next/static');
      const hasNextHeader = headers['x-powered-by']?.includes('Next.js');
      if (hasNextData || hasNextStatic || hasNextHeader) {
        return {
          matched: true,
          confidence: hasNextData && hasNextStatic ? 0.98 : 0.90,
          evidence: hasNextData ? 'Observed __NEXT_DATA__ hydration block' : 'Detected /_next/static asset path',
        };
      }
      return { matched: false };
    },
  },
  {
    name: 'React',
    category: 'Library',
    match: (headers, html) => {
      const hasReactRoot = html && (html.includes('data-reactroot') || html.includes('react-dom') || html.includes('_reactRootContainer'));
      if (hasReactRoot) {
        return { matched: true, confidence: 0.95, evidence: 'Observed React DOM root markers' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Cloudflare',
    category: 'CDN / Security',
    match: (headers) => {
      const hasCfRay = Boolean(headers['cf-ray']);
      const isCfServer = (headers['server'] || '').toLowerCase().includes('cloudflare');
      if (hasCfRay || isCfServer) {
        return {
          matched: true,
          confidence: hasCfRay && isCfServer ? 0.99 : 0.95,
          evidence: hasCfRay ? `Observed CF-Ray: ${headers['cf-ray']}` : 'Observed Server: cloudflare',
        };
      }
      return { matched: false };
    },
  },
  {
    name: 'Nginx',
    category: 'Web Server',
    match: (headers) => {
      const server = (headers['server'] || '').toLowerCase();
      if (server.includes('nginx')) {
        return { matched: true, confidence: 0.95, evidence: `Observed Server header: ${headers['server']}` };
      }
      return { matched: false };
    },
  },
  {
    name: 'Apache',
    category: 'Web Server',
    match: (headers) => {
      const server = (headers['server'] || '').toLowerCase();
      if (server.includes('apache')) {
        return { matched: true, confidence: 0.95, evidence: `Observed Server header: ${headers['server']}` };
      }
      return { matched: false };
    },
  },
  {
    name: 'Express',
    category: 'Backend Framework',
    match: (headers) => {
      const poweredBy = (headers['x-powered-by'] || '').toLowerCase();
      if (poweredBy.includes('express')) {
        return { matched: true, confidence: 0.95, evidence: 'Observed X-Powered-By: Express' };
      }
      return { matched: false };
    },
  },
  {
    name: 'WordPress',
    category: 'CMS',
    match: (headers, html) => {
      const hasWpContent = html && (html.includes('/wp-content/') || html.includes('/wp-includes/'));
      const hasWpGen = html && /<meta name="generator" content="WordPress/i.test(html);
      if (hasWpContent || hasWpGen) {
        return {
          matched: true,
          confidence: hasWpGen ? 0.99 : 0.90,
          evidence: hasWpGen ? 'Observed WordPress generator meta tag' : 'Detected /wp-content/ directory structure',
        };
      }
      return { matched: false };
    },
  },
];

/**
 * Fingerprints technologies from observed response headers and HTML body.
 *
 * @param {Record<string, string>} headers
 * @param {string} html
 * @returns {Array<{ name: string, category: string, confidence: number, evidence: string }>}
 */
function detectTechnologies(headers = {}, html = '') {
  const detected = [];
  for (const sig of TECH_SIGNATURES) {
    const res = sig.match(headers, html);
    if (res.matched) {
      detected.push({
        name: sig.name,
        category: sig.category,
        confidence: res.confidence,
        evidence: res.evidence,
      });
    }
  }
  return detected;
}

module.exports = {
  detectTechnologies,
  TECH_SIGNATURES,
};
