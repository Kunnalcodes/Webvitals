/**
 * Remediation Engine & Multi-Stack Coordinator — Phase 4
 * WebVitals
 *
 * Deterministic-first remediation coordinator that matches findings and verified
 * technology stacks (Nginx, Apache, Node, Next.js, Caddy, Cloudflare, DNS).
 */

'use strict';

const { generateNginxRemediation } = require('./generators/nginxGenerator');
const { generateApacheRemediation } = require('./generators/apacheGenerator');
const { generateNodeRemediation } = require('./generators/nodeGenerator');
const { generateNextRemediation } = require('./generators/nextGenerator');
const { generateCaddyRemediation, generateCloudflareRemediation, generateDnsRemediation } = require('./generators/dnsGenerator');
const { generateVercelRemediation, generateNetlifyRemediation } = require('./generators/cloudGenerator');

/**
 * Resolves the most appropriate remediation for a finding and detected technology stack.
 *
 * @param {object} scanReport - Canonical Phase 3 scan report
 * @param {string} findingId - Unique finding identifier
 * @param {string} [preferredStack] - Optional stack override from user (e.g. 'nginx', 'apache', 'next')
 * @returns {object|null}
 */
function resolveRemediation(scanReport, findingId, preferredStack = null) {
  if (!scanReport || !findingId) return null;

  const finding = (scanReport.findings || []).find((f) => f.id === findingId);
  if (!finding) return null;

  // 1. DNS findings always route to DNS generator
  if (finding.channel === 'DNS' || findingId.startsWith('SPF') || findingId.startsWith('DMARC') || findingId.startsWith('CAA')) {
    const dnsResult = generateDnsRemediation(findingId, scanReport.hostname || 'yourdomain.com');
    if (dnsResult) {
      return { findingId, ...dnsResult };
    }
  }

  // 2. Determine technology stack
  const detectedTech = scanReport.technologies || [];
  let targetStack = preferredStack ? preferredStack.toLowerCase() : null;

  if (!targetStack) {
    // Check detected technologies with confidence >= 0.85
    for (const tech of detectedTech) {
      const name = (tech.name || '').toLowerCase();
      const conf = tech.confidence ?? 1.0;
      if (conf >= 0.85) {
        if (name.includes('vercel')) { targetStack = 'vercel'; break; }
        if (name.includes('netlify')) { targetStack = 'netlify'; break; }
        if (name.includes('next')) { targetStack = 'next'; break; }
        if (name.includes('nginx')) { targetStack = 'nginx'; break; }
        if (name.includes('apache')) { targetStack = 'apache'; break; }
        if (name.includes('caddy')) { targetStack = 'caddy'; break; }
        if (name.includes('cloudflare')) { targetStack = 'cloudflare'; break; }
        if (name.includes('express') || name.includes('node')) { targetStack = 'node'; break; }
      }
    }
  }

  // 3. Generate remediation according to stack
  let result = null;
  if (targetStack === 'vercel') {
    result = generateVercelRemediation(findingId);
  } else if (targetStack === 'netlify') {
    result = generateNetlifyRemediation(findingId);
  } else if (targetStack === 'nginx') {
    result = generateNginxRemediation(findingId);
  } else if (targetStack === 'apache') {
    result = generateApacheRemediation(findingId);
  } else if (targetStack === 'next') {
    result = generateNextRemediation(findingId);
  } else if (targetStack === 'node' || targetStack === 'express') {
    result = generateNodeRemediation(findingId);
  } else if (targetStack === 'caddy') {
    result = generateCaddyRemediation(findingId);
  } else if (targetStack === 'cloudflare') {
    result = generateCloudflareRemediation(findingId);
  }

  // 4. Fallback to Nginx / Generic if stack is unknown or unsupported
  if (!result) {
    result = generateNginxRemediation(findingId) || generateNodeRemediation(findingId);
    if (result) {
      result.applicability = 'GENERIC';
      result.confidence = 0.75;
    }
  }

  if (!result) {
    return {
      findingId,
      stack: 'Generic Web Server',
      applicability: 'INSUFFICIENT_EVIDENCE',
      confidence: 0.50,
      file: 'Web Server / Application Configuration',
      snippet: `# Refer to vendor documentation for ${finding.channel} configuration`,
      explanation: finding.description,
      compatibilityWarnings: ['Stack could not be automatically determined with high confidence.'],
      validationSteps: 'Inspect HTTP response headers with curl -I',
      rollbackSteps: 'Revert server configuration changes.',
    };
  }

  return { findingId, ...result };
}

module.exports = {
  resolveRemediation,
};
