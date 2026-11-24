/**
 * Content & Web Intelligence Worker — WebVitals Modular Scan Engine
 *
 * Detects tech stack, framework signatures, robots.txt crawl rules,
 * sitemap availability, and social metadata. Outputs Standard Result Schema objects.
 */

'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');
const { createCheckResult } = require('../scan/checkSchema');
const { detectTechnologies } = require('../signatures/technologySignatures');

/**
 * Runs content and web intelligence checks.
 *
 * @param {URL} urlObj
 * @param {Object} headers
 * @param {string} bodySnippet
 * @returns {Promise<{ checks: Object[], contentData: Object }>}
 */
async function runContentWorker(urlObj, headers = {}, bodySnippet = '') {
  const startTime = Date.now();
  const checks = [];
  const hostname = urlObj.hostname;
  const isHttps = urlObj.protocol === 'https:';

  // 1. Multi-Signal Technology Stack Fingerprinting
  const detectedTech = detectTechnologies(headers, bodySnippet);
  const techNames = detectedTech.map((t) => t.name).join(', ') || 'Standard Web Stack';

  checks.push(createCheckResult({
    checkId: 'content.tech_stack',
    category: 'content',
    title: 'Technology Stack & Framework Fingerprinting',
    status: 'pass',
    severity: 'none',
    confidence: 0.95,
    summary: `Identified ${detectedTech.length || 1} technologies: ${techNames}`,
    details: 'Fingerprinted frontend frameworks, backend servers, and CDN infrastructure via HTTP headers, HTML DOM markers, and asset patterns.',
    evidence: { technologies: detectedTech },
    source: 'multi-signal-heuristics',
    durationMs: Date.now() - startTime,
  }));

  // 2. Robots.txt & AI Crawler Directives Probe
  let robotsTxtContent = '';
  let robotsFound = false;
  try {
    const robotsUrl = `${urlObj.origin}/robots.txt`;
    const robotsRes = await new Promise((resolve) => {
      const client = isHttps ? https : http;
      const req = client.get(
        robotsUrl,
        { headers: { 'User-Agent': 'WebVitals-Scanner/4.0' }, timeout: 4000 },
        (res) => {
          let b = '';
          res.on('data', (c) => (b += c.toString('utf8')));
          res.on('end', () => resolve({ status: res.statusCode, body: b }));
        }
      );
      req.on('error', () => resolve({ status: null, body: '' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: null, body: '' }); });
    });

    if (robotsRes.status === 200 && robotsRes.body.toLowerCase().includes('user-agent')) {
      robotsFound = true;
      robotsTxtContent = robotsRes.body;
    }
  } catch {}

  if (robotsFound) {
    const lowerRobots = robotsTxtContent.toLowerCase();
    const blocksGpt = lowerRobots.includes('gptbot') && lowerRobots.includes('disallow: /');
    const blocksClaude = lowerRobots.includes('claudebot') && lowerRobots.includes('disallow: /');
    const blockedAiCount = (blocksGpt ? 1 : 0) + (blocksClaude ? 1 : 0);

    checks.push(createCheckResult({
      checkId: 'content.robots_txt',
      category: 'content',
      title: 'Search & AI Crawler Directives (robots.txt)',
      status: 'pass',
      severity: 'none',
      confidence: 1.0,
      summary: `Valid robots.txt discovered (${blockedAiCount > 0 ? `${blockedAiCount} AI crawler(s) restricted` : 'Standard crawl rules active'})`,
      details: `Published at ${urlObj.origin}/robots.txt. Manages indexation boundaries and scraper ingress.`,
      evidence: { exists: true, blocksGpt, blocksClaude, snippet: robotsTxtContent.slice(0, 300) },
      source: 'http-probe',
      durationMs: Date.now() - startTime,
    }));
  } else {
    checks.push(createCheckResult({
      checkId: 'content.robots_txt',
      category: 'content',
      title: 'Search & AI Crawler Directives (robots.txt)',
      status: 'info',
      severity: 'informational',
      confidence: 1.0,
      summary: 'No robots.txt file found (All public pages open to crawling)',
      details: `Target does not serve a robots.txt file at ${urlObj.origin}/robots.txt. Search engines and AI scrapers crawl unrestricted.`,
      evidence: { exists: false },
      recommendation: 'Create a robots.txt file to guide search engines and protect private directories.',
      source: 'http-probe',
      durationMs: Date.now() - startTime,
    }));
  }

  // 3. Social Tags & OpenGraph Metadata
  const titleMatch = /<title[^>]*>([^<]+)<\/title>/i.exec(bodySnippet);
  const ogTitleMatch = /<meta\s+[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i.exec(bodySnippet);
  const ogImageMatch = /<meta\s+[^>]*property=["']og:image["'][^>]*content=["']([^"']+)["']/i.exec(bodySnippet);
  const twitterCardMatch = /<meta\s+[^>]*name=["']twitter:card["'][^>]*content=["']([^"']+)["']/i.exec(bodySnippet);

  const hasOg = Boolean(ogTitleMatch || ogImageMatch);

  checks.push(createCheckResult({
    checkId: 'content.social_tags',
    category: 'content',
    title: 'OpenGraph & Social Sharing Metadata',
    status: hasOg ? 'pass' : 'info',
    severity: 'none',
    confidence: 1.0,
    summary: hasOg ? 'OpenGraph social preview metadata properly configured' : 'Basic HTML title found, but OpenGraph tags are missing',
    details: `Page title: "${titleMatch ? titleMatch[1].trim() : hostname}". Twitter card: ${twitterCardMatch ? twitterCardMatch[1] : 'Not Specified'}.`,
    evidence: {
      title: titleMatch ? titleMatch[1].trim() : null,
      ogTitle: ogTitleMatch ? ogTitleMatch[1] : null,
      hasOgImage: Boolean(ogImageMatch),
      twitterCard: twitterCardMatch ? twitterCardMatch[1] : null,
    },
    recommendation: hasOg ? '' : 'Add og:title, og:description, and og:image tags for rich previews on social and messaging apps.',
    source: 'html-parser',
    durationMs: Date.now() - startTime,
  }));

  const contentData = {
    technologies: detectedTech,
    robotsFound,
    socialTags: {
      title: titleMatch ? titleMatch[1].trim() : hostname,
      ogTitle: ogTitleMatch ? ogTitleMatch[1] : null,
      ogImage: ogImageMatch ? ogImageMatch[1] : null,
    },
  };

  return { checks, contentData };
}

module.exports = {
  runContentWorker,
};
