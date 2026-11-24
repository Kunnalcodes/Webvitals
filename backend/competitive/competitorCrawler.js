/**
 * Competitor & Primary Multi-Page Discovery Crawler — WebVitals 2.0
 *
 * Discovers accessible content, sitemaps, robots.txt directives, and internal page inventories
 * for both target domains up to safe, bounded limits.
 */

'use strict';

const { URL } = require('url');
const { fetchUrl, fetchResource } = require('../seo/crawler');
const { parseHtml } = require('../seo/htmlParser');
const { extractSemanticContent } = require('../seo/intelligence/contentExtractor');
const { validateTargetUrl } = require('../middleware/abuseProtection');

/**
 * Extracts URL locations from sitemap XML content.
 *
 * @param {string} xmlContent
 * @param {number} maxUrls
 * @returns {string[]} Array of URLs
 */
function extractSitemapUrls(xmlContent, maxUrls = 25) {
  if (!xmlContent || typeof xmlContent !== 'string') return [];
  const urls = [];
  const locRegex = /<loc>\s*(https?:\/\/[^<\s]+)\s*<\/loc>/gi;
  let match;
  while ((match = locRegex.exec(xmlContent)) !== null && urls.length < maxUrls) {
    const rawUrl = match[1].trim();
    if (validateTargetUrl(rawUrl).valid) {
      urls.push(rawUrl);
    }
  }
  return urls;
}

/**
 * Classifies an internal URL into a page type.
 *
 * @param {string} urlStr
 * @returns {string} Page type
 */
function classifyPageType(urlStr) {
  const path = (urlStr || '').toLowerCase();
  if (/pricing|plans|cost|subscription/i.test(path)) return 'pricing';
  if (/service|services|solutions/i.test(path)) return 'service';
  if (/product|products|features|platform/i.test(path)) return 'product';
  if (/blog|article|news|post|insights/i.test(path)) return 'blog';
  if (/guide|documentation|docs|tutorial|how-to/i.test(path)) return 'guide';
  if (/about|team|company|leadership|story/i.test(path)) return 'about';
  if (/contact|support|help|sales|demo/i.test(path)) return 'contact';
  if (/faq|questions|answers/i.test(path)) return 'faq';
  if (/vs|compare|comparison|alternatives/i.test(path)) return 'comparison';
  if (/case-study|case-studies|customers|testimonials/i.test(path)) return 'case_study';
  return 'general';
}

/**
 * Crawls and builds a page inventory for a target domain.
 *
 * @param {Object} targetObj - { url, domain, hostname, label }
 * @param {Object} [options] - Crawl options (maxAdditionalPages)
 * @returns {Promise<Object>} Domain page inventory and metadata
 */
async function crawlDomainInventory(targetObj, options = {}) {
  const maxPages = options.maxAdditionalPages || 4;
  const baseUrl = targetObj.url;
  const urlObj = new URL(baseUrl);

  // 1. Fetch Homepage & Core Files
  const [homeResult, robotsRes, sitemapRes] = await Promise.all([
    fetchUrl(urlObj, 5).catch(err => ({
      finalUrl: baseUrl,
      statusCode: 500,
      headers: {},
      chain: [],
      body: '',
      elapsedMs: 0,
      error: err.message,
    })),
    fetchResource(baseUrl, '/robots.txt'),
    fetchResource(baseUrl, '/sitemap.xml'),
  ]);

  const homeHtml = homeResult.body || '';
  const parsedHome = parseHtml(homeHtml, homeResult.finalUrl || baseUrl);
  const semanticHome = extractSemanticContent(homeHtml, parsedHome);

  // Parse sitemap URLs if sitemap was discovered
  const discoveredSitemapUrls = sitemapRes.exists ? extractSitemapUrls(sitemapRes.content, 30) : [];

  // 2. Discover Priority Candidate Sub-pages
  const candidateUrls = new Set();

  // Add priority internal links from homepage
  if (parsedHome.links && Array.isArray(parsedHome.links)) {
    for (const link of parsedHome.links) {
      if (link.isInternal && link.href && link.href.startsWith('http')) {
        const type = classifyPageType(link.href);
        if (type !== 'general' && candidateUrls.size < maxPages) {
          candidateUrls.add(link.href);
        }
      }
    }
  }

  // Complement with sitemap URLs if available
  for (const sUrl of discoveredSitemapUrls) {
    if (candidateUrls.size >= maxPages) break;
    const type = classifyPageType(sUrl);
    if (type !== 'general' && !candidateUrls.has(sUrl)) {
      candidateUrls.add(sUrl);
    }
  }

  // 3. Concurrently fetch candidate sub-pages
  const subPagePromises = Array.from(candidateUrls).map(async (pageUrl) => {
    try {
      const pageObj = new URL(pageUrl);
      const res = await fetchUrl(pageObj, 3);
      if (res.statusCode >= 200 && res.statusCode < 400 && res.body) {
        const parsed = parseHtml(res.body, res.finalUrl || pageUrl);
        const semantic = extractSemanticContent(res.body, parsed);
        return {
          url: res.finalUrl || pageUrl,
          type: classifyPageType(pageUrl),
          statusCode: res.statusCode,
          elapsedMs: res.elapsedMs,
          title: parsed.title || '',
          metaDescription: parsed.metaDescription || '',
          wordCount: parsed.wordCount || 0,
          headings: {
            h1: parsed.h1 || [],
            h2: (parsed.h2 || []).slice(0, 10),
            h3: (parsed.h3 || []).slice(0, 10),
          },
          semantic: {
            headings: semantic.headings || [],
            tablesCount: (semantic.tables || []).length,
            definitionsCount: (semantic.definitions || []).length,
            qaBlocksCount: (semantic.qaBlocks || []).length,
            qaBlocks: (semantic.qaBlocks || []).slice(0, 5),
            cleanBodyText: (semantic.cleanBodyText || '').slice(0, 3000),
          },
        };
      }
    } catch {
      // Sub-page fetch failure is non-fatal
    }
    return null;
  });

  const subPages = (await Promise.all(subPagePromises)).filter(Boolean);

  // Group pages by classified type
  const pagesByType = {
    homepage: 1,
    service: 0,
    product: 0,
    pricing: 0,
    blog: 0,
    guide: 0,
    about: 0,
    contact: 0,
    faq: 0,
    comparison: 0,
    case_study: 0,
    general: 0,
  };

  subPages.forEach(p => {
    pagesByType[p.type] = (pagesByType[p.type] || 0) + 1;
  });

  return {
    domain: targetObj.domain,
    hostname: targetObj.hostname,
    url: targetObj.url,
    finalUrl: homeResult.finalUrl || baseUrl,
    statusCode: homeResult.statusCode,
    elapsedMs: homeResult.elapsedMs,
    homepage: {
      title: parsedHome.title || '',
      metaDescription: parsedHome.metaDescription || '',
      canonicalUrl: parsedHome.canonicalUrl || '',
      wordCount: parsedHome.wordCount || 0,
      headings: {
        h1: parsedHome.h1 || [],
        h2: (parsedHome.h2 || []).slice(0, 12),
        h3: (parsedHome.h3 || []).slice(0, 12),
      },
      schemaTypes: parsedHome.structuredData?.types || [],
      openGraph: parsedHome.openGraph || {},
      twitterCard: parsedHome.twitterCard || {},
      links: {
        internalCount: (parsedHome.links || []).filter(l => l.isInternal).length,
        externalCount: (parsedHome.links || []).filter(l => !l.isInternal).length,
      },
      semantic: {
        headings: semanticHome.headings || [],
        tables: semanticHome.tables || [],
        definitions: semanticHome.definitions || [],
        qaBlocks: semanticHome.qaBlocks || [],
        boilerplateRatio: semanticHome.boilerplateRatio || '25%',
        readingMinutes: semanticHome.readingMinutes || 2,
        cleanBodyText: (semanticHome.cleanBodyText || '').slice(0, 5000),
      },
    },
    subPages,
    totalPagesDiscovered: 1 + subPages.length + discoveredSitemapUrls.length,
    pagesByType,
    sitemap: {
      exists: sitemapRes.exists,
      url: sitemapRes.url,
      discoveredUrlsCount: discoveredSitemapUrls.length,
      sampleUrls: discoveredSitemapUrls.slice(0, 10),
    },
    robotsTxt: {
      exists: robotsRes.exists,
      url: robotsRes.url,
      content: robotsRes.content.slice(0, 1000),
      hasAiDisallows: /gptbot|chatgpt|claude|perplexity|google-extended/i.test(robotsRes.content),
    },
  };
}

module.exports = {
  crawlDomainInventory,
  classifyPageType,
  extractSitemapUrls,
};
