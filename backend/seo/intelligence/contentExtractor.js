/**
 * Content Extractor — WebVitals 2.0 SEO/GEO/AEO Intelligence Engine
 *
 * Extracts deep semantic content, full H1-H6 heading hierarchy, structured tables,
 * lists, definitions, Q&A / FAQ blocks, boilerplate ratio, freshness, and author attribution.
 */

'use strict';

function decodeEntities(text = '') {
  return text
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .trim();
}

/**
 * Extracts and analyzes all structured content from HTML.
 *
 * @param {string} html
 * @param {Object} parsedData - Base metadata from htmlParser
 * @param {string} [finalUrl='']
 * @returns {Object} Structured content extraction
 */
function extractDeepContent(html = '', parsedData = {}, finalUrl = '') {
  if (!html || typeof html !== 'string') {
    return {
      wordCount: 0,
      charCount: 0,
      readingTimeMinutes: 0,
      cleanBodyText: '',
      boilerplateRatio: 0,
      headingsTree: [],
      headingStats: { h1: 0, h2: 0, h3: 0, h4: 0, h5: 0, h6: 0, hasHierarchyIssue: false, issues: [] },
      tables: [],
      lists: { totalLists: 0, totalItems: 0, orderedCount: 0, unorderedCount: 0 },
      definitions: [],
      qaBlocks: [],
      freshness: { publishedDate: null, modifiedDate: null, copyrightYear: null, isRecent: false },
      authorship: { authorName: null, authorUrl: null, hasBio: false },
      linksAnalysis: { total: 0, internal: 0, external: 0, genericAnchorsCount: 0, genericAnchors: [] },
      imagesAnalysis: { total: 0, withAlt: 0, missingAlt: 0, nextGenFormatCount: 0 },
    };
  }

  // 1. Heading Hierarchy (H1 - H6)
  const headingRegex = /<(h[1-6])(?:\s+[^>]*?)?>([\s\S]*?)<\/\1>/gi;
  const headingsTree = [];
  const headingStats = { h1: 0, h2: 0, h3: 0, h4: 0, h5: 0, h6: 0, hasHierarchyIssue: false, issues: [] };
  let hMatch;

  while ((hMatch = headingRegex.exec(html)) !== null) {
    const levelTag = hMatch[1].toLowerCase();
    const levelNum = parseInt(levelTag.replace('h', ''), 10);
    const rawText = hMatch[2].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
    const cleanText = decodeEntities(rawText);

    if (cleanText) {
      headingsTree.push({ level: levelNum, tag: levelTag, text: cleanText });
      headingStats[levelTag]++;
    }
  }

  // Evaluate Heading Hierarchy issues
  if (headingStats.h1 === 0) {
    headingStats.issues.push('Missing H1 heading on the page.');
    headingStats.hasHierarchyIssue = true;
  } else if (headingStats.h1 > 1) {
    headingStats.issues.push(`Multiple H1 headings (${headingStats.h1}) detected.`);
    headingStats.hasHierarchyIssue = true;
  }

  for (let i = 0; i < headingsTree.length - 1; i++) {
    const currentLevel = headingsTree[i].level;
    const nextLevel = headingsTree[i + 1].level;
    if (nextLevel > currentLevel + 1) {
      headingStats.issues.push(`Skipped heading level from H${currentLevel} to H${nextLevel} ("${headingsTree[i + 1].text.slice(0, 40)}...")`);
      headingStats.hasHierarchyIssue = true;
      break;
    }
  }

  // 2. Main Content Extraction & Boilerplate Ratio
  // Remove non-content regions
  const strippedHtml = html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
    .replace(/<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');

  // Extract navigation / header / footer for boilerplate calculation
  const navMatches = strippedHtml.match(/<(nav|footer|header)\b[^>]*>([\s\S]*?)<\/\1>/gi) || [];
  const boilerplateText = navMatches.map(n => n.replace(/<[^>]*>/g, ' ')).join(' ').replace(/\s+/g, ' ').trim();

  // Full clean text
  const cleanBodyText = strippedHtml
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const words = cleanBodyText ? cleanBodyText.split(/\s+/).filter(w => w.length > 0) : [];
  const wordCount = words.length;
  const charCount = cleanBodyText.length;
  const readingTimeMinutes = Math.max(1, Math.ceil(wordCount / 200));

  const boilerplateWords = boilerplateText ? boilerplateText.split(/\s+/).filter(Boolean).length : 0;
  const boilerplateRatio = wordCount > 0 ? parseFloat((boilerplateWords / wordCount).toFixed(2)) : 0;

  // 3. Structured Tables
  const tableRegex = /<table\b[^>]*>([\s\S]*?)<\/table>/gi;
  const tables = [];
  let tMatch;
  while ((tMatch = tableRegex.exec(html)) !== null && tables.length < 10) {
    const tableContent = tMatch[1];
    const thMatches = tableContent.match(/<th\b[^>]*>([\s\S]*?)<\/th>/gi) || [];
    const headers = thMatches.map(th => decodeEntities(th.replace(/<[^>]*>/g, '').trim())).filter(Boolean);
    const rowCount = (tableContent.match(/<tr\b[^>]*>/gi) || []).length;
    tables.push({ headers, rowCount });
  }

  // 4. Structured Lists (UL / OL)
  const ulCount = (html.match(/<ul\b[^>]*>/gi) || []).length;
  const olCount = (html.match(/<ol\b[^>]*>/gi) || []).length;
  const liCount = (html.match(/<li\b[^>]*>/gi) || []).length;
  const lists = {
    totalLists: ulCount + olCount,
    orderedCount: olCount,
    unorderedCount: ulCount,
    totalItems: liCount,
  };

  // 5. Definitions (<dl>, <dt>, <dd>)
  const definitions = [];
  const dtRegex = /<dt\b[^>]*>([\s\S]*?)<\/dt>\s*<dd\b[^>]*>([\s\S]*?)<\/dd>/gi;
  let defMatch;
  while ((defMatch = dtRegex.exec(html)) !== null && definitions.length < 15) {
    const term = decodeEntities(defMatch[1].replace(/<[^>]*>/g, '').trim());
    const def = decodeEntities(defMatch[2].replace(/<[^>]*>/g, '').trim());
    if (term && def) definitions.push({ term, definition: def });
  }

  // 6. Q&A / FAQ Blocks & Question-Oriented Headings
  const qaBlocks = [];
  // Heading-based questions
  headingsTree.forEach(h => {
    const t = h.text.trim();
    if (t.endsWith('?') || /^(what|how|why|when|where|who|is|can|should|do|does)\b/i.test(t)) {
      qaBlocks.push({ question: t, level: h.tag, source: 'heading' });
    }
  });

  // Details/Summary accordion elements
  const detailsRegex = /<details\b[^>]*>[\s\S]*?<summary\b[^>]*>([\s\S]*?)<\/summary>([\s\S]*?)<\/details>/gi;
  let detMatch;
  while ((detMatch = detailsRegex.exec(html)) !== null && qaBlocks.length < 25) {
    const q = decodeEntities(detMatch[1].replace(/<[^>]*>/g, '').trim());
    const a = decodeEntities(detMatch[2].replace(/<[^>]*>/g, '').trim()).slice(0, 300);
    if (q) qaBlocks.push({ question: q, answerSnippet: a, source: 'details_summary' });
  }

  // Schema FAQPage / QAPage check
  const jsonLd = parsedData.jsonLd || [];
  jsonLd.forEach(item => {
    if (item['@type'] === 'FAQPage' && Array.isArray(item.mainEntity)) {
      item.mainEntity.forEach(qItem => {
        if (qItem.name && qItem.acceptedAnswer?.text) {
          qaBlocks.push({
            question: qItem.name,
            answerSnippet: qItem.acceptedAnswer.text.replace(/<[^>]*>/g, '').slice(0, 300),
            source: 'schema_faq',
          });
        }
      });
    }
  });

  // 7. Freshness & Publication Dates
  let publishedDate = null;
  let modifiedDate = null;

  // Check Schema dates
  jsonLd.forEach(item => {
    if (item.datePublished) publishedDate = item.datePublished;
    if (item.dateModified) modifiedDate = item.dateModified;
  });

  // Check Meta Tags
  const pubMeta = html.match(/<meta\s+[^>]*property=["']article:published_time["'][^>]*content=["']([^"']+)["']/i) ||
                  html.match(/<meta\s+[^>]*name=["']date["'][^>]*content=["']([^"']+)["']/i);
  if (pubMeta) publishedDate = pubMeta[1];

  const modMeta = html.match(/<meta\s+[^>]*property=["']article:modified_time["'][^>]*content=["']([^"']+)["']/i);
  if (modMeta) modifiedDate = modMeta[1];

  // Copyright Year in Footer
  const copyMatch = html.match(/(?:©|&copy;|copyright)\s*(?:20\d{2}\s*[-–]\s*)?(20\d{2})/i);
  const copyrightYear = copyMatch ? parseInt(copyMatch[1], 10) : null;

  const currentYear = new Date().getFullYear();
  const isRecent = (publishedDate && new Date(publishedDate).getFullYear() >= currentYear - 1) ||
                   (modifiedDate && new Date(modifiedDate).getFullYear() >= currentYear - 1) ||
                   (copyrightYear && copyrightYear >= currentYear - 1);

  const freshness = {
    publishedDate,
    modifiedDate,
    copyrightYear,
    isRecent: Boolean(isRecent),
  };

  // 8. Authorship & Credibility Attribution
  let authorName = null;
  let authorUrl = null;
  jsonLd.forEach(item => {
    if (item.author) {
      if (typeof item.author === 'string') authorName = item.author;
      else if (item.author.name) authorName = item.author.name;
      if (item.author.url) authorUrl = item.author.url;
    }
  });

  const authorMeta = html.match(/<meta\s+[^>]*name=["']author["'][^>]*content=["']([^"']+)["']/i);
  if (!authorName && authorMeta) authorName = authorMeta[1];

  const relAuthor = html.match(/<a\s+[^>]*rel=["'][^"']*author[^"']*["'][^>]*>([\s\S]*?)<\/a>/i);
  if (!authorName && relAuthor) authorName = decodeEntities(relAuthor[1].replace(/<[^>]*>/g, '').trim());

  const hasBio = /class=["'][^"']*(?:author-bio|about-author|author-profile|author-card)[^"']*["']/i.test(html);
  const authorship = { authorName, authorUrl, hasBio };

  // 9. Links Anchor Text Analysis
  const rawLinks = parsedData.links || [];
  const genericAnchorsList = [];
  const GENERIC_ANCHOR_PATTERNS = /^(click here|read more|learn more|more|here|link|view|this page|continue|check this out|go)$/i;

  rawLinks.forEach(link => {
    const text = (link.text || '').trim();
    if (GENERIC_ANCHOR_PATTERNS.test(text)) {
      genericAnchorsList.push({ anchor: text, url: link.url });
    }
  });

  const linksAnalysis = {
    total: rawLinks.length,
    internal: rawLinks.filter(l => l.isInternal).length,
    external: rawLinks.filter(l => !l.isInternal).length,
    genericAnchorsCount: genericAnchorsList.length,
    genericAnchors: genericAnchorsList.slice(0, 10),
  };

  // 10. Images Analysis
  const rawImages = parsedData.images || [];
  const withAlt = rawImages.filter(img => img.hasAlt && img.alt.trim().length > 0).length;
  const missingAlt = rawImages.length - withAlt;
  const nextGenCount = rawImages.filter(img => /\.(webp|avif|svg)(\?|$)/i.test(img.src)).length;

  const imagesAnalysis = {
    total: rawImages.length,
    withAlt,
    missingAlt,
    nextGenFormatCount: nextGenCount,
  };

  return {
    wordCount,
    charCount,
    readingTimeMinutes,
    cleanBodyText: cleanBodyText.slice(0, 15000), // First 15KB of text for analysis
    boilerplateRatio,
    headingsTree,
    headingStats,
    tables,
    lists,
    definitions,
    qaBlocks,
    freshness,
    authorship,
    linksAnalysis,
    imagesAnalysis,
  };
}

module.exports = {
  extractDeepContent,
  decodeEntities,
};
