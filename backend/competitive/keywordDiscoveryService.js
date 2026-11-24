/**
 * Multi-Source Keyword Discovery Pipeline — WebVitals 2.0
 *
 * Extracts authentic, evidence-based keyword candidates across multiple sources:
 *   - Page titles & meta descriptions
 *   - H1-H3 heading hierarchy
 *   - Semantic body text n-grams (1-4 grams)
 *   - Sitemap URL path slugs
 *   - Extracted Q&A blocks & question patterns
 *   - Entity & industry terms
 *   - User-provided seed queries
 */

'use strict';

const STOPWORDS = new Set([
  'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', 'aren\'t', 'as', 'at',
  'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by', 'can\'t', 'cannot', 'could',
  'couldn\'t', 'did', 'didn\'t', 'do', 'does', 'doesn\'t', 'doing', 'don\'t', 'down', 'during', 'each', 'few', 'for',
  'from', 'further', 'had', 'hadn\'t', 'has', 'hasn\'t', 'have', 'haven\'t', 'having', 'he', 'he\'d', 'he\'ll',
  'he\'s', 'her', 'here', 'here\'s', 'hers', 'herself', 'him', 'himself', 'his', 'how\'s', 'i', 'i\'d', 'i\'ll',
  'i\'m', 'i\'ve', 'if', 'in', 'into', 'is', 'isn\'t', 'it', 'it\'s', 'its', 'itself', 'let\'s', 'me', 'more', 'most',
  'mustn\'t', 'my', 'myself', 'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought', 'our',
  'ours', 'ourselves', 'out', 'over', 'own', 'same', 'shan\'t', 'she', 'she\'d', 'she\'ll', 'she\'s', 'should',
  'shouldn\'t', 'so', 'some', 'such', 'than', 'that', 'that\'s', 'the', 'their', 'theirs', 'them', 'themselves',
  'then', 'there', 'there\'s', 'these', 'they', 'they\'d', 'they\'ll', 'they\'re', 'they\'ve', 'this', 'those',
  'through', 'to', 'too', 'under', 'until', 'up', 'very', 'was', 'wasn\'t', 'we', 'we\'d', 'we\'ll', 'we\'re',
  'we\'ve', 'were', 'weren\'t', 'while', 'with', 'won\'t', 'would', 'wouldn\'t', 'you', 'you\'d', 'you\'ll',
  'you\'re', 'you\'ve', 'your', 'yours', 'yourself', 'yourselves'
]);

/**
 * Cleans and tokenizes text into lowercase words.
 */
function tokenize(text) {
  if (!text || typeof text !== 'string') return [];
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !STOPWORDS.has(w));
}

/**
 * Extracts salient n-grams (2 to 4 words) from text.
 */
function extractNgrams(text, minN = 2, maxN = 4, maxItems = 15) {
  if (!text || typeof text !== 'string') return [];
  const cleanTokens = text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .split(/\s+/)
    .filter(Boolean);

  const freq = new Map();

  for (let n = minN; n <= maxN; n++) {
    for (let i = 0; i <= cleanTokens.length - n; i++) {
      const slice = cleanTokens.slice(i, i + n);
      // Skip if starting or ending with pure filler stopword
      if (STOPWORDS.has(slice[0]) || STOPWORDS.has(slice[slice.length - 1])) continue;
      const phrase = slice.join(' ');
      if (phrase.length > 5 && !/^\d+$/.test(phrase)) {
        freq.set(phrase, (freq.get(phrase) || 0) + 1);
      }
    }
  }

  return Array.from(freq.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxItems)
    .map(([phrase, count]) => ({ phrase, count }));
}

/**
 * Extracts keyword phrases from URL slug paths.
 */
function extractSlugKeywords(urls = []) {
  const slugKeywords = new Set();
  urls.forEach(u => {
    try {
      const parsed = new URL(u);
      const segments = parsed.pathname.split('/').filter(Boolean);
      segments.forEach(seg => {
        const clean = seg.replace(/[-_]/g, ' ').replace(/\.(html|php|asp|xml)$/i, '').trim();
        if (clean.length >= 4 && !/^\d+$/.test(clean)) {
          slugKeywords.add(clean.toLowerCase());
        }
      });
    } catch {
      // Ignore invalid URL
    }
  });
  return Array.from(slugKeywords);
}

/**
 * Extracts question keywords from text, headings, and Q&A blocks.
 */
function extractQuestionKeywords(headings = [], qaBlocks = [], cleanText = '') {
  const questions = new Set();
  const qRegex = /^(what|how|why|when|where|who|which|can|should|is|are|does|do|best|top|vs)\b/i;

  headings.forEach(h => {
    const text = (typeof h === 'string' ? h : h.text || '').trim();
    if (text.endsWith('?') || qRegex.test(text)) {
      questions.add(text.replace(/\?+$/, ''));
    }
  });

  qaBlocks.forEach(qa => {
    if (qa.question) {
      questions.add(qa.question.trim().replace(/\?+$/, ''));
    }
  });

  return Array.from(questions);
}

/**
 * Discovers a comprehensive set of keywords for a single domain inventory.
 *
 * @param {Object} inventory - Crawled domain inventory
 * @param {string} domainType - 'primary' or 'competitor'
 * @param {string[]} [seedKeywords] - Optional user-provided seed keywords
 * @returns {Array<Object>} Discovered keyword records
 */
function discoverDomainKeywords(inventory, domainType = 'primary', seedKeywords = []) {
  if (!inventory) return [];
  const keywordMap = new Map();

  const addKeyword = (rawKw, source, sourceType, targetPageUrl, initialRelevance = 0.8) => {
    if (!rawKw || typeof rawKw !== 'string') return;
    const cleanKw = rawKw.toLowerCase().replace(/['"“”]/g, '').trim();
    if (cleanKw.length < 3 || cleanKw.length > 80 || /^\d+$/.test(cleanKw)) return;

    if (!keywordMap.has(cleanKw)) {
      keywordMap.set(cleanKw, {
        keyword: cleanKw,
        source,
        sourceType,
        domainType,
        originatingDomain: inventory.domain,
        targetPageUrl: targetPageUrl || inventory.url,
        relevanceScore: initialRelevance,
        occurrences: 1,
      });
    } else {
      const existing = keywordMap.get(cleanKw);
      existing.occurrences += 1;
      existing.relevanceScore = Math.min(1.0, existing.relevanceScore + 0.05);
    }
  };

  const home = inventory.homepage || {};

  // 1. Page Title Keywords
  if (home.title) {
    const titleParts = home.title.split(/[|—–-]/).map(s => s.trim()).filter(Boolean);
    titleParts.forEach(tp => {
      addKeyword(tp, `${domainType}_homepage_title`, 'title_tag', inventory.url, 0.95);
    });
  }

  // 2. Heading Keywords (H1, H2, H3)
  (home.headings?.h1 || []).forEach(h => {
    addKeyword(h, `${domainType}_h1_heading`, 'heading_h1', inventory.url, 0.95);
  });
  (home.headings?.h2 || []).forEach(h => {
    addKeyword(h, `${domainType}_h2_heading`, 'heading_h2', inventory.url, 0.85);
  });
  (home.headings?.h3 || []).forEach(h => {
    addKeyword(h, `${domainType}_h3_heading`, 'heading_h3', inventory.url, 0.75);
  });

  // 3. Sub-page Titles & Headings
  (inventory.subPages || []).forEach(sp => {
    if (sp.title) {
      sp.title.split(/[|—–-]/).forEach(tp => addKeyword(tp, `${domainType}_subpage_title`, 'subpage_title', sp.url, 0.85));
    }
    (sp.headings?.h1 || []).forEach(h => addKeyword(h, `${domainType}_subpage_h1`, 'subpage_h1', sp.url, 0.90));
    (sp.headings?.h2 || []).forEach(h => addKeyword(h, `${domainType}_subpage_h2`, 'subpage_h2', sp.url, 0.80));
  });

  // 4. Salient Body N-grams
  const bodyNgrams = extractNgrams(home.semantic?.cleanBodyText || '', 2, 4, 20);
  bodyNgrams.forEach(ng => {
    addKeyword(ng.phrase, `${domainType}_body_content`, 'content_ngram', inventory.url, 0.70);
  });

  // 5. Sitemap URL Path Slugs
  const sitemapUrls = inventory.sitemap?.sampleUrls || [];
  const slugKws = extractSlugKeywords(sitemapUrls);
  slugKws.forEach(skw => {
    addKeyword(skw, `${domainType}_sitemap_slug`, 'sitemap_url', inventory.sitemap?.url, 0.75);
  });

  // 6. Extracted Question Queries
  const allHeadings = [...(home.headings?.h1 || []), ...(home.headings?.h2 || []), ...(home.headings?.h3 || [])];
  const allQa = [...(home.semantic?.qaBlocks || [])];
  const questions = extractQuestionKeywords(allHeadings, allQa);
  questions.forEach(q => {
    addKeyword(q, `${domainType}_question_structure`, 'question_query', inventory.url, 0.90);
  });

  // 7. Seed Keywords (User provided)
  if (Array.isArray(seedKeywords)) {
    seedKeywords.forEach(sk => {
      addKeyword(sk, 'user_seed_keyword', 'user_seed', inventory.url, 1.0);
    });
  }

  return Array.from(keywordMap.values());
}

/**
 * Runs the complete discovery pipeline across both primary and competitor inventories.
 *
 * @param {Object} primaryInventory
 * @param {Object} competitorInventory
 * @param {string[]} [seedKeywords]
 * @returns {Object} { primaryKeywords, competitorKeywords, combinedKeywords }
 */
function discoverCompetitiveKeywords(primaryInventory, competitorInventory, seedKeywords = []) {
  const primaryKeywords = discoverDomainKeywords(primaryInventory, 'primary', seedKeywords);
  const competitorKeywords = discoverDomainKeywords(competitorInventory, 'competitor', seedKeywords);

  const combinedMap = new Map();

  primaryKeywords.forEach(k => {
    combinedMap.set(k.keyword, {
      ...k,
      primaryPresent: true,
      competitorPresent: false,
    });
  });

  competitorKeywords.forEach(k => {
    if (combinedMap.has(k.keyword)) {
      const existing = combinedMap.get(k.keyword);
      existing.competitorPresent = true;
      existing.competitorTargetPage = k.targetPageUrl;
      existing.competitorSource = k.source;
    } else {
      combinedMap.set(k.keyword, {
        ...k,
        primaryPresent: false,
        competitorPresent: true,
        competitorTargetPage: k.targetPageUrl,
        competitorSource: k.source,
      });
    }
  });

  return {
    primaryKeywords,
    competitorKeywords,
    combinedKeywords: Array.from(combinedMap.values()),
  };
}

module.exports = {
  discoverDomainKeywords,
  discoverCompetitiveKeywords,
  extractNgrams,
  extractSlugKeywords,
  extractQuestionKeywords,
};
