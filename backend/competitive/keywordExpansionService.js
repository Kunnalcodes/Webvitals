/**
 * Keyword Expansion & Categorization System — WebVitals 2.0
 *
 * Classifies and expands discovered keywords across 12 strategic categories:
 *   1. Core Keywords
 *   2. Commercial Keywords
 *   3. Transactional Keywords
 *   4. Informational Keywords
 *   5. Long-Tail Keywords
 *   6. Question Keywords
 *   7. Local Keywords
 *   8. Brand Keywords
 *   9. Comparison Keywords
 *   10. Pain-Point Keywords
 *   11. Industry Keywords
 *   12. Entity & Semantic Keywords
 *
 * Maps search intent, business value, and source-aware fields (nullable metrics).
 */

'use strict';

/**
 * Classifies search intent for a query.
 *
 * @param {string} keyword
 * @returns {string} 'informational' | 'commercial' | 'transactional' | 'navigational' | 'local'
 */
function classifyKeywordIntent(keyword) {
  const kw = (keyword || '').toLowerCase();

  // Local intent
  if (/\b(near me|in [a-z]+|city|county|state|area|location|uk|usa|india|california|london)\b/i.test(kw)) {
    return 'local';
  }

  // Transactional intent
  if (/\b(buy|order|purchase|pricing|price|cost|quote|discount|coupon|hire|book|register|sign up|checkout|trial)\b/i.test(kw)) {
    return 'transactional';
  }

  // Commercial investigation
  if (/\b(best|top|review|reviews|vs|versus|compare|comparison|alternative|alternatives|platform|software|tool|agency|provider)\b/i.test(kw)) {
    return 'commercial';
  }

  // Navigational
  if (/\b(login|sign in|portal|dashboard|official|website|app|docs|download)\b/i.test(kw)) {
    return 'navigational';
  }

  // Default to Informational
  return 'informational';
}

/**
 * Classifies a keyword into one of the 12 strategic categories.
 *
 * @param {string} keyword
 * @param {Object} context - { primaryDomain, competitorDomain, industry, location }
 * @returns {string} Category key
 */
function categorizeKeyword(keyword, context = {}) {
  const kw = (keyword || '').toLowerCase();
  const primaryBrand = (context.primaryDomain || '').split('.')[0].toLowerCase();
  const competitorBrand = (context.competitorDomain || '').split('.')[0].toLowerCase();

  // 1. Comparison Keywords (A vs B, alternatives)
  if (/\b(vs|versus|compare|comparison|alternative|alternatives|difference)\b/i.test(kw)) {
    return 'comparison';
  }

  // 2. Brand Keywords
  if ((primaryBrand && kw.includes(primaryBrand)) || (competitorBrand && kw.includes(competitorBrand))) {
    return 'brand';
  }

  // 3. Question Keywords
  if (/^(what|why|how|where|when|who|which|can|should|does|is|are)\b/i.test(kw) || kw.includes('?')) {
    return 'question';
  }

  // 4. Local Keywords
  if (/\b(near me|local|nearby|city|state|country)\b/i.test(kw) || (context.location && kw.includes(context.location.toLowerCase()))) {
    return 'local';
  }

  // 5. Transactional Keywords
  if (/\b(buy|order|purchase|pricing|price|cost|hire|book|checkout|get started|trial)\b/i.test(kw)) {
    return 'transactional';
  }

  // 6. Commercial Keywords
  if (/\b(best|top|review|reviews|software|tools|services|solutions|provider|agency)\b/i.test(kw)) {
    return 'commercial';
  }

  // 7. Pain-Point Keywords
  if (/\b(problem|error|fix|issue|slow|vulnerability|leak|risk|failed|prevent|stop|troubleshoot|solve)\b/i.test(kw)) {
    return 'pain_point';
  }

  // 8. Long-Tail Keywords
  const wordCount = kw.split(/\s+/).length;
  if (wordCount >= 4) {
    return 'long_tail';
  }

  // 9. Industry Keywords
  if (/\b(security|seo|intelligence|cloud|compliance|api|database|infra|network|ssl|dns|tls|cyber|devops)\b/i.test(kw)) {
    return 'industry';
  }

  // 10. Entity & Semantic Keywords
  if (/\b(architecture|framework|standard|protocol|rfc|schema|algorithm|engine|model)\b/i.test(kw)) {
    return 'entity_semantic';
  }

  // 11. Informational Keywords
  if (/\b(guide|tutorial|learn|definition|tips|examples|overview|basics|how to)\b/i.test(kw)) {
    return 'informational';
  }

  // 12. Core Keywords (default)
  return 'core';
}

/**
 * Calculates estimated business value score (0-100) based on intent and category.
 */
function calculateBusinessValue(intent, category) {
  let score = 50;

  // Intent weighting
  if (intent === 'transactional') score += 35;
  else if (intent === 'commercial') score += 25;
  else if (intent === 'local') score += 20;
  else if (intent === 'informational') score += 10;
  else if (intent === 'navigational') score += 15;

  // Category weighting
  if (category === 'comparison' || category === 'transactional') score += 10;
  if (category === 'pain_point') score += 10;
  if (category === 'core') score += 10;

  return Math.min(100, Math.max(20, score));
}

/**
 * Enriches and expands discovered keyword candidates into structured data model records.
 *
 * @param {Array<Object>} discoveredKeywords
 * @param {Object} context - { primaryDomain, competitorDomain, industry, location }
 * @returns {Array<Object>} Structured keyword records
 */
function expandAndEnrichKeywords(discoveredKeywords = [], context = {}) {
  return discoveredKeywords.map((rawRecord, index) => {
    const kw = rawRecord.keyword;
    const intent = classifyKeywordIntent(kw);
    const category = categorizeKeyword(kw, context);
    const businessValue = calculateBusinessValue(intent, category);

    return {
      id: `kw-${index + 1}-${Buffer.from(kw).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 8)}`,
      keyword: kw,
      category,
      intent,
      source: rawRecord.source || 'crawled_content',
      sourceType: rawRecord.sourceType || 'content_ngram',
      originatingDomain: rawRecord.originatingDomain || context.primaryDomain,
      primaryPresent: Boolean(rawRecord.primaryPresent),
      competitorPresent: Boolean(rawRecord.competitorPresent),
      primaryTargetPage: rawRecord.primaryPresent ? (rawRecord.targetPageUrl || context.primaryDomain) : null,
      competitorTargetPage: rawRecord.competitorPresent ? (rawRecord.competitorTargetPage || context.competitorDomain) : null,

      // Third-party metric placeholders — Section 7 strictly enforces:
      // "All data fields must be nullable and source-aware. Missing values must not be represented as fabricated zero values."
      searchVolume: null,
      volumeStatus: 'UNAVAILABLE — provider integration required',
      cpc: null,
      keywordDifficulty: null,
      rankingPosition: null,
      competitorRankingPosition: null,

      // Computed dynamic metrics
      relevanceScore: Math.round((rawRecord.relevanceScore || 0.8) * 100) / 100,
      businessValue,
      confidence: rawRecord.sourceType.startsWith('heading') || rawRecord.sourceType.startsWith('title') ? 0.95 : 0.85,
      lastChecked: new Date().toISOString(),
    };
  });
}

module.exports = {
  classifyKeywordIntent,
  categorizeKeyword,
  calculateBusinessValue,
  expandAndEnrichKeywords,
};
