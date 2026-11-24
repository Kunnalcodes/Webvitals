/**
 * Keyword Semantic Clustering & Topic Mapping Engine — WebVitals 2.0
 *
 * Groups keywords into hierarchical topic clusters, intent groups, and topic maps.
 * Identifies keyword cannibalization risks where multiple internal pages target the same query.
 */

'use strict';

/**
 * Computes Jaccard word token similarity between two phrases.
 */
function tokenSimilarity(a, b) {
  const setA = new Set((a || '').toLowerCase().split(/\s+/).filter(w => w.length > 2));
  const setB = new Set((b || '').toLowerCase().split(/\s+/).filter(w => w.length > 2));
  if (setA.size === 0 || setB.size === 0) return 0;

  let intersection = 0;
  setA.forEach(w => {
    if (setB.has(w)) intersection++;
  });

  const union = setA.size + setB.size - intersection;
  return union > 0 ? intersection / union : 0;
}

/**
 * Extracts a representative parent topic name from a cluster of keywords.
 */
function deriveTopicName(keywords = []) {
  if (keywords.length === 0) return 'General Topics';
  // Count word frequencies
  const wordFreq = new Map();
  keywords.forEach(k => {
    const tokens = (k.keyword || '').toLowerCase().split(/\s+/).filter(w => w.length > 3);
    tokens.forEach(t => {
      wordFreq.set(t, (wordFreq.get(t) || 0) + 1);
    });
  });

  const sortedWords = Array.from(wordFreq.entries()).sort((a, b) => b[1] - a[1]);
  if (sortedWords.length >= 2) {
    return `${capitalize(sortedWords[0][0])} & ${capitalize(sortedWords[1][0])}`;
  } else if (sortedWords.length === 1) {
    return `${capitalize(sortedWords[0][0])} Solutions`;
  }
  return capitalize(keywords[0].keyword || 'Topic Cluster');
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Clusters a list of enriched keywords into semantic topic clusters.
 *
 * @param {Array<Object>} enrichedKeywords
 * @returns {Array<Object>} Array of Topic Clusters
 */
function clusterKeywords(enrichedKeywords = []) {
  const clusters = [];
  const assigned = new Set();

  // 1. Group by high semantic token similarity (threshold >= 0.35)
  for (let i = 0; i < enrichedKeywords.length; i++) {
    if (assigned.has(i)) continue;
    const seed = enrichedKeywords[i];
    const currentCluster = [seed];
    assigned.add(i);

    for (let j = i + 1; j < enrichedKeywords.length; j++) {
      if (assigned.has(j)) continue;
      const candidate = enrichedKeywords[j];
      const sim = tokenSimilarity(seed.keyword, candidate.keyword);

      if (sim >= 0.35 || seed.category === candidate.category && sim >= 0.20) {
        currentCluster.push(candidate);
        assigned.add(j);
      }
    }

    const parentTopic = deriveTopicName(currentCluster);
    const primaryCount = currentCluster.filter(k => k.primaryPresent).length;
    const competitorCount = currentCluster.filter(k => k.competitorPresent).length;

    clusters.push({
      id: `cluster-${clusters.length + 1}`,
      name: parentTopic,
      keywordCount: currentCluster.length,
      primaryCoverageRatio: Math.round((primaryCount / currentCluster.length) * 100),
      competitorCoverageRatio: Math.round((competitorCount / currentCluster.length) * 100),
      primaryPages: [...new Set(currentCluster.map(k => k.primaryTargetPage).filter(Boolean))],
      competitorPages: [...new Set(currentCluster.map(k => k.competitorTargetPage).filter(Boolean))],
      keywords: currentCluster,
    });
  }

  // Sort clusters by keyword count descending
  return clusters.sort((a, b) => b.keywordCount - a.keywordCount);
}

/**
 * Builds the visual Topic Map comparing primary vs competitor page coverage.
 *
 * @param {Array<Object>} clusters
 * @returns {Array<Object>} Topic Map items
 */
function buildTopicMap(clusters = []) {
  return clusters.slice(0, 10).map((cluster) => {
    const missingPages = cluster.competitorCoverageRatio > cluster.primaryCoverageRatio;
    return {
      mainTopic: cluster.name,
      keywordCount: cluster.keywordCount,
      subtopics: cluster.keywords.slice(0, 5).map(k => k.keyword),
      intentMix: [...new Set(cluster.keywords.map(k => k.intent))],
      primaryCoverage: `${cluster.primaryCoverageRatio}%`,
      competitorCoverage: `${cluster.competitorCoverageRatio}%`,
      existingPrimaryPages: cluster.primaryPages,
      competitorPages: cluster.competitorPages,
      recommendedAsset: missingPages
        ? `Develop dedicated pillar asset for ${cluster.name} to close competitor coverage gap`
        : `Expand supporting cluster content and internal link depth for ${cluster.name}`,
    };
  });
}

/**
 * Detects internal keyword cannibalization risks.
 *
 * @param {Array<Object>} primaryPages - Crawled pages for primary site
 * @param {Array<Object>} keywords - Primary keywords
 * @returns {Array<Object>} Detected cannibalization risks
 */
function detectCannibalizationRisks(primaryPages = [], keywords = []) {
  const risks = [];

  // Group keywords targeting primary site
  const primaryKw = keywords.filter(k => k.primaryPresent);

  for (let i = 0; i < primaryPages.length; i++) {
    for (let j = i + 1; j < primaryPages.length; j++) {
      const pageA = primaryPages[i];
      const pageB = primaryPages[j];

      const simTitle = tokenSimilarity(pageA.title, pageB.title);
      const simH1 = tokenSimilarity(
        (pageA.headings?.h1 || []).join(' '),
        (pageB.headings?.h1 || []).join(' ')
      );

      if (simTitle >= 0.50 || simH1 >= 0.50) {
        risks.push({
          type: 'CANONICAL_OR_TOPIC_OVERLAP',
          severity: 'Moderate',
          pageA: pageA.url,
          pageB: pageB.url,
          sharedIntent: classifyPageType(pageA.url),
          explanation: `Pages "${pageA.title}" and "${pageB.title}" share high keyword overlap (${Math.round(Math.max(simTitle, simH1) * 100)}% title/H1 similarity).`,
          recommendation: 'Differentiate search intent, consolidate into a single authoritative pillar page, or set canonical link.',
        });
      }
    }
  }

  return risks;
}

function classifyPageType(urlStr) {
  const path = (urlStr || '').toLowerCase();
  if (/pricing|plans/i.test(path)) return 'Transactional / Pricing';
  if (/service|solution/i.test(path)) return 'Commercial / Services';
  if (/blog|guide|doc/i.test(path)) return 'Informational / Editorial';
  return 'General Landing';
}

module.exports = {
  tokenSimilarity,
  clusterKeywords,
  buildTopicMap,
  detectCannibalizationRisks,
};
