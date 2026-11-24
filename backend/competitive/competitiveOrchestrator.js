/**
 * Competitive Scan & Intelligence Orchestrator — WebVitals 2.0
 *
 * Implements the complete 10-step competitive intelligence analysis workflow:
 *   Step 1: Validate and crawl primary domain
 *   Step 2: Validate and crawl competitor domain
 *   Step 3: Discover indexed & accessible page inventories
 *   Step 4: Multi-source keyword discovery & expansion
 *   Step 5: Compare SEO, GEO, AEO, content, and authority signals
 *   Step 6: Normalize evidence and eliminate duplicates
 *   Step 7: Synthesize findings via Vertex AI
 *   Step 8: Generate actionable competitive growth report
 *   Step 9: Compute dynamic opportunity prioritization & "How to Compete" roadmap
 *   Step 10: Compile unified JSON report for interactive exploration & export
 */

'use strict';

const crypto = require('crypto');
const { validateCompetitivePair } = require('./domainValidator');
const { crawlDomainInventory } = require('./competitorCrawler');
const { discoverCompetitiveKeywords } = require('./keywordDiscoveryService');
const { expandAndEnrichKeywords } = require('./keywordExpansionService');
const { clusterKeywords, buildTopicMap, detectCannibalizationRisks } = require('./keywordClusteringService');
const { analyzeKeywordGaps } = require('./keywordGapEngine');
const { analyzeContentGaps } = require('./contentGapEngine');
const { compareSeoInfrastructure, reverseEngineerSeoStrategies } = require('./seoComparisonEngine');
const { compareGeoReadiness } = require('./geoComparisonEngine');
const { compareAeoReadiness } = require('./aeoComparisonEngine');
const { compareAuthoritySignals } = require('./authorityAnalysisService');
const { generateGrowthStrategy } = require('./growthStrategyGenerator');
const { generateCompetitiveAiAnalysis } = require('./vertexCompetitiveAnalyst');
const { emitProgress } = require('../scan/progressEmitter');

/**
 * Calculates overall competitive position assessment (Section 2).
 */
function evaluateCompetitivePosition(overviewMetrics = {}) {
  let primaryPoints = 0;
  let competitorPoints = 0;

  if (overviewMetrics.seoLeader === 'Primary') primaryPoints += 2;
  else if (overviewMetrics.seoLeader === 'Competitor') competitorPoints += 2;

  if (overviewMetrics.geoLeader === 'Primary') primaryPoints += 2;
  else if (overviewMetrics.geoLeader === 'Competitor') competitorPoints += 2;

  if (overviewMetrics.aeoLeader === 'Primary') primaryPoints += 2;
  else if (overviewMetrics.aeoLeader === 'Competitor') competitorPoints += 2;

  if ((overviewMetrics.primaryKeywords || 0) > (overviewMetrics.competitorKeywords || 0)) primaryPoints += 1;
  else if ((overviewMetrics.competitorKeywords || 0) > (overviewMetrics.primaryKeywords || 0)) competitorPoints += 1;

  if ((overviewMetrics.primaryPagesDiscovered || 0) > (overviewMetrics.competitorPagesDiscovered || 0)) primaryPoints += 1;
  else if ((overviewMetrics.competitorPagesDiscovered || 0) > (overviewMetrics.primaryPagesDiscovered || 0)) competitorPoints += 1;

  const diff = primaryPoints - competitorPoints;

  if (diff >= 3) {
    return {
      status: 'COMPETITIVE_ADVANTAGE',
      label: 'Competitive Advantage',
      summary: `Your business maintains clear leadership across technical architecture, content depth, and answer readiness. Focus on protecting high-value money pages and expanding long-tail clusters.`,
      score: primaryPoints,
    };
  } else if (diff <= -3) {
    return {
      status: 'STRONG_COMPETITOR_ADVANTAGE',
      label: 'Strong Competitor Advantage',
      summary: `Competitor currently leads across core SEO infrastructure, keyword targeting depth, and answer completeness. Execute the Phase 1 & 2 Roadmap to recapture commercial intent.`,
      score: competitorPoints,
    };
  } else if (Math.abs(diff) <= 1) {
    return {
      status: 'SIMILAR_POSITIONING',
      label: 'Similar Positioning / Parity',
      summary: `Both businesses are closely matched across core metrics. Technical execution, Schema entity clarity, and speed of content publication will determine market leadership.`,
      score: 5,
    };
  } else {
    return {
      status: 'EMERGING_OPPORTUNITY',
      label: 'Emerging Opportunity',
      summary: `Primary site has strong fundamentals with high-priority keyword and content gaps that can be captured with moderate engineering effort.`,
      score: 6,
    };
  }
}

/**
 * Executes full 10-step competitive intelligence analysis.
 *
 * @param {string} primaryInput - Primary website URL or domain
 * @param {string} competitorInput - Competitor website URL or domain
 * @param {Object} [options] - Optional scan parameters
 * @returns {Promise<Object>} Full Competitive Intelligence Report
 */
async function performCompetitiveAnalysis(primaryInput, competitorInput, options = {}) {
  const scanId = `comp-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const startTime = Date.now();

  const reportProgress = (stage, progress, message) => {
    emitProgress(scanId, { stage, progress, message });
  };

  // Step 1: Validate and normalize both inputs
  reportProgress('VALIDATING_DOMAINS', 10, 'Validating domains and enforcing SSRF guards...');
  const validation = validateCompetitivePair(primaryInput, competitorInput, options);
  if (!validation.isValid) {
    throw new Error(validation.error);
  }

  const { primary: pTarget, competitor: cTarget, options: resolvedOptions } = validation;

  // Step 2 & 3: Crawl and build page inventories
  reportProgress('CRAWLING_PRIMARY', 25, `Discovering indexed pages & sitemap for ${pTarget.domain}...`);
  const primaryInventory = await crawlDomainInventory(pTarget, { maxAdditionalPages: 5 });

  reportProgress('CRAWLING_COMPETITOR', 40, `Discovering indexed pages & sitemap for ${cTarget.domain}...`);
  const competitorInventory = await crawlDomainInventory(cTarget, { maxAdditionalPages: 5 });

  // Step 4: Multi-source keyword discovery & expansion
  reportProgress('DISCOVERING_KEYWORDS', 55, 'Running multi-source keyword discovery pipeline...');
  const rawDiscovered = discoverCompetitiveKeywords(
    primaryInventory,
    competitorInventory,
    resolvedOptions.businessObjectives
  );

  const context = {
    primaryDomain: pTarget.domain,
    competitorDomain: cTarget.domain,
    industry: resolvedOptions.industry,
    location: resolvedOptions.targetLocation,
  };

  const enrichedKeywords = expandAndEnrichKeywords(rawDiscovered.combinedKeywords, context);

  // Step 5: Keyword clustering & Cannibalization risks
  reportProgress('CLUSTERING_TOPICS', 65, 'Clustering topics, intent mapping, and detecting cannibalization...');
  const clusters = clusterKeywords(enrichedKeywords);
  const topicMap = buildTopicMap(clusters);
  const cannibalizationRisks = detectCannibalizationRisks(
    [primaryInventory.homepage, ...(primaryInventory.subPages || [])],
    enrichedKeywords
  );

  // Step 6: Keyword gap analysis & Content gap analysis
  reportProgress('EVALUATING_GAPS', 75, 'Analyzing keyword gaps, content coverage, and opportunity scores...');
  const keywordGapReport = analyzeKeywordGaps(enrichedKeywords, context);
  const contentGapReport = analyzeContentGaps(primaryInventory, competitorInventory, keywordGapReport);

  // Step 7: Technical SEO, GEO, and AEO Comparisons
  reportProgress('BENCHMARKING_ENGINES', 85, 'Benchmarking SEO infrastructure, GEO machine readability, and AEO answers...');
  const seoComparison = compareSeoInfrastructure(primaryInventory, competitorInventory);
  const seoStrategies = reverseEngineerSeoStrategies(primaryInventory, competitorInventory);
  const geoComparison = compareGeoReadiness(primaryInventory, competitorInventory);
  const aeoComparison = compareAeoReadiness(primaryInventory, competitorInventory, enrichedKeywords);
  const authorityComparison = compareAuthoritySignals(primaryInventory, competitorInventory);

  // Step 8: 5-Phase Growth Strategy Roadmap
  reportProgress('GENERATING_ROADMAP', 92, 'Generating "How to Compete" 5-phase growth roadmap...');
  const growthStrategy = generateGrowthStrategy(
    primaryInventory,
    competitorInventory,
    keywordGapReport,
    contentGapReport,
    seoComparison
  );

  // Step 9: Vertex AI Strategic Interpretation (with deterministic fallback)
  reportProgress('SYNTHESIZING_AI', 97, 'Synthesizing strategic analyst narrative with Vertex AI...');
  const boundedAiEvidence = {
    primaryDomain: pTarget.domain,
    primaryStatus: primaryInventory.statusCode,
    primaryElapsedMs: primaryInventory.elapsedMs,
    competitorDomain: cTarget.domain,
    competitorStatus: competitorInventory.statusCode,
    competitorElapsedMs: competitorInventory.elapsedMs,
    seoLeader: seoComparison.summary.infrastructureLeader,
    primarySeoWins: seoComparison.summary.primaryWins,
    competitorSeoWins: seoComparison.summary.competitorWins,
    primaryGeoScore: geoComparison.primaryGeoScore,
    competitorGeoScore: geoComparison.competitorGeoScore,
    geoLeader: geoComparison.geoLeader,
    primaryAeoScore: aeoComparison.primaryAeoScore,
    competitorAeoScore: aeoComparison.competitorAeoScore,
    aeoLeader: aeoComparison.aeoLeader,
    totalKeywords: enrichedKeywords.length,
    topGaps: (keywordGapReport.buckets?.competitorGaps || []).slice(0, 5).map(k => k.keyword),
    contentGaps: (contentGapReport.gaps || []).slice(0, 3).map(g => g.topic),
  };

  const aiIntelligence = await generateCompetitiveAiAnalysis(boundedAiEvidence);

  // Step 10: Compile Final Unified Report
  const overviewMetrics = {
    seoLeader: seoComparison.summary.infrastructureLeader,
    geoLeader: geoComparison.geoLeader,
    aeoLeader: aeoComparison.aeoLeader,
    primaryKeywords: rawDiscovered.primaryKeywords.length,
    competitorKeywords: rawDiscovered.competitorKeywords.length,
    primaryPagesDiscovered: primaryInventory.totalPagesDiscovered,
    competitorPagesDiscovered: competitorInventory.totalPagesDiscovered,
  };

  const competitivePosition = evaluateCompetitivePosition(overviewMetrics);

  reportProgress('COMPLETE', 100, 'Competitive intelligence audit completed successfully.');

  const report = {
    scanId,
    timestamp: new Date().toISOString(),
    elapsedMs: Date.now() - startTime,
    primary: {
      url: pTarget.url,
      domain: pTarget.domain,
      hostname: pTarget.hostname,
      statusCode: primaryInventory.statusCode,
      elapsedMs: primaryInventory.elapsedMs,
      pagesDiscovered: primaryInventory.totalPagesDiscovered,
      sitemapDiscovered: primaryInventory.sitemap.exists,
      robotsTxtDiscovered: primaryInventory.robotsTxt.exists,
    },
    competitor: {
      url: cTarget.url,
      domain: cTarget.domain,
      hostname: cTarget.hostname,
      statusCode: competitorInventory.statusCode,
      elapsedMs: competitorInventory.elapsedMs,
      pagesDiscovered: competitorInventory.totalPagesDiscovered,
      sitemapDiscovered: competitorInventory.sitemap.exists,
      robotsTxtDiscovered: competitorInventory.robotsTxt.exists,
    },
    options: resolvedOptions,
    competitivePosition,
    overviewComparison: [
      {
        metric: 'Technical SEO Infrastructure',
        primaryValue: `${seoComparison.summary.primaryWins} dimensions won`,
        competitorValue: `${seoComparison.summary.competitorWins} dimensions won`,
        difference: `${Math.abs(seoComparison.summary.primaryWins - seoComparison.summary.competitorWins)} wins diff`,
        interpretation: `Technical crawlability and indexability leadership: ${seoComparison.summary.infrastructureLeader}.`,
        confidence: 0.95,
      },
      {
        metric: 'GEO Machine Readability',
        primaryValue: `${geoComparison.primaryGeoScore}/100`,
        competitorValue: `${geoComparison.competitorGeoScore}/100`,
        difference: `${geoComparison.scoreDifference} pts`,
        interpretation: `Generative engine readiness leadership: ${geoComparison.geoLeader}.`,
        confidence: 0.90,
      },
      {
        metric: 'AEO Direct Answer Quality',
        primaryValue: `${aeoComparison.primaryAeoScore}/100`,
        competitorValue: `${aeoComparison.competitorAeoScore}/100`,
        difference: `${aeoComparison.scoreDifference} pts`,
        interpretation: `Answer Engine question answering leadership: ${aeoComparison.aeoLeader}.`,
        confidence: 0.88,
      },
      {
        metric: 'Keyword Coverage Universe',
        primaryValue: `${rawDiscovered.primaryKeywords.length} targeted queries`,
        competitorValue: `${rawDiscovered.competitorKeywords.length} targeted queries`,
        difference: `${Math.abs(rawDiscovered.primaryKeywords.length - rawDiscovered.competitorKeywords.length)} queries`,
        interpretation: rawDiscovered.primaryKeywords.length >= rawDiscovered.competitorKeywords.length ? 'Primary leads topic breath.' : 'Competitor covers a wider keyword surface.',
        confidence: 0.92,
      },
      {
        metric: 'Indexed Content Depth',
        primaryValue: `${contentGapReport.contentDepth.primaryAverageWords} avg words/page`,
        competitorValue: `${contentGapReport.contentDepth.competitorAverageWords} avg words/page`,
        difference: `${contentGapReport.contentDepth.differenceWords} words diff`,
        interpretation: `Depth advantage sits with ${contentGapReport.contentDepth.depthAdvantage}.`,
        confidence: 0.90,
      },
      {
        metric: 'External Authority & Backlinks',
        primaryValue: 'Unavailable — data source required',
        competitorValue: 'Unavailable — data source required',
        difference: 'N/A',
        interpretation: 'Requires active Moz, Ahrefs, or Semrush API credentials.',
        confidence: 0.0,
      },
    ],
    keywordIntelligence: {
      summary: keywordGapReport.summary,
      allKeywords: keywordGapReport.allKeywords,
      buckets: keywordGapReport.buckets,
      topOpportunities: keywordGapReport.topOpportunities,
    },
    topicClustering: {
      clusters,
      topicMap,
      cannibalizationRisks,
    },
    contentGapAnalysis: contentGapReport,
    seoComparison: {
      infrastructure: seoComparison,
      strategies: seoStrategies,
    },
    geoComparison,
    aeoComparison,
    authorityComparison,
    growthStrategy,
    aiIntelligence,
  };

  return report;
}

module.exports = {
  performCompetitiveAnalysis,
  evaluateCompetitivePosition,
};
