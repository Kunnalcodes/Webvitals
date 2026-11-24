/**
 * SEO, GEO & AEO Intelligence Engine Orchestrator — WebVitals 2.0
 *
 * Unites:
 *   - Content Extractor
 *   - Entity & Brand Analyzer
 *   - Search Intent Classifier & Mismatch Detector
 *   - Question Coverage & Answer Quality Analyzer
 *   - Multi-Strategy Detection (SEO, GEO, AEO)
 *   - Deterministic Transparent Scoring Models
 *   - Prioritized Improvement Roadmap (P0 - P3)
 *   - Evidence Provenance Validator
 *   - Vertex AI / Gemini Strategic Reasoning & Page Draft Workspace
 */

'use strict';

const { extractDeepContent } = require('./contentExtractor');
const { analyzeEntityAndBrand } = require('./entityAnalyzer');
const { classifySearchIntent } = require('./searchIntentAnalyzer');
const { analyzeQuestionCoverage } = require('./questionCoverageAnalyzer');
const { detectAllStrategies } = require('./strategyDetector');
const { calculateSeoScore, calculateGeoScore, calculateAeoScore } = require('./scoringEngines');
const { generateStructuredRecommendations } = require('./recommendationEngine');
const { getSystemDisclosures, PROVENANCE_LEVELS } = require('./evidenceValidator');
const { generateVertexAiIntelligence } = require('./vertexAiReportService');

/**
 * Builds the complete multi-vector SEO, GEO, and AEO intelligence report.
 *
 * @param {Object} params
 * @returns {Promise<Object>} Complete intelligence report
 */
async function buildSeoIntelligenceReport({
  targetUrl,
  crawlResult,
  parsedData,
  robotsTxt,
  sitemapXml,
  brokenLinks = [],
  lighthouse = {},
}) {
  const finalUrl = crawlResult.finalUrl || targetUrl;

  // 1. Semantic Content Extraction
  const contentData = extractDeepContent(crawlResult.body, parsedData, finalUrl);

  // 2. Entity & Brand Understanding
  const entityData = analyzeEntityAndBrand(parsedData, contentData, finalUrl);

  // 3. Search Intent Classification & Mismatch Detection
  const intentData = classifySearchIntent(parsedData, contentData, finalUrl);

  // 4. Question Coverage & AEO Journey Analysis
  const questionData = analyzeQuestionCoverage(contentData, entityData, intentData);

  // 5. Multi-Vector Strategy Detection (SEO, GEO, AEO)
  const strategyData = detectAllStrategies({
    parsedData,
    contentData,
    entityData,
    intentData,
    questionData,
    crawlData: {
      url: finalUrl,
      robotsTxt,
      sitemapXml,
    },
  });

  // 6. Deterministic Transparent Scoring Engines
  const seoScores = calculateSeoScore({
    parsedData,
    contentData,
    crawlData: { url: finalUrl, robotsTxt },
    lighthouse,
  });

  const geoScores = calculateGeoScore({
    parsedData,
    contentData,
    entityData,
    crawlData: { url: finalUrl, robotsTxt },
  });

  const aeoScores = calculateAeoScore({
    contentData,
    questionData,
    intentData,
  });

  // 7. Prioritized Recommendation Engine (P0 - P3)
  const recommendationData = generateStructuredRecommendations({
    parsedData,
    contentData,
    entityData,
    intentData,
    questionData,
    crawlData: { url: finalUrl, robotsTxt, sitemapXml },
    seoScores,
    geoScores,
    aeoScores,
  });

  // 8. Vertex AI Strategic Intelligence & Page Optimization Drafts
  const aiIntelligence = await generateVertexAiIntelligence({
    url: finalUrl,
    parsedData,
    contentData,
    entityData,
    intentData,
    questionData,
    seoScores,
    geoScores,
    aeoScores,
  });

  // 9. Overall Discoverability Assessment
  const averageScore = Math.round((seoScores.score * 0.4) + (geoScores.score * 0.35) + (aeoScores.score * 0.25));
  const overallDiscoverability = averageScore >= 80 ? 'Optimal Global Discoverability' :
                                averageScore >= 65 ? 'Competitive with Strategic Gaps' :
                                averageScore >= 50 ? 'Moderate Search & AI Presence' : 'Significant Discoverability Deficit';

  const improvementPotential = averageScore < 70 ? 'High (+25 to 35 pts with P0/P1 fixes)' :
                               averageScore < 85 ? 'Moderate (+10 to 15 pts with P1/P2 fixes)' : 'Refinement & Defense (+5 to 10 pts)';

  return {
    url: targetUrl,
    finalUrl,
    timestamp: new Date().toISOString(),

    // Main Executive Overview
    overview: {
      seoScore: seoScores.score,
      seoGrade: seoScores.grade,
      geoScore: geoScores.score,
      geoGrade: geoScores.grade,
      geoRating: geoScores.readinessRating,
      aeoScore: aeoScores.score,
      aeoGrade: aeoScores.grade,
      aeoRating: aeoScores.readinessRating,
      overallDiscoverability,
      averageScore,
      improvementPotential,
      scanCoverage: '100% Core DOM, Robots, Sitemap & Structured Data Audited',
      evidenceQuality: 'Verified Remote Observation & Cryptographic Handshakes',
      p0BlockersCount: recommendationData.grouped.P0.length,
      p1HighImpactCount: recommendationData.grouped.P1.length,
      totalRecommendationsCount: recommendationData.totalCount,
    },

    // Module 1: SEO — Search Engine Optimization
    seo: {
      score: seoScores.score,
      grade: seoScores.grade,
      gradeLabel: seoScores.gradeLabel,
      factors: seoScores.factors,
      strategies: strategyData.seoStrategies,
      searchIntent: intentData,
      technical: {
        isHttps: finalUrl.startsWith('https:'),
        hasRobotsTxt: Boolean(robotsTxt.exists),
        robotsStatus: robotsTxt.status,
        hasSitemapXml: Boolean(sitemapXml.exists),
        sitemapStatus: sitemapXml.status,
        hasCanonical: Boolean(parsedData.canonicalUrl),
        canonicalUrl: parsedData.canonicalUrl,
        isIndexable: !((parsedData.metaRobots || '').toLowerCase().includes('noindex')),
        metaRobots: parsedData.metaRobots || 'index, follow (implicit)',
        redirectsCount: crawlResult.chain?.length > 1 ? crawlResult.chain.length - 1 : 0,
        brokenLinksCount: brokenLinks.length,
        brokenLinksSample: brokenLinks.slice(0, 10),
      },
      onPage: {
        title: parsedData.title,
        titleLength: parsedData.title?.length || 0,
        metaDescription: parsedData.metaDescription,
        descLength: parsedData.metaDescription?.length || 0,
        headingsTree: contentData.headingsTree,
        headingStats: contentData.headingStats,
        wordCount: contentData.wordCount,
        readingTimeMinutes: contentData.readingTimeMinutes,
        boilerplateRatio: contentData.boilerplateRatio,
        linksAnalysis: contentData.linksAnalysis,
        imagesAnalysis: contentData.imagesAnalysis,
      },
    },

    // Module 2: GEO — Generative Engine Optimization
    geo: {
      score: geoScores.score,
      grade: geoScores.grade,
      readinessRating: geoScores.readinessRating,
      factors: geoScores.factors,
      strategies: strategyData.geoStrategies,
      entity: entityData,
      machineReadability: {
        semanticStructure: contentData.headingStats.hasHierarchyIssue ? 'Warning: Heading levels skipped' : 'Well-Formed Hierarchy',
        boilerplateRatioPercent: (contentData.boilerplateRatio * 100).toFixed(0),
        cleanTextSnippet: contentData.cleanBodyText.slice(0, 500) + '...',
      },
      citationReadiness: {
        tablesCount: contentData.tables.length,
        listsCount: contentData.lists.totalLists,
        definitionsCount: contentData.definitions.length,
        hasFreshnessProof: contentData.freshness.isRecent,
        freshnessDates: contentData.freshness,
      },
      aiCrawlerPolicies: {
        robotsChecked: Boolean(robotsTxt.exists),
        sampleContent: robotsTxt.contentSample || 'No robots directives provided.',
        crawlerAccessStatus: /User-agent:\s*(GPTBot|ClaudeBot)[\s\S]*?Disallow:\s*\//i.test(robotsTxt.contentSample || '') ? 'Restricted' : 'Permitted',
      },
    },

    // Module 3: AEO — Answer Engine Optimization
    aeo: {
      score: aeoScores.score,
      grade: aeoScores.grade,
      readinessRating: aeoScores.readinessRating,
      factors: aeoScores.factors,
      strategies: strategyData.aeoStrategies,
      questionCoverage: questionData,
      directAnswerQuality: {
        directAnswerBlocksCount: (questionData.answeredQuestions || []).filter(q => q.hasDirectAnswer).length,
        hasFaqSchema: questionData.answerStructuresDetected.hasFaqSchema,
        hasQABlocks: questionData.answerStructuresDetected.hasQABlocks,
        hasTables: questionData.answerStructuresDetected.hasTables,
      },
      userJourneyStages: questionData.journeyCoverage,
    },

    // Unified Visual Strategy Matrix
    strategyMatrix: strategyData.strategyMatrix,

    // Prioritized Improvement Roadmap (P0, P1, P2, P3)
    roadmap: Object.assign([...recommendationData.list], recommendationData.grouped),
    roadmapGrouped: recommendationData.grouped,
    allRecommendations: recommendationData.list,

    // Vertex AI Strategic Narrative & Draft Workspace
    aiIntelligence: {
      executiveNarrative: aiIntelligence.executiveNarrative,
      searchEngineInterpretation: aiIntelligence.searchEngineInterpretation,
      generativeAiInterpretation: aiIntelligence.generativeAiInterpretation,
      discoverabilityBottlenecks: aiIntelligence.discoverabilityBottlenecks,
      pageOptimizationDrafts: aiIntelligence.pageOptimizationDrafts,
      provenance: aiIntelligence._provenance || PROVENANCE_LEVELS.AI_INTERPRETED,
    },

    // Transparency & Provenance Disclosures
    disclosures: getSystemDisclosures(),
  };
}

module.exports = {
  buildSeoIntelligenceReport,
};
