/**
 * GEO (Generative Engine Optimization) Competitive Intelligence Engine — WebVitals 2.0
 *
 * Compares primary vs competitor across machine readability, entity clarity,
 * structured definitions, source attribution, and AI crawler policy directives.
 */

'use strict';

const { analyzeEntityAndBrand } = require('../seo/intelligence/entityAnalyzer');

/**
 * Evaluates and compares GEO readiness between primary and competitor.
 *
 * @param {Object} primaryInventory
 * @param {Object} competitorInventory
 * @returns {Object} GEO comparative analysis
 */
function compareGeoReadiness(primaryInventory, competitorInventory) {
  const pHome = primaryInventory.homepage || {};
  const cHome = competitorInventory.homepage || {};
  const pSemantic = pHome.semantic || {};
  const cSemantic = cHome.semantic || {};

  // Entity Analysis
  const pEntity = analyzeEntityAndBrand(
    { jsonLd: [], openGraph: {}, links: [] },
    { cleanBodyText: pSemantic.cleanBodyText || '' },
    primaryInventory.url
  );
  const cEntity = analyzeEntityAndBrand(
    { jsonLd: [], openGraph: {}, links: [] },
    { cleanBodyText: cSemantic.cleanBodyText || '' },
    competitorInventory.url
  );

  // Machine Readability Factors
  const pTables = pSemantic.tables?.length || 0;
  const cTables = cSemantic.tables?.length || 0;
  const pDefinitions = pSemantic.definitions?.length || 0;
  const cDefinitions = cSemantic.definitions?.length || 0;

  // AI Crawler Access (robots.txt)
  const pRobots = primaryInventory.robotsTxt || {};
  const cRobots = competitorInventory.robotsTxt || {};

  const pBlockedAi = (pRobots.content.match(/disallow:\s*\/.*(?:gptbot|claude|perplexity|google-extended)/gi) || []).length;
  const cBlockedAi = (cRobots.content.match(/disallow:\s*\/.*(?:gptbot|claude|perplexity|google-extended)/gi) || []).length;

  const pAiStatus = pBlockedAi > 0 ? `Restricted (${pBlockedAi} bots restricted)` : 'Open / Permissive';
  const cAiStatus = cBlockedAi > 0 ? `Restricted (${cBlockedAi} bots restricted)` : 'Open / Permissive';

  // GEO Dimension Comparison
  const dimensions = [
    {
      dimension: 'Entity Clarity & Disambiguation',
      primaryScore: pHome.schemaTypes?.length > 0 ? 85 : 55,
      competitorScore: cHome.schemaTypes?.length > 0 ? 85 : 55,
      primaryObservation: pHome.schemaTypes?.length > 0 ? `Schema types: ${pHome.schemaTypes.join(', ')}` : 'No schema entity detected',
      competitorObservation: cHome.schemaTypes?.length > 0 ? `Schema types: ${cHome.schemaTypes.join(', ')}` : 'No schema entity detected',
      advantage: (pHome.schemaTypes?.length || 0) > (cHome.schemaTypes?.length || 0) ? 'Primary' :
                 (cHome.schemaTypes?.length || 0) > (pHome.schemaTypes?.length || 0) ? 'Competitor' : 'Parity',
      significance: 'Generative engines rely on explicit entity definitions to ground citation graphs.',
    },
    {
      dimension: 'Machine Readability & Semantic Extraction',
      primaryScore: (pTables > 0 || pDefinitions > 0) ? 80 : 50,
      competitorScore: (cTables > 0 || cDefinitions > 0) ? 80 : 50,
      primaryObservation: `${pTables} tables, ${pDefinitions} definition lists, boilerplate: ${pSemantic.boilerplateRatio || '25%'}`,
      competitorObservation: `${cTables} tables, ${cDefinitions} definition lists, boilerplate: ${cSemantic.boilerplateRatio || '25%'}`,
      advantage: (pTables + pDefinitions) > (cTables + cDefinitions) ? 'Primary' :
                 (cTables + cDefinitions) > (pTables + pDefinitions) ? 'Competitor' : 'Parity',
      significance: 'Structured tables and definition lists (<dl>, <dt>, <dd>) are easiest for LLMs to extract without hallucinations.',
    },
    {
      dimension: 'AI Crawler Accessibility',
      primaryScore: pBlockedAi === 0 ? 90 : 60,
      competitorScore: cBlockedAi === 0 ? 90 : 60,
      primaryObservation: pAiStatus,
      competitorObservation: cAiStatus,
      advantage: pBlockedAi < cBlockedAi ? 'Primary' : cBlockedAi < pBlockedAi ? 'Competitor' : 'Parity',
      significance: 'Permitting GPTBot, PerplexityBot, and Google-Extended ensures content is indexed in AI search databases.',
    },
    {
      dimension: 'Content Citation Readiness',
      primaryScore: (pSemantic.cleanBodyText || '').length >= 1500 ? 75 : 55,
      competitorScore: (cSemantic.cleanBodyText || '').length >= 1500 ? 75 : 55,
      primaryObservation: `${(pSemantic.cleanBodyText || '').length} characters of extractable body copy`,
      competitorObservation: `${(cSemantic.cleanBodyText || '').length} characters of extractable body copy`,
      advantage: (pSemantic.cleanBodyText || '').length > (cSemantic.cleanBodyText || '').length ? 'Primary' : 'Competitor',
      significance: 'In-depth factual explanations provide the statistical and semantic substance required for AI citations.',
    },
  ];

  // Calculate Overall GEO Scores (0-100)
  const primaryGeoScore = Math.round(dimensions.reduce((acc, d) => acc + d.primaryScore, 0) / dimensions.length);
  const competitorGeoScore = Math.round(dimensions.reduce((acc, d) => acc + d.competitorScore, 0) / dimensions.length);

  return {
    primaryGeoScore,
    competitorGeoScore,
    geoLeader: primaryGeoScore > competitorGeoScore ? 'Primary' : competitorGeoScore > primaryGeoScore ? 'Competitor' : 'Parity',
    scoreDifference: Math.abs(primaryGeoScore - competitorGeoScore),
    dimensions,
    aiVisibilityDisclaimer: {
      status: 'READINESS_INFERRED',
      message: 'Direct AI citation measurement across closed platforms requires verified live prompt logging. Analysis reflects structural LLM extraction readiness.',
    },
  };
}

module.exports = {
  compareGeoReadiness,
};
