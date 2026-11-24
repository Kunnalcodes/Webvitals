/**
 * Keyword Gap Analysis & Opportunity Scoring Engine — WebVitals 2.0
 *
 * Evaluates competitive keyword gaps across 9 dynamic categories:
 *   1. Competitor keywords
 *   2. Shared keywords
 *   3. Competitor gaps
 *   4. Your opportunities
 *   5. Weak keywords
 *   6. Untapped opportunities
 *   7. Branded opportunities
 *   8. Local opportunities
 *   9. Question gaps
 *
 * Computes transparent opportunity scores (0-100) and actionable engineering recommendations.
 */

'use strict';

/**
 * Computes dynamic keyword opportunity score (0-100).
 *
 * @param {Object} kw - Enriched keyword record
 * @returns {Object} { score, priority }
 */
function calculateOpportunityScore(kw) {
  let score = kw.businessValue || 50;

  // Gap status bonus: competitor covers it, but primary lacks coverage
  if (kw.competitorPresent && !kw.primaryPresent) {
    score += 20; // High capture urgency
  } else if (!kw.competitorPresent && !kw.primaryPresent) {
    score += 15; // Untapped market potential
  } else if (kw.competitorPresent && kw.primaryPresent) {
    score += 10; // Head-to-head competition
  }

  // Intent weighting
  if (kw.intent === 'transactional') score += 15;
  else if (kw.intent === 'commercial') score += 10;
  else if (kw.category === 'question') score += 10;

  // Clamp 0-100
  const finalScore = Math.min(100, Math.max(25, Math.round(score)));

  let priority = 'P2';
  if (finalScore >= 85) priority = 'P0';
  else if (finalScore >= 70) priority = 'P1';
  else if (finalScore >= 50) priority = 'P2';
  else priority = 'P3';

  return { score: finalScore, priority };
}

/**
 * Analyzes keyword gap status and generates actionable competitive guidance.
 *
 * @param {Array<Object>} enrichedKeywords
 * @param {Object} context - { primaryDomain, competitorDomain, primaryPages, competitorPages }
 * @returns {Object} Gap analysis breakdown and prioritized opportunities
 */
function analyzeKeywordGaps(enrichedKeywords = [], context = {}) {
  const competitorKeywords = [];
  const sharedKeywords = [];
  const competitorGaps = [];
  const yourOpportunities = [];
  const weakKeywords = [];
  const untappedOpportunities = [];
  const brandedOpportunities = [];
  const localOpportunities = [];
  const questionGaps = [];

  const processedKeywords = enrichedKeywords.map((kw) => {
    let gapCategory = 'competitor_keywords';
    let gapStatusLabel = 'Competitor page-targeting evidence';
    let whyItMatters = '';
    let competitorAction = '';
    let primaryAction = '';
    let recommendedContentAction = '';

    // Determine Gap Classification
    if (kw.category === 'brand') {
      gapCategory = 'branded_opportunities';
      gapStatusLabel = 'Brand entity visibility';
      whyItMatters = 'Essential for entity disambiguation, branded SERP protection, and Knowledge Panel clarity.';
      competitorAction = kw.competitorPresent ? 'Competitor references this brand entity in metadata.' : 'No active brand coverage.';
      primaryAction = kw.primaryPresent ? 'Primary site targets this brand term.' : 'Missing explicit brand markup or page targeting.';
      recommendedContentAction = 'Optimize Organization schema, About page entity statements, and branded homepage title tag.';
    } else if (kw.category === 'local') {
      gapCategory = 'local_opportunities';
      gapStatusLabel = 'Geographic query opportunity';
      whyItMatters = 'Captures location-aware intent and regional customer searches.';
      competitorAction = kw.competitorPresent ? 'Competitor targets regional market queries.' : 'No regional targeting detected.';
      primaryAction = kw.primaryPresent ? 'Primary site addresses this region.' : 'Lacks local landing page or geo schema.';
      recommendedContentAction = 'Publish location-specific service landing page with LocalBusiness schema.';
    } else if (kw.category === 'question') {
      if (kw.competitorPresent && !kw.primaryPresent) {
        gapCategory = 'question_gaps';
        gapStatusLabel = 'Competitor question coverage gap';
        whyItMatters = 'Users asking this question receive direct answers from competitor content, reducing primary site citations.';
        competitorAction = `Competitor answers query on ${kw.competitorTargetPage || 'their website'}.`;
        primaryAction = 'Primary site has no direct answer or FAQ block for this query.';
        recommendedContentAction = 'Implement direct 50-word answer block and FAQ structured schema on target service page.';
      } else if (kw.competitorPresent && kw.primaryPresent) {
        gapCategory = 'shared_keywords';
        gapStatusLabel = 'Shared question coverage';
        whyItMatters = 'Both businesses attempt to answer this query. Competitive win depends on directness and inverted pyramid formatting.';
        competitorAction = 'Competitor provides on-page answer.';
        primaryAction = 'Primary site provides on-page answer.';
        recommendedContentAction = 'Enhance answer quality with structured tables, bullet points, and verified citations.';
      } else {
        gapCategory = 'your_opportunities';
        gapStatusLabel = 'Untapped question opportunity';
        whyItMatters = 'Valuable informational query that neither business currently satisfies with dedicated content.';
        competitorAction = 'No explicit answer detected.';
        primaryAction = 'No explicit answer detected.';
        recommendedContentAction = 'Publish educational guide addressing this question with conversational query markup.';
      }
    } else if (kw.competitorPresent && !kw.primaryPresent) {
      gapCategory = 'competitor_gaps';
      gapStatusLabel = 'Competitor content coverage / Primary gap';
      whyItMatters = 'Competitor captures organic search traffic and buyer consideration while primary site is invisible.';
      competitorAction = `Competitor actively targets this topic on ${kw.competitorTargetPage || 'their pages'}.`;
      primaryAction = 'Primary site lacks dedicated page or sufficient topical depth.';
      recommendedContentAction = `Author a dedicated, high-utility ${kw.intent} landing page targeting this keyword theme.`;
    } else if (kw.competitorPresent && kw.primaryPresent) {
      gapCategory = 'shared_keywords';
      gapStatusLabel = 'Direct competitive overlap';
      whyItMatters = 'Head-to-head keyword battle where technical SEO, entity clarity, and depth determine ranking.';
      competitorAction = 'Competitor targets topic on-page.';
      primaryAction = 'Primary site targets topic on-page.';
      recommendedContentAction = 'Outperform competitor by adding original research, comparison tables, and Schema markup.';
    } else if (!kw.competitorPresent && kw.primaryPresent) {
      gapCategory = 'your_opportunities';
      gapStatusLabel = 'Primary website competitive advantage';
      whyItMatters = 'Topic where primary site has unique coverage that competitor has failed to target.';
      competitorAction = 'Competitor has no observed coverage.';
      primaryAction = 'Primary site has active page targeting.';
      recommendedContentAction = 'Strengthen topical moat with internal links from homepage and supporting blog posts.';
    } else {
      gapCategory = 'untapped_opportunities';
      gapStatusLabel = 'Unverified visibility opportunity';
      whyItMatters = 'Relevant industry topic with potential search demand that neither competitor currently covers.';
      competitorAction = 'No active page targeting detected.';
      primaryAction = 'No active page targeting detected.';
      recommendedContentAction = 'Capitalize on market vacuum by authoring an authoritative guide or feature page.';
    }

    const { score: opportunityScore, priority } = calculateOpportunityScore(kw);

    const record = {
      ...kw,
      gapCategory,
      gapStatusLabel,
      opportunityScore,
      priority,
      whyItMatters,
      competitorAction,
      primaryAction,
      recommendedContentAction,
      targetPageRecommendation: kw.primaryTargetPage || `New ${kw.category} page on ${context.primaryDomain || 'primary website'}`,
    };

    // Sort into buckets
    if (gapCategory === 'competitor_keywords') competitorKeywords.push(record);
    else if (gapCategory === 'shared_keywords') sharedKeywords.push(record);
    else if (gapCategory === 'competitor_gaps') competitorGaps.push(record);
    else if (gapCategory === 'your_opportunities') yourOpportunities.push(record);
    else if (gapCategory === 'weak_keywords') weakKeywords.push(record);
    else if (gapCategory === 'untapped_opportunities') untappedOpportunities.push(record);
    else if (gapCategory === 'branded_opportunities') brandedOpportunities.push(record);
    else if (gapCategory === 'local_opportunities') localOpportunities.push(record);
    else if (gapCategory === 'question_gaps') questionGaps.push(record);

    return record;
  });

  // Sort by opportunity score descending
  processedKeywords.sort((a, b) => b.opportunityScore - a.opportunityScore);

  return {
    allKeywords: processedKeywords,
    summary: {
      totalDiscovered: processedKeywords.length,
      competitorOnlyCount: competitorGaps.length,
      sharedCount: sharedKeywords.length,
      primaryAdvantageCount: yourOpportunities.length,
      questionGapsCount: questionGaps.length,
      untappedCount: untappedOpportunities.length,
      p0CriticalCount: processedKeywords.filter(k => k.priority === 'P0').length,
      p1HighCount: processedKeywords.filter(k => k.priority === 'P1').length,
    },
    buckets: {
      competitorGaps,
      sharedKeywords,
      yourOpportunities,
      questionGaps,
      untappedOpportunities,
      brandedOpportunities,
      localOpportunities,
    },
    topOpportunities: processedKeywords.slice(0, 15),
  };
}

module.exports = {
  calculateOpportunityScore,
  analyzeKeywordGaps,
};
