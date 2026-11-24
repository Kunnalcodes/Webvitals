/**
 * Content Gap & Page Strategy Comparison Engine — WebVitals 2.0
 *
 * Compares content inventories across 12 page types, detects content depth gaps,
 * and recommends original, differentiated, superior content assets (never cloning).
 */

'use strict';

/**
 * Compares content inventories and identifies page-level topic gaps.
 *
 * @param {Object} primaryInventory - Primary site crawled data
 * @param {Object} competitorInventory - Competitor site crawled data
 * @param {Array<Object>} keywordGaps - Output from analyzeKeywordGaps
 * @returns {Object} Content gap analysis and recommended new content assets
 */
function analyzeContentGaps(primaryInventory, competitorInventory, keywordGaps = {}) {
  const primaryPages = [primaryInventory.homepage, ...(primaryInventory.subPages || [])];
  const competitorPages = [competitorInventory.homepage, ...(competitorInventory.subPages || [])];

  const primaryTypes = primaryInventory.pagesByType || {};
  const competitorTypes = competitorInventory.pagesByType || {};

  // Compare Page Type Coverage
  const pageTypeComparison = [
    { type: 'Service Pages', primary: primaryTypes.service || 0, competitor: competitorTypes.service || 0 },
    { type: 'Product / Features', primary: primaryTypes.product || 0, competitor: competitorTypes.product || 0 },
    { type: 'Pricing & Plans', primary: primaryTypes.pricing || 0, competitor: competitorTypes.pricing || 0 },
    { type: 'Blog & Insights', primary: primaryTypes.blog || 0, competitor: competitorTypes.blog || 0 },
    { type: 'Guides & Documentation', primary: primaryTypes.guide || 0, competitor: competitorTypes.guide || 0 },
    { type: 'FAQ & Knowledge Base', primary: primaryTypes.faq || 0, competitor: competitorTypes.faq || 0 },
    { type: 'Comparison & Alternatives', primary: primaryTypes.comparison || 0, competitor: competitorTypes.comparison || 0 },
    { type: 'Case Studies & Proof', primary: primaryTypes.case_study || 0, competitor: competitorTypes.case_study || 0 },
    { type: 'About & Company Identity', primary: primaryTypes.about || 0, competitor: competitorTypes.about || 0 },
    { type: 'Contact & Demos', primary: primaryTypes.contact || 0, competitor: competitorTypes.contact || 0 },
  ].map(row => {
    let status = 'Parity';
    if (row.competitor > row.primary) status = 'Competitor Advantage';
    else if (row.primary > row.competitor) status = 'Primary Advantage';
    return { ...row, status };
  });

  // Calculate Content Depth (Word Count & Structure)
  const primaryAvgWords = Math.round(
    primaryPages.reduce((acc, p) => acc + (p.wordCount || 0), 0) / Math.max(1, primaryPages.length)
  );
  const competitorAvgWords = Math.round(
    competitorPages.reduce((acc, p) => acc + (p.wordCount || 0), 0) / Math.max(1, competitorPages.length)
  );

  // Identify Specific Topic & Page Gaps
  const gaps = [];

  // Gap 1: Pricing Transparency Gap
  if (competitorTypes.pricing > 0 && primaryTypes.pricing === 0) {
    gaps.push({
      id: 'cgap-pricing',
      topic: 'Pricing, Plans & Commercial Transparency',
      pageType: 'pricing',
      searchIntent: 'commercial / transactional',
      competitorEvidence: `Competitor publishes explicit pricing page at ${competitorPages.find(p => p.type === 'pricing')?.url || 'their pricing endpoint'}.`,
      primaryEvidence: 'Primary site lacks a dedicated public pricing or engagement tier page.',
      opportunity: 'Buyers searching for commercial costs encounter competitor first. Adding transparent pricing captures high-intent evaluators.',
      suggestedTitle: `${capitalize(primaryInventory.domain.split('.')[0])} Pricing & Plans — Transparent Tiers`,
      suggestedH1: 'Transparent Pricing Designed for Scale',
      suggestedOutline: [
        'Tier comparison table (Starter, Professional, Enterprise)',
        'Feature matrix breakdown with checkboxes',
        'Direct answer block: Are there setup fees or annual discounts?',
        'Interactive ROI or cost estimator widget',
        'FAQ structured schema addressing billing questions'
      ],
      supportingKeywords: ['pricing', 'subscription cost', 'plans', 'free trial', 'enterprise tier'],
      internalLinks: ['/features', '/contact', '/security'],
      priority: 'P0',
      effort: 'Medium',
      strategy: 'Differentiate with clear, transparent self-serve options rather than gate-keeping info behind sales forms.',
    });
  }

  // Gap 2: Comparison & Alternatives Moat
  if (competitorTypes.comparison > 0 || (keywordGaps.buckets?.competitorGaps || []).some(k => k.category === 'comparison')) {
    gaps.push({
      id: 'cgap-comparison',
      topic: `Head-to-Head Comparison: ${capitalize(primaryInventory.domain.split('.')[0])} vs ${capitalize(competitorInventory.domain.split('.')[0])}`,
      pageType: 'comparison',
      searchIntent: 'commercial investigation',
      competitorEvidence: `Competitor leverages comparison queries to position against alternative solutions.`,
      primaryEvidence: 'Primary website has no objective comparison or alternative landing page.',
      opportunity: 'Capture prospects searching "alternatives" before they commit to competitor.',
      suggestedTitle: `${capitalize(primaryInventory.domain.split('.')[0])} vs ${capitalize(competitorInventory.domain.split('.')[0])} — Feature & Performance Comparison`,
      suggestedH1: `Detailed Platform Comparison: Why Modern Teams Choose ${capitalize(primaryInventory.domain.split('.')[0])}`,
      suggestedOutline: [
        'Executive architectural breakdown and core philosophy',
        'Feature-by-feature side-by-side technical comparison table',
        'Speed, security, and developer ergonomics benchmarks',
        'Migration pathway and onboarding ease',
        'Customer testimonials and verified case study proof'
      ],
      supportingKeywords: ['vs', 'alternatives', 'comparison', 'pros and cons', 'switch from'],
      internalLinks: ['/pricing', '/docs', '/demo'],
      priority: 'P1',
      effort: 'Medium',
      strategy: 'Provide an honest, objective breakdown highlighting unique strengths (e.g. speed, accuracy, API flexibility) without unsubstantiated disparagement.',
    });
  }

  // Gap 3: Question / FAQ Knowledge Base Gap
  const questionGapsList = keywordGaps.buckets?.questionGaps || [];
  if (questionGapsList.length > 0 || competitorTypes.faq > primaryTypes.faq) {
    const sampleQuestions = questionGapsList.slice(0, 4).map(q => q.keyword);
    gaps.push({
      id: 'cgap-faq',
      topic: 'Customer Question & Answer Knowledge Hub',
      pageType: 'faq',
      searchIntent: 'informational / support',
      competitorEvidence: `Competitor actively answers ${questionGapsList.length} user questions that are missing on primary site.`,
      primaryEvidence: 'Primary website has limited or scattered FAQ answers.',
      opportunity: 'Win Google Featured Snippets and AI Answer Engine citations by providing direct, authoritative answers.',
      suggestedTitle: `Frequently Asked Questions — ${capitalize(primaryInventory.domain.split('.')[0])} Help & Architecture`,
      suggestedH1: 'Everything You Need to Know: Technical & Operational FAQs',
      suggestedOutline: [
        'How it works & technical prerequisites',
        'Data privacy, security, and compliance assurances',
        'API rate limits and integration options',
        'Troubleshooting common integration errors'
      ],
      supportingKeywords: sampleQuestions.length > 0 ? sampleQuestions : ['how does it work', 'security compliance', 'api integration'],
      internalLinks: ['/features', '/support', '/docs'],
      priority: 'P1',
      effort: 'Low',
      strategy: 'Format every answer in inverted pyramid style (direct 40-word conclusion first, followed by technical details).',
    });
  }

  // Gap 4: High-Value Keyword Theme Clusters (from Top Gaps)
  const topCompetitorGaps = (keywordGaps.buckets?.competitorGaps || []).slice(0, 3);
  topCompetitorGaps.forEach((cg, idx) => {
    gaps.push({
      id: `cgap-kw-${idx + 1}`,
      topic: `Dedicated Solution Page for "${capitalize(cg.keyword)}"`,
      pageType: 'service',
      searchIntent: cg.intent,
      competitorEvidence: `Competitor addresses "${cg.keyword}" on ${cg.competitorTargetPage || 'their pages'}.`,
      primaryEvidence: 'Primary site lacks dedicated landing page for this query theme.',
      opportunity: `Close competitor organic traffic advantage for high-intent query "${cg.keyword}".`,
      suggestedTitle: `${capitalize(cg.keyword)} Solutions — ${capitalize(primaryInventory.domain.split('.')[0])}`,
      suggestedH1: `Enterprise ${capitalize(cg.keyword)} Platform`,
      suggestedOutline: [
        `What is ${cg.keyword} and why it is critical`,
        'Step-by-step workflow and architecture',
        'Real-time metrics and telemetry reports',
        'Case study example and measurable outcomes'
      ],
      supportingKeywords: [cg.keyword, `${cg.keyword} tool`, `best ${cg.keyword}`, `${cg.keyword} guide`],
      internalLinks: ['/features', '/pricing', '/contact'],
      priority: cg.priority,
      effort: 'Medium',
      strategy: 'Author a high-depth pillar guide that includes real code snippets, diagrams, and actionable workflows.',
    });
  });

  return {
    pageTypeComparison,
    contentDepth: {
      primaryAverageWords: primaryAvgWords,
      competitorAverageWords: competitorAvgWords,
      depthAdvantage: primaryAvgWords > competitorAvgWords ? 'Primary' : competitorAvgWords > primaryAvgWords ? 'Competitor' : 'Parity',
      differenceWords: Math.abs(primaryAvgWords - competitorAvgWords),
    },
    totalGapsIdentified: gaps.length,
    gaps,
  };
}

function capitalize(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

module.exports = {
  analyzeContentGaps,
};
