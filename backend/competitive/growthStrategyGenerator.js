/**
 * "How to Compete" 5-Phase Growth Strategy Generator — WebVitals 2.0
 *
 * Generates an evidence-grounded, sequential competitive roadmap across:
 *   Phase 1 — Fix (Technical blockers & hygiene)
 *   Phase 2 — Capture (Achievable high-value keyword & question gaps)
 *   Phase 3 — Build Authority (Pillars, clusters & proof assets)
 *   Phase 4 — Expand (New vertical clusters & comparison assets)
 *   Phase 5 — Optimize (Internal linking & continuous refresh)
 */

'use strict';

/**
 * Generates dynamic 5-phase growth strategy based on scan findings.
 *
 * @param {Object} primaryInventory
 * @param {Object} competitorInventory
 * @param {Object} keywordGapReport
 * @param {Object} contentGapReport
 * @param {Object} seoComparisonReport
 * @returns {Object} 5-Phase competitive roadmap
 */
function generateGrowthStrategy(
  primaryInventory,
  competitorInventory,
  keywordGapReport,
  contentGapReport,
  seoComparisonReport
) {
  const pHome = primaryInventory.homepage || {};
  const cHome = competitorInventory.homepage || {};
  const topKwGaps = keywordGapReport.buckets?.competitorGaps || [];
  const questionGaps = keywordGapReport.buckets?.questionGaps || [];
  const contentGaps = contentGapReport.gaps || [];

  // ==========================================
  // PHASE 1 — FIX (Technical & Entity Blockers)
  // ==========================================
  const phase1 = [];

  if (!primaryInventory.robotsTxt.exists) {
    phase1.push({
      action: 'Deploy Configured robots.txt with Explicit Sitemap Reference',
      reason: 'Competitor has active robots.txt guiding search crawlers; primary site lacks crawl instructions.',
      supportingEvidence: `Primary robots.txt returned 404/missing at ${primaryInventory.url}/robots.txt.`,
      targetTopic: 'Technical SEO Infrastructure',
      expectedOutcome: 'Faster indexing of newly deployed pages and prevention of crawler budget waste.',
      priority: 'P0',
      effort: 'Low',
      dependencies: 'None',
      validationMetric: 'HTTP 200 on /robots.txt with valid User-agent directives.',
    });
  }

  if (!pHome.canonicalUrl) {
    phase1.push({
      action: 'Implement Explicit Canonical Tag in HTML <head>',
      reason: 'Prevents URL splitting across protocol variations and tracking parameters.',
      supportingEvidence: `Canonical tag missing on ${primaryInventory.url}.`,
      targetTopic: 'Canonical Directives',
      expectedOutcome: 'Consolidation of ranking signals to primary endpoint.',
      priority: 'P0',
      effort: 'Low',
      dependencies: 'None',
      validationMetric: '<link rel="canonical" href="..." /> confirmed in DOM.',
    });
  }

  if (!pHome.schemaTypes?.length) {
    phase1.push({
      action: 'Inject Organization & WebSite JSON-LD Schema with sameAs Social Links',
      reason: 'Competitor defines machine-readable schemas, giving them an entity clarity advantage in GEO engines.',
      supportingEvidence: `Zero schema types detected on primary site homepage.`,
      targetTopic: 'Entity Optimization',
      expectedOutcome: 'Clear brand disambiguation and eligibility for Google Knowledge Panel.',
      priority: 'P1',
      effort: 'Low',
      dependencies: 'Official social profiles URL list',
      validationMetric: 'Valid schema test in Google Rich Results tool.',
    });
  }

  if ((pHome.headings?.h1 || []).length !== 1) {
    phase1.push({
      action: 'Standardize Homepage to Exactly One Primary H1 Heading',
      reason: 'Heading hierarchy communicates primary topic to search engines.',
      supportingEvidence: `Detected ${(pHome.headings?.h1 || []).length} H1 tags on primary homepage.`,
      targetTopic: 'On-Page Hierarchy',
      expectedOutcome: 'Clearer topical indexing and resolution of heading skip penalties.',
      priority: 'P1',
      effort: 'Low',
      dependencies: 'None',
      validationMetric: 'DOM querySelectorAll("h1").length === 1.',
    });
  }

  // ==========================================
  // PHASE 2 — CAPTURE (High-Value Keyword & Question Gaps)
  // ==========================================
  const phase2 = [];

  // Capture top 2 keyword gaps
  topKwGaps.slice(0, 2).forEach(kw => {
    phase2.push({
      action: `Target High-Intent Query "${kw.keyword}" with Dedicated Page Content`,
      reason: `Competitor currently captures organic traffic for this keyword on ${kw.competitorTargetPage || 'their site'}.`,
      supportingEvidence: `Competitor page targeting detected; primary coverage is currently 0%.`,
      targetTopic: kw.keyword,
      expectedOutcome: `Establish initial page visibility and compete for buyer intent.`,
      priority: 'P0',
      effort: 'Medium',
      dependencies: 'Phase 1 canonical infrastructure',
      validationMetric: `Page published and targeting "${kw.keyword}" in title and H1.`,
    });
  });

  // Capture top question gap
  if (questionGaps.length > 0) {
    const qg = questionGaps[0];
    phase2.push({
      action: `Answer Customer Question: "${qg.keyword}" with Inverted Pyramid FAQ Block`,
      reason: 'Competitor answers this question, gaining consideration and answer engine references.',
      supportingEvidence: `Discovered question actively addressed on ${qg.competitorTargetPage || competitorInventory.domain}.`,
      targetTopic: qg.keyword,
      expectedOutcome: 'Direct inclusion in Google Featured Snippets and AI conversational responses.',
      priority: 'P1',
      effort: 'Low',
      dependencies: 'Target service page',
      validationMetric: 'Direct 50-word answer block with FAQ structured data.',
    });
  }

  // ==========================================
  // PHASE 3 — BUILD AUTHORITY (Pillars & Proof)
  // ==========================================
  const phase3 = [];

  const comparisonGap = contentGaps.find(g => g.pageType === 'comparison');
  if (comparisonGap) {
    phase3.push({
      action: `Publish Objective Platform Comparison: ${comparisonGap.topic}`,
      reason: 'Prospects evaluating competitor will find your platform as the superior alternative.',
      supportingEvidence: comparisonGap.competitorEvidence,
      targetTopic: comparisonGap.topic,
      expectedOutcome: 'Interception of late-stage high-intent buyers seeking alternatives.',
      priority: 'P1',
      effort: 'Medium',
      dependencies: 'Feature matrix & performance benchmark data',
      validationMetric: 'Live comparison page with side-by-side technical evaluation table.',
    });
  }

  phase3.push({
    action: 'Publish Original Benchmark Study or Diagnostic Calculator Asset',
    reason: 'Organic editorial link magnet that attracts genuine citations from industry publications.',
    supportingEvidence: 'Competitor lacks original empirical research assets.',
    targetTopic: 'Topical Authority & Digital PR',
    expectedOutcome: 'Inflow of high-quality referring domain links and increased domain authority.',
    priority: 'P2',
    effort: 'High',
    dependencies: 'Telemetry dataset or free interactive tool',
    validationMetric: 'Published interactive asset with embed code and shareable charts.',
  });

  // ==========================================
  // PHASE 4 — EXPAND (New Verticals & Long-Tail Clusters)
  // ==========================================
  const phase4 = [];

  topKwGaps.slice(2, 4).forEach(kw => {
    phase4.push({
      action: `Launch Supporting Topic Cluster Article for "${kw.keyword}"`,
      reason: 'Strengthens topical depth and passes contextual internal links to core money pages.',
      supportingEvidence: `Discovered competitor depth across topic cluster.`,
      targetTopic: kw.keyword,
      expectedOutcome: 'Rank for secondary long-tail variants and reinforce pillar page authority.',
      priority: 'P2',
      effort: 'Medium',
      dependencies: 'Pillar page published in Phase 2',
      validationMetric: 'Published guide linking to primary service page with exact anchor text.',
    });
  });

  // ==========================================
  // PHASE 5 — OPTIMIZE (Internal Linking & Content Refresh)
  // ==========================================
  const phase5 = [
    {
      action: 'Strengthen Contextual Internal Linking from High-Traffic Pages',
      reason: 'Ensures PageRank flow directly targets newly published Phase 2 & 3 landing pages.',
      supportingEvidence: `Competitor maintains ${cHome.links?.internalCount || 0} internal links.`,
      targetTopic: 'Site Architecture & PageRank Distribution',
      expectedOutcome: 'Faster indexing and authority transfer to new solution pages.',
      priority: 'P2',
      effort: 'Low',
      dependencies: 'Phase 2 and 3 pages live',
      validationMetric: 'At least 3 contextual links pointing to each priority solution page.',
    },
    {
      action: 'Quarterly Content Freshness Refresh & Statistical Audit',
      reason: 'Search engines and Generative engines strongly favor fresh, recently verified data.',
      supportingEvidence: 'Stale content loses answer engine citations as facts become outdated.',
      targetTopic: 'Content Lifecycle Maintenance',
      expectedOutcome: 'Retention of Featured Snippets and high conversion rates.',
      priority: 'P3',
      effort: 'Medium',
      dependencies: 'Live analytics or Search Console access',
      validationMetric: 'Updated timestamp with verifiable newly added data points.',
    },
  ];

  return {
    phase1Fix: phase1,
    phase2Capture: phase2,
    phase3Authority: phase3,
    phase4Expand: phase4,
    phase5Optimize: phase5,
    totalRoadmapActions: phase1.length + phase2.length + phase3.length + phase4.length + phase5.length,
    p0CriticalCount: [...phase1, ...phase2].filter(a => a.priority === 'P0').length,
    p1HighCount: [...phase1, ...phase2, ...phase3].filter(a => a.priority === 'P1').length,
  };
}

module.exports = {
  generateGrowthStrategy,
};
