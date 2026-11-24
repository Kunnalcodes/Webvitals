/**
 * Competitor SEO Strategy Reverse Engineering & Infrastructure Comparison — WebVitals 2.0
 *
 * Compares technical SEO infrastructure side-by-side and reverse-engineers 16 competitor SEO strategies.
 */

'use strict';

/**
 * Compares technical SEO infrastructure elements between primary and competitor.
 */
function compareSeoInfrastructure(primaryInventory, competitorInventory) {
  const pHome = primaryInventory.homepage || {};
  const cHome = competitorInventory.homepage || {};

  const dimensions = [
    {
      name: 'Indexability & Robots Directives',
      primaryValue: primaryInventory.robotsTxt.exists ? 'Configured & Active' : 'Missing robots.txt',
      competitorValue: competitorInventory.robotsTxt.exists ? 'Configured & Active' : 'Missing robots.txt',
      winner: primaryInventory.robotsTxt.exists && !competitorInventory.robotsTxt.exists ? 'Primary' :
              competitorInventory.robotsTxt.exists && !primaryInventory.robotsTxt.exists ? 'Competitor' : 'Parity',
      interpretation: 'Controls search engine crawler rate, disallow directories, and sitemap discovery.',
    },
    {
      name: 'XML Sitemap Architecture',
      primaryValue: primaryInventory.sitemap.exists ? `Discovered (${primaryInventory.sitemap.discoveredUrlsCount} URLs)` : 'Missing Sitemap',
      competitorValue: competitorInventory.sitemap.exists ? `Discovered (${competitorInventory.sitemap.discoveredUrlsCount} URLs)` : 'Missing Sitemap',
      winner: (primaryInventory.sitemap.discoveredUrlsCount || 0) > (competitorInventory.sitemap.discoveredUrlsCount || 0) ? 'Primary' :
              (competitorInventory.sitemap.discoveredUrlsCount || 0) > (primaryInventory.sitemap.discoveredUrlsCount || 0) ? 'Competitor' : 'Parity',
      interpretation: 'Enables deterministic crawler discovery for newly published and updated pages.',
    },
    {
      name: 'Canonical URL Consistency',
      primaryValue: pHome.canonicalUrl ? 'Explicit Canonical Tag' : 'Missing Canonical',
      competitorValue: cHome.canonicalUrl ? 'Explicit Canonical Tag' : 'Missing Canonical',
      winner: pHome.canonicalUrl && !cHome.canonicalUrl ? 'Primary' :
              cHome.canonicalUrl && !pHome.canonicalUrl ? 'Competitor' : 'Parity',
      interpretation: 'Prevents duplicate content splitting across HTTP/HTTPS and URL parameter variations.',
    },
    {
      name: 'Heading Hierarchy Tree (H1-H3)',
      primaryValue: `H1: ${(pHome.headings?.h1 || []).length}, H2: ${(pHome.headings?.h2 || []).length}`,
      competitorValue: `H1: ${(cHome.headings?.h1 || []).length}, H2: ${(cHome.headings?.h2 || []).length}`,
      winner: (pHome.headings?.h1 || []).length === 1 ? 'Primary' : 'Competitor',
      interpretation: 'Strict single H1 with logical H2 sub-sections communicates topic hierarchy to crawlers.',
    },
    {
      name: 'Structured Data Schema (JSON-LD)',
      primaryValue: pHome.schemaTypes?.length > 0 ? pHome.schemaTypes.join(', ') : 'No Schema Detected',
      competitorValue: cHome.schemaTypes?.length > 0 ? cHome.schemaTypes.join(', ') : 'No Schema Detected',
      winner: (pHome.schemaTypes?.length || 0) > (cHome.schemaTypes?.length || 0) ? 'Primary' :
              (cHome.schemaTypes?.length || 0) > (pHome.schemaTypes?.length || 0) ? 'Competitor' : 'Parity',
      interpretation: 'Enables rich snippets, Organization Knowledge Panels, and machine-readable metadata.',
    },
    {
      name: 'Internal Linking Breadth',
      primaryValue: `${pHome.links?.internalCount || 0} internal links`,
      competitorValue: `${cHome.links?.internalCount || 0} internal links`,
      winner: (pHome.links?.internalCount || 0) > (cHome.links?.internalCount || 0) ? 'Primary' :
              (cHome.links?.internalCount || 0) > (pHome.links?.internalCount || 0) ? 'Competitor' : 'Parity',
      interpretation: 'Distributes PageRank authority and topical relevance through contextual in-body links.',
    },
    {
      name: 'Content Depth & Word Count',
      primaryValue: `${pHome.wordCount || 0} words (homepage)`,
      competitorValue: `${cHome.wordCount || 0} words (homepage)`,
      winner: (pHome.wordCount || 0) > (cHome.wordCount || 0) ? 'Primary' : 'Competitor',
      interpretation: 'Comprehensive topical coverage provides search engines with richer semantic context.',
    },
    {
      name: 'Server Response Latency',
      primaryValue: `${primaryInventory.elapsedMs || 0} ms`,
      competitorValue: `${competitorInventory.elapsedMs || 0} ms`,
      winner: (primaryInventory.elapsedMs || 500) < (competitorInventory.elapsedMs || 500) ? 'Primary' : 'Competitor',
      interpretation: 'Faster initial server response directly impacts Time to First Byte (TTFB) and crawl budget.',
    },
  ];

  const primaryWins = dimensions.filter(d => d.winner === 'Primary').length;
  const competitorWins = dimensions.filter(d => d.winner === 'Competitor').length;

  return {
    dimensions,
    summary: {
      primaryWins,
      competitorWins,
      parityCount: dimensions.filter(d => d.winner === 'Parity').length,
      infrastructureLeader: primaryWins > competitorWins ? 'Primary' : competitorWins > primaryWins ? 'Competitor' : 'Parity',
    },
  };
}

/**
 * Reverse-engineers 16 competitor SEO strategies based on observed crawl evidence.
 */
function reverseEngineerSeoStrategies(primaryInventory, competitorInventory) {
  const cHome = competitorInventory.homepage || {};
  const pHome = primaryInventory.homepage || {};
  const cPages = competitorInventory.subPages || [];
  const pPages = primaryInventory.subPages || [];
  const cTypes = competitorInventory.pagesByType || {};
  const pTypes = primaryInventory.pagesByType || {};

  const strategies = [
    {
      id: 'strat-landing',
      strategy: 'Conversion-Focused Landing Pages',
      evidence: `Competitor maintains dedicated landing structures with ${cHome.links?.internalCount || 0} internal navigation elements.`,
      competitorPages: cPages.filter(p => p.type === 'service' || p.type === 'product').map(p => p.url).slice(0, 3),
      competitorEffectiveness: cTypes.service > 0 ? 'Strong' : 'Moderate',
      confidence: 0.90,
      whyBeneficial: 'Funnel organic visitors directly to intent-aligned conversion funnels.',
      primaryApplied: pTypes.service > 0,
      howToCompete: 'Ensure every primary service page has a clear above-the-fold CTA, trust proof, and self-serve onboarding.',
    },
    {
      id: 'strat-service-arch',
      strategy: 'Service-Page Architecture',
      evidence: `Competitor discovered with ${cTypes.service || 0} distinct service/solution URLs.`,
      competitorPages: cPages.filter(p => p.type === 'service').map(p => p.url),
      competitorEffectiveness: cTypes.service >= 2 ? 'Strong' : 'Moderate',
      confidence: 0.88,
      whyBeneficial: 'Allows targeting specific service keywords rather than forcing one homepage to rank for everything.',
      primaryApplied: pTypes.service >= 2,
      howToCompete: 'Separate broad offerings into discrete, highly targeted child pages with dedicated keyword clusters.',
    },
    {
      id: 'strat-topic-cluster',
      strategy: 'Topic Cluster & Supporting Pages',
      evidence: `Discovered ${competitorInventory.sitemap?.discoveredUrlsCount || cPages.length} pages in competitor sitemap/links.`,
      competitorPages: cPages.slice(0, 3).map(p => p.url),
      competitorEffectiveness: (competitorInventory.sitemap?.discoveredUrlsCount || 0) >= 10 ? 'Strong' : 'Moderate',
      confidence: 0.85,
      whyBeneficial: 'Search engines reward topical authority when multiple child pages link back to an authoritative pillar page.',
      primaryApplied: (primaryInventory.sitemap?.discoveredUrlsCount || 0) >= 10,
      howToCompete: 'Build 3-5 supporting guide articles linking directly to your core money pages with descriptive anchor text.',
    },
    {
      id: 'strat-long-tail',
      strategy: 'Long-Tail Query Targeting',
      evidence: `Competitor H2/H3 headings average ${(cHome.headings?.h2 || []).length} structured sub-sections.`,
      competitorPages: [competitorInventory.url],
      competitorEffectiveness: (cHome.headings?.h2 || []).length >= 5 ? 'Strong' : 'Moderate',
      confidence: 0.86,
      whyBeneficial: 'Captures highly qualified users looking for specific niche capabilities or technical answers.',
      primaryApplied: (pHome.headings?.h2 || []).length >= 5,
      howToCompete: 'Add H2 sections answering specific technical use cases, protocols, and workflows.',
    },
    {
      id: 'strat-comparison',
      strategy: 'Comparison & Alternatives Strategy',
      evidence: cTypes.comparison > 0 ? `Competitor has active comparison/alternative URL.` : 'Competitor relies on general branding.',
      competitorPages: cPages.filter(p => p.type === 'comparison').map(p => p.url),
      competitorEffectiveness: cTypes.comparison > 0 ? 'Strong' : 'Weak',
      confidence: 0.82,
      whyBeneficial: 'Intersects prospects at the final decision stage of their buying journey.',
      primaryApplied: pTypes.comparison > 0,
      howToCompete: 'Publish an objective "Why Us vs Them" comparison page with clear benchmark data.',
    },
    {
      id: 'strat-internal-link',
      strategy: 'Internal Linking Network',
      evidence: `Competitor utilizes ${cHome.links?.internalCount || 0} internal links on homepage.`,
      competitorPages: [competitorInventory.url],
      competitorEffectiveness: (cHome.links?.internalCount || 0) >= 15 ? 'Strong' : 'Moderate',
      confidence: 0.88,
      whyBeneficial: 'Accelerates crawling and conveys topical relationship between related offerings.',
      primaryApplied: (pHome.links?.internalCount || 0) >= 15,
      howToCompete: 'Audit internal links to ensure high-priority landing pages receive contextual links from your top pages.',
    },
    {
      id: 'strat-schema',
      strategy: 'Structured Data & Entity Signals',
      evidence: cHome.schemaTypes?.length > 0 ? `Competitor defines schemas: ${cHome.schemaTypes.join(', ')}` : 'No structured data on competitor homepage.',
      competitorPages: [competitorInventory.url],
      competitorEffectiveness: cHome.schemaTypes?.length > 0 ? 'Strong' : 'Weak',
      confidence: 0.92,
      whyBeneficial: 'Helps Google identify brand entities, founders, locations, and software specifications.',
      primaryApplied: pHome.schemaTypes?.length > 0,
      howToCompete: 'Inject complete Organization and WebSite JSON-LD with sameAs social profile verification.',
    },
    {
      id: 'strat-pricing',
      strategy: 'Commercial Transparency / Pricing SEO',
      evidence: cTypes.pricing > 0 ? 'Competitor has public pricing page.' : 'Competitor keeps pricing private.',
      competitorPages: cPages.filter(p => p.type === 'pricing').map(p => p.url),
      competitorEffectiveness: cTypes.pricing > 0 ? 'Strong' : 'Weak',
      confidence: 0.90,
      whyBeneficial: 'Pricing queries are among the highest-converting searches in any vertical.',
      primaryApplied: pTypes.pricing > 0,
      howToCompete: 'Deploy a dedicated pricing table with self-serve signup options.',
    },
  ];

  return strategies;
}

module.exports = {
  compareSeoInfrastructure,
  reverseEngineerSeoStrategies,
};
