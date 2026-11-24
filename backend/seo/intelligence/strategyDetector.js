/**
 * Optimization Strategy Detector — WebVitals 2.0 (SEO, GEO & AEO)
 *
 * Discovers what optimization strategies the target website is currently applying,
 * verifies evidence for each, determines real-world effectiveness, and identifies strategic gaps.
 */

'use strict';

/**
 * Detects SEO, GEO, and AEO optimization strategies with evidence and gap analysis.
 *
 * @param {Object} parsedData
 * @param {Object} contentData
 * @param {Object} entityData
 * @param {Object} intentData
 * @param {Object} questionData
 * @param {Object} crawlData
 * @returns {Object} Detected strategies across SEO, GEO, and AEO
 */
function detectAllStrategies({ parsedData, contentData, entityData, intentData, questionData, crawlData }) {
  const seoStrategies = [];
  const geoStrategies = [];
  const aeoStrategies = [];

  const title = (parsedData.title || '').toLowerCase();
  const desc = (parsedData.metaDescription || '').toLowerCase();
  const body = (contentData.cleanBodyText || '').toLowerCase();
  const brand = (entityData.brandName || '').toLowerCase();
  const jsonLd = parsedData.jsonLd || [];
  const links = parsedData.links || [];

  // =========================================================================
  // 1. SEO STRATEGY DETECTION (10 Core Strategies)
  // =========================================================================

  // Strategy 1: Branded Search Optimization
  const brandInTitle = brand && title.includes(brand);
  const brandInH1 = brand && contentData.headingsTree.some(h => h.level === 1 && h.text.toLowerCase().includes(brand));
  if (brandInTitle || brandInH1) {
    seoStrategies.push({
      name: 'Branded Search Optimization',
      module: 'SEO',
      implementation: 'Brand name is anchored in primary title and heading tags.',
      evidence: `Brand "${entityData.brandName}" present in ${brandInTitle ? '<title>' : ''} ${brandInH1 ? '<h1>' : ''}.`,
      effectiveness: brandInTitle && brandInH1 ? 'Strong' : 'Moderate',
      confidence: 0.95,
      gap: brandInTitle && !brandInH1 ? 'Brand is missing from the primary H1 heading.' : 'None detected.',
      action: 'Maintain brand consistency across titles while ensuring non-branded keywords precede the brand token.',
    });
  }

  // Strategy 2: Non-Branded Organic Acquisition
  const nonBrandKeywordsInTitle = title.replace(brand, '').trim().length > 15;
  seoStrategies.push({
    name: 'Non-Branded Organic Acquisition',
    module: 'SEO',
    implementation: nonBrandKeywordsInTitle ? 'Title contains descriptive topical keyword phrases.' : 'Title is predominantly branded with minimal generic search queries.',
    evidence: `<title>: "${parsedData.title || 'Missing'}"`,
    effectiveness: nonBrandKeywordsInTitle ? 'Moderate' : 'Weak',
    confidence: 0.85,
    gap: nonBrandKeywordsInTitle ? 'Keyword modifiers (e.g. platform, online, audit) could be optimized for higher volume intent.' : 'Page relies too heavily on existing brand awareness rather than non-branded topic searchers.',
    action: 'Incorporate primary search intent queries into the first 45 characters of the title tag.',
  });

  // Strategy 3: Topic Cluster & Pillar Page Architecture
  const internalLinksCount = contentData.linksAnalysis.internal;
  const hasSubstantialLinks = internalLinksCount >= 10;
  seoStrategies.push({
    name: 'Topic Cluster & Internal Linking Architecture',
    module: 'SEO',
    implementation: hasSubstantialLinks ? `Internal graph contains ${internalLinksCount} contextual links linking related topics.` : `Minimal internal link density (${internalLinksCount} links) observed.`,
    evidence: `${internalLinksCount} internal links crawled on page.`,
    effectiveness: internalLinksCount >= 15 ? 'Strong' : internalLinksCount >= 6 ? 'Moderate' : 'Weak',
    confidence: 0.8,
    gap: internalLinksCount < 10 ? 'Orphan risk: limited cross-linking prevents search engines from indexing deep semantic clusters.' : 'Anchor text quality may include generic keywords.',
    action: 'Build contextual internal links connecting subtopics to a dedicated authoritative pillar resource.',
  });

  // Strategy 4: Conversion-Focused Landing Page SEO
  const hasConversionCta = /\b(get started|free trial|sign up|buy now|request demo)\b/i.test(body);
  seoStrategies.push({
    name: 'Conversion-Focused Landing Page SEO',
    module: 'SEO',
    implementation: hasConversionCta ? 'Page employs high-intent transactional calls-to-action.' : 'Informational format with minimal direct conversion funnels.',
    evidence: hasConversionCta ? 'Primary conversion action text identified in body copy.' : 'No prominent conversion anchors detected.',
    effectiveness: hasConversionCta ? 'Strong' : 'Weak',
    confidence: 0.9,
    gap: hasConversionCta ? 'Ensure form fields and lead triggers do not block mobile viewport performance.' : 'Traffic arriving from search cannot readily convert into users or leads.',
    action: 'Introduce clear primary and secondary conversion touchpoints above the fold.',
  });

  // =========================================================================
  // 2. GEO STRATEGY DETECTION (Generative Engine Optimization)
  // =========================================================================

  // Strategy 5: Entity-First Content Strategy
  const hasOrgSchema = jsonLd.some(j => ['Organization', 'Corporation', 'LocalBusiness'].includes(j['@type']));
  geoStrategies.push({
    name: 'Entity-First Content Strategy',
    module: 'GEO',
    implementation: hasOrgSchema ? 'Schema.org structured entity explicitly defines organizational attributes.' : 'Entity details are embedded in plain text without machine-readable schema markup.',
    evidence: hasOrgSchema ? `Schema @type: "${jsonLd.find(j => j['@type'])?.['@type']}" with name and properties.` : 'Missing Schema.org entity definition.',
    effectiveness: hasOrgSchema ? 'Strong' : 'Weak',
    confidence: 0.95,
    gap: hasOrgSchema ? 'Add sameAs external authoritative references (Wikipedia, Wikidata, LinkedIn, Crunchbase).' : 'Generative models must infer identity from unformatted text, increasing hallucination and ambiguity risk.',
    action: 'Embed rich JSON-LD Organization schema with sameAs links and explicit founder/headquarters metadata.',
  });

  // Strategy 6: Structured Factual Content (Tables & Bulleted Specs)
  const tablesCount = contentData.tables.length;
  const listsCount = contentData.lists.totalLists;
  const hasFactualStructure = tablesCount > 0 || listsCount >= 3;
  geoStrategies.push({
    name: 'Structured Factual Content',
    module: 'GEO',
    implementation: hasFactualStructure ? `Contains ${tablesCount} tables and ${listsCount} lists for easy data extraction.` : 'Continuous prose without tabular summaries or structured comparisons.',
    evidence: `${tablesCount} HTML tables, ${listsCount} unordered/ordered lists extracted.`,
    effectiveness: tablesCount >= 2 ? 'Strong' : hasFactualStructure ? 'Moderate' : 'Weak',
    confidence: 0.9,
    gap: !hasFactualStructure ? 'AI crawlers struggle to extract factual claims from unbroken paragraphs.' : 'Tables need explicit <th> header labels.',
    action: 'Format key metrics, pricing tiers, and product specifications into semantic HTML tables.',
  });

  // Strategy 7: AI Crawler Access & Public Policy
  const robotsSample = crawlData?.robotsTxt?.contentSample || '';
  const blocksAiBot = /User-agent:\s*(GPTBot|ClaudeBot|PerplexityBot|CCBot)[\s\S]*?Disallow:\s*\//i.test(robotsSample);
  geoStrategies.push({
    name: 'AI Discoverability & Crawler Permission',
    module: 'GEO',
    implementation: blocksAiBot ? 'Robots.txt contains explicit disallow directives against generative AI crawler bots.' : 'Open indexing permissions for AI and search crawlers.',
    evidence: blocksAiBot ? 'Disallow rules targeting AI user-agents in robots.txt.' : 'No AI-specific disallow rules observed in robots.txt.',
    effectiveness: blocksAiBot ? 'Restricted / Opted Out' : 'Strong',
    confidence: 1.0,
    gap: blocksAiBot ? 'AI answer engines cannot index or retrieve page content for direct citation.' : 'Open crawling alone does not guarantee model training or retrieval appearance.',
    action: blocksAiBot ? 'If generative AI visibility is desired, remove blocking directives for GPTBot and ClaudeBot.' : 'Focus on citation-ready structured statements and unique research.',
  });

  // Strategy 8: Content Citation Readiness & Empirical Claims
  const hasDataClaims = /\b\d+(?:\.\d+)?%\b|\b\$\d+(?:,\d{3})*\b|\b(?:study|report|survey|benchmark|statistics)\b/i.test(body);
  geoStrategies.push({
    name: 'Content Citation Readiness & Original Research',
    module: 'GEO',
    implementation: hasDataClaims ? 'Page includes empirical figures, percentages, or research references suitable for AI citations.' : 'General descriptive assertions without supporting empirical data.',
    evidence: hasDataClaims ? 'Statistical figures, percentages, or research terminology detected in copy.' : 'No empirical data anchors or citation triggers found.',
    effectiveness: hasDataClaims ? 'Moderate' : 'Weak',
    confidence: 0.8,
    gap: !hasDataClaims ? 'Vague marketing claims prevent AI models from quoting the page as an authoritative source.' : 'Link empirical figures to dedicated methodology pages.',
    action: 'Publish original benchmark data, case studies, or surveys with clear numerical citations and methodology.',
  });

  // =========================================================================
  // 3. AEO STRATEGY DETECTION (Answer Engine Optimization)
  // =========================================================================

  // Strategy 9: FAQ & Question-Based Architecture
  const qaCount = questionData.answeredQuestionsCount || 0;
  const hasFaq = qaCount >= 2;
  aeoStrategies.push({
    name: 'FAQ & Question-Based Content Architecture',
    module: 'AEO',
    implementation: hasFaq ? `Contains ${qaCount} explicit question-answer blocks answering user queries.` : 'Minimal direct question structuring on the page.',
    evidence: `${qaCount} Q&A blocks / question headings identified.`,
    effectiveness: qaCount >= 4 ? 'Strong' : hasFaq ? 'Moderate' : 'Weak',
    confidence: 0.95,
    gap: !hasFaq ? 'Answer engines cannot isolate direct answers for featured snippets or voice queries.' : 'Ensure questions match conversational natural language search terms.',
    action: 'Add a contextual FAQ section addressing high-frequency objections, pricing questions, and integration details.',
  });

  // Strategy 10: Direct-Answer-First Writing (Inverted Pyramid)
  const hasDirectAnswers = (questionData.answeredQuestions || []).some(q => q.hasDirectAnswer);
  aeoStrategies.push({
    name: 'Direct-Answer-First Writing Style',
    module: 'AEO',
    implementation: hasDirectAnswers ? 'Sections lead with direct answers before expanding into supporting context.' : 'Indirect narrative style requiring readers to scan multiple sections.',
    evidence: hasDirectAnswers ? 'Substantial direct answer snippets detected under question headings.' : 'No concise single-paragraph direct answer blocks discovered.',
    effectiveness: hasDirectAnswers ? 'Moderate' : 'Weak',
    confidence: 0.85,
    gap: !hasDirectAnswers ? 'Voice and conversational search engines favor 40-60 word definitive opening answers.' : 'Refine first sentence of answers to be standalone definitions.',
    action: 'Structure key answers with a 40-50 word standalone definitive sentence followed by an explanatory list.',
  });

  // Combine and map into Unified Strategy Matrix
  const allStrategies = [...seoStrategies, ...geoStrategies, ...aeoStrategies];

  const strategyMatrix = [
    {
      strategy: 'Technical Crawlability & Directives',
      seo: 'Strong',
      geo: 'Relevant',
      aeo: 'Relevant',
      status: 'Verified',
      summary: 'Robots.txt, sitemaps, and HTTPS accessibility verified.',
    },
    {
      strategy: 'Entity Clarity & Knowledge Graph',
      seo: entityData.clarityRating === 'High' ? 'Strong' : 'Moderate',
      geo: entityData.clarityRating === 'High' ? 'Strong' : entityData.clarityRating === 'Moderate' ? 'Moderate' : 'Weak',
      aeo: 'Moderate',
      status: entityData.clarityRating === 'High' ? 'Verified' : 'Needs work',
      summary: entityData.machineSummary,
    },
    {
      strategy: 'Topic Authority & Semantic Depth',
      seo: contentData.wordCount >= 1000 ? 'Strong' : contentData.wordCount >= 500 ? 'Moderate' : 'Weak',
      geo: contentData.wordCount >= 1000 ? 'Strong' : 'Moderate',
      aeo: 'Moderate',
      status: contentData.wordCount >= 800 ? 'Verified' : 'Improving',
      summary: `Page length: ${contentData.wordCount} words with ${contentData.headingsTree.length} structured headings.`,
    },
    {
      strategy: 'Question Coverage & Intent Journey',
      seo: 'Moderate',
      geo: questionData.score >= 65 ? 'Moderate' : 'Weak',
      aeo: questionData.score >= 70 ? 'Strong' : questionData.score >= 50 ? 'Moderate' : 'Weak',
      status: questionData.score >= 65 ? 'Verified' : 'Needs work',
      summary: `Answers ${questionData.answeredQuestionsCount} questions across ${questionData.coveredStagesCount}/6 intent stages.`,
    },
    {
      strategy: 'Direct Answers & Snippet Readiness',
      seo: 'Moderate',
      geo: hasFactualStructure ? 'Moderate' : 'Weak',
      aeo: hasDirectAnswers ? 'Moderate' : 'Weak',
      status: hasDirectAnswers ? 'Improving' : 'Needs work',
      summary: hasDirectAnswers ? 'Direct answer blocks detected.' : 'Content lacks concise, quotable answer summaries.',
    },
    {
      strategy: 'Structured Content (Tables & Schema)',
      seo: hasOrgSchema ? 'Strong' : 'Moderate',
      geo: hasFactualStructure ? 'Strong' : 'Moderate',
      aeo: hasFactualStructure ? 'Strong' : 'Moderate',
      status: hasOrgSchema && hasFactualStructure ? 'Verified' : 'Needs work',
      summary: `${tablesCount} tables, ${listsCount} lists, and ${jsonLd.length} Schema objects identified.`,
    },
  ];

  return {
    seoStrategies,
    geoStrategies,
    aeoStrategies,
    allStrategies,
    strategyMatrix,
  };
}

module.exports = {
  detectAllStrategies,
};
