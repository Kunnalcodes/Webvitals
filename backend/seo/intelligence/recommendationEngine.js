/**
 * Prioritized Recommendation Engine — WebVitals 2.0 SEO/GEO/AEO
 *
 * Generates actionable, evidence-backed improvements categorized into:
 *   P0 — Critical (Indexability & Access Blockers)
 *   P1 — High Impact (Entity, Answer Quality, Heading Structure)
 *   P2 — Growth (Topic Depth, Comparison Tables, FAQ Schema)
 *   P3 — Refinement (Anchor Text, Image Formats, Polish)
 */

'use strict';

/**
 * Builds structured, evidence-backed recommendations across SEO, GEO, and AEO.
 *
 * @param {Object} context
 * @returns {Object} Grouped recommendations (P0, P1, P2, P3) and flat prioritized list
 */
function generateStructuredRecommendations({
  parsedData,
  contentData,
  entityData,
  intentData,
  questionData,
  crawlData,
  seoScores,
  geoScores,
  aeoScores,
}) {
  const recommendations = [];

  // ── 1. Check for P0 Critical Blockers ─────────────────────────────────────
  const isNoIndex = (parsedData.metaRobots || '').toLowerCase().includes('noindex');
  if (isNoIndex) {
    recommendations.push({
      id: 'rec-noindex',
      title: 'Remove "noindex" Meta Directive to Restore Search Crawling',
      module: 'SEO',
      priority: 'P0',
      effort: 'Low',
      problem: 'Page header contains <meta name="robots" content="noindex">, which commands search engines to drop the URL from search indexes entirely.',
      evidence: `<meta name="robots" content="${parsedData.metaRobots}"> observed in HTML head.`,
      whyItMatters: 'Pages with noindex cannot appear in organic search results, generate organic traffic, or be retrieved by search-driven answer engines.',
      recommendedAction: 'Remove the "noindex" directive from the robots meta tag on production environments.',
      suggestedImplementation: '<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1">',
      expectedOutcome: 'Search engines can index the URL and display it in organic search rankings.',
      validation: 'Verify HTTP response with: curl -sL <url> | grep -i "robots"',
    });
  }

  const isHttps = crawlData?.url?.startsWith('https:') || false;
  if (!isHttps) {
    recommendations.push({
      id: 'rec-https',
      title: 'Enforce HTTPS Transport Encryption and Automatic 301 Redirection',
      module: 'SEO',
      priority: 'P0',
      effort: 'Medium',
      problem: 'Page is served over unencrypted HTTP protocol without mandatory SSL/TLS security.',
      evidence: `Requested URL protocol is "${crawlData?.url?.split('://')[0] || 'http'}:".`,
      whyItMatters: 'HTTPS is a confirmed Google core ranking signal and a mandatory security baseline for user data protection and browser trust.',
      recommendedAction: 'Install a trusted TLS certificate (e.g. Let\'s Encrypt) and configure your web server (Nginx/Apache/Cloudflare) to 301 redirect all HTTP requests to HTTPS.',
      suggestedImplementation: 'server {\n  listen 80;\n  server_name yourdomain.com;\n  return 301 https://$host$request_uri;\n}',
      expectedOutcome: 'Eliminates "Not Secure" browser warning, protects data integrity, and improves organic search ranking eligibility.',
      validation: 'Test HTTP to HTTPS redirect with: curl -I http://<domain>',
    });
  }

  // ── 2. Check for P1 High Impact Improvements ──────────────────────────────
  if (entityData.clarityRating === 'Ambiguous' || entityData.clarityRating === 'Unidentified') {
    recommendations.push({
      id: 'rec-entity-schema',
      title: 'Establish Authoritative Organization Schema & Knowledge Graph Entity',
      module: 'GEO',
      priority: 'P1',
      effort: 'Low',
      problem: 'The website lacks structured Organization or LocalBusiness Schema.org JSON-LD markup, leaving its brand identity ambiguous to generative AI systems.',
      evidence: 'No Organization or Corporation @type schema object identified in DOM.',
      whyItMatters: 'Generative engines (ChatGPT, Google Gemini, Perplexity) rely on structured entity graphs to attribute facts, products, and quotes to a verified corporate entity.',
      recommendedAction: 'Embed JSON-LD Organization markup on the homepage with verified name, logo, description, sameAs social links, and contact channels.',
      suggestedImplementation: `<script type="application/ld+json">\n{\n  "@context": "https://schema.org",\n  "@type": "Organization",\n  "name": "${entityData.brandName}",\n  "url": "${crawlData?.url || 'https://example.com'}",\n  "logo": "${crawlData?.url || 'https://example.com'}/logo.png",\n  "sameAs": [\n    "https://twitter.com/yourbrand",\n    "https://linkedin.com/company/yourbrand"\n  ]\n}\n<\/script>`,
      expectedOutcome: 'Improves entity disambiguation in Google Knowledge Panels and increases accuracy of generative AI citations.',
      validation: 'Validate structured markup using Google Rich Results Test (https://search.google.com/test/rich-results).',
    });
  }

  if (contentData.headingStats.h1 !== 1) {
    recommendations.push({
      id: 'rec-h1-hierarchy',
      title: contentData.headingStats.h1 === 0 ? 'Add a Descriptive, Unique H1 Heading' : 'Consolidate Multiple H1 Headings into a Single Primary H1',
      module: 'SEO',
      priority: 'P1',
      effort: 'Low',
      problem: contentData.headingStats.h1 === 0
        ? 'No <h1> heading was found on the page. Search engines and screen readers rely on H1 to understand the primary topic.'
        : `Found ${contentData.headingStats.h1} separate <h1> headings. Multiple H1s dilute topical focus.`,
      evidence: `Heading stats: ${contentData.headingStats.h1} H1s discovered on page.`,
      whyItMatters: 'A single, prominent H1 establishes primary topical relevance for search crawlers and generative content extractors.',
      recommendedAction: 'Ensure exactly one <h1> element encapsulates the page\'s primary topic, and convert secondary headings to <h2>.',
      suggestedImplementation: `<h1>${parsedData.title ? parsedData.title.split(/[-–|]/)[0].trim() : 'Primary Topical Title'}</h1>`,
      expectedOutcome: 'Clearer semantic hierarchy and improved ranking relevance for primary query keywords.',
      validation: 'Inspect DOM with: document.querySelectorAll("h1").length === 1',
    });
  }

  // Intent mismatch recommendations
  if (intentData.mismatches?.length > 0) {
    intentData.mismatches.forEach((mismatch, idx) => {
      recommendations.push({
        id: `rec-intent-${idx}`,
        title: `Resolve Search Intent Mismatch: ${mismatch.type.replace(/_/g, ' ')}`,
        module: 'SEO',
        priority: 'P1',
        effort: 'Medium',
        problem: mismatch.description,
        evidence: `Primary intent is ${intentData.primaryIntentLabel}, but content structure diverges from user expectations.`,
        whyItMatters: 'Search engines demote pages with high bounce rates caused by mismatched user intent.',
        recommendedAction: mismatch.recommendation,
        suggestedImplementation: 'Align heading promises directly with above-the-fold content blocks and scannable conversion elements.',
        expectedOutcome: 'Increases dwell time, lowers search abandonment, and improves organic ranking stability.',
        validation: 'Review user engagement metrics in Google Analytics / Search Console for session duration and bounce rates.',
      });
    });
  }

  // ── 3. Check for P2 Growth Opportunities ──────────────────────────────────
  if (questionData.score < 70) {
    recommendations.push({
      id: 'rec-faq-schema',
      title: 'Implement Structured FAQ / Q&A Blocks with FAQPage Schema',
      module: 'AEO',
      priority: 'P2',
      effort: 'Medium',
      problem: 'Website answers few natural language questions directly, limiting eligibility for Google Featured Snippets and conversational AI answers.',
      evidence: `Identified only ${questionData.answeredQuestionsCount} direct question blocks. FAQPage Schema is not active.`,
      whyItMatters: 'Search engines prioritize question-answer pairs for Position 0 Featured Snippets and People Also Ask expandable modules.',
      recommendedAction: 'Add a dedicated FAQ section addressing top user journey questions and annotate it with FAQPage JSON-LD.',
      suggestedImplementation: `<script type="application/ld+json">\n{\n  "@context": "https://schema.org",\n  "@type": "FAQPage",\n  "mainEntity": [{\n    "@type": "Question",\n    "name": "How does ${entityData.brandName} work?",\n    "acceptedAnswer": {\n      "@type": "Answer",\n      "text": "${entityData.brandName} delivers automated analysis by combining live telemetry with verified scoring models."\n    }\n  }]\n}\n<\/script>`,
      expectedOutcome: 'Increases likelihood of ranking in Google "People Also Ask" carousels and provides direct citation sources for voice assistants.',
      validation: 'Test with Google Search Console Rich Results Tool and verify question formatting.',
    });
  }

  if (contentData.tables.length === 0 && contentData.lists.totalLists < 2) {
    recommendations.push({
      id: 'rec-structured-tables',
      title: 'Add Comparison Tables and Specification Lists for AI Extractability',
      module: 'GEO',
      priority: 'P2',
      effort: 'Medium',
      problem: 'Content is presented primarily in long-form paragraphs without tabular summaries or bulleted specifications.',
      evidence: '0 HTML tables and fewer than 2 lists detected in DOM.',
      whyItMatters: 'Generative AI extractors (Gemini, ChatGPT) heavily favor structured tables when synthesizing answers for comparison and feature queries.',
      recommendedAction: 'Summarize core features, specifications, and pricing tiers in an HTML <table> with explicit <th> header cells.',
      suggestedImplementation: '<table class="specs-table">\n  <thead>\n    <tr><th>Feature</th><th>Standard Tier</th><th>Enterprise Tier</th></tr>\n  </thead>\n  <tbody>\n    <tr><td>Security Probes</td><td>Included</td><td>Continuous Real-Time</td></tr>\n  </tbody>\n</table>',
      expectedOutcome: 'Enables AI engines to extract tabular data for comparison answers and improves on-page user scannability.',
      validation: 'Verify table renders cleanly on mobile viewports with horizontal scroll wrappers.',
    });
  }

  // ── 4. Check for P3 Refinements ───────────────────────────────────────────
  if (contentData.linksAnalysis.genericAnchorsCount > 0) {
    recommendations.push({
      id: 'rec-generic-anchors',
      title: 'Replace Generic Anchor Texts ("Click Here", "Learn More") with Descriptive Phrases',
      module: 'SEO',
      priority: 'P3',
      effort: 'Low',
      problem: `Found ${contentData.linksAnalysis.genericAnchorsCount} internal links with non-descriptive anchor text such as "click here", "read more", or "learn more".`,
      evidence: `Sample generic anchors: ${contentData.linksAnalysis.genericAnchors.map(a => `"${a.anchor}"`).slice(0, 3).join(', ')}.`,
      whyItMatters: 'Descriptive anchor text passes contextual topical authority to destination pages, helping search engines understand linked concepts.',
      recommendedAction: 'Update anchor texts to describe the exact destination topic (e.g. change "Click Here" to "Review our cybersecurity audit report").',
      suggestedImplementation: '<a href="/security-audit">Read our complete cybersecurity audit guide</a>',
      expectedOutcome: 'Improved internal PageRank distribution and keyword relevance for linked destination URLs.',
      validation: 'Audit site crawl links in screaming frog or custom script to ensure 0 generic anchor occurrences.',
    });
  }

  if (contentData.imagesAnalysis.missingAlt > 0) {
    recommendations.push({
      id: 'rec-image-alt',
      title: `Add Descriptive Alt Text Attributes to ${contentData.imagesAnalysis.missingAlt} Images`,
      module: 'SEO',
      priority: 'P3',
      effort: 'Low',
      problem: `${contentData.imagesAnalysis.missingAlt} images lack descriptive alt attributes.`,
      evidence: `${contentData.imagesAnalysis.missingAlt} of ${contentData.imagesAnalysis.total} images missing alt text.`,
      whyItMatters: 'Image alt text is critical for accessibility (WCAG compliance) and allows visual search crawlers (Google Images) to index graphic assets.',
      recommendedAction: 'Add concise, descriptive alt text to every non-decorative image explaining the visual subject matter.',
      suggestedImplementation: '<img src="/assets/dashboard-chart.png" alt="WebVitals 2.0 Security Posture Matrix Dashboard">',
      expectedOutcome: 'Full accessibility compliance and expanded visibility in Google Image search.',
      validation: 'Inspect images in DOM to verify all <img> tags have non-empty alt attributes.',
    });
  }

  // Group into P0, P1, P2, P3
  const grouped = {
    P0: recommendations.filter(r => r.priority === 'P0'),
    P1: recommendations.filter(r => r.priority === 'P1'),
    P2: recommendations.filter(r => r.priority === 'P2'),
    P3: recommendations.filter(r => r.priority === 'P3'),
  };

  return {
    totalCount: recommendations.length,
    grouped,
    list: recommendations,
  };
}

module.exports = {
  generateStructuredRecommendations,
};
