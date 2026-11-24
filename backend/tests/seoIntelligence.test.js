/**
 * SEO, GEO & AEO Intelligence Engine Unit Tests — WebVitals 2.0
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { extractDeepContent } = require('../seo/intelligence/contentExtractor');
const { analyzeEntityAndBrand } = require('../seo/intelligence/entityAnalyzer');
const { classifySearchIntent } = require('../seo/intelligence/searchIntentAnalyzer');
const { analyzeQuestionCoverage } = require('../seo/intelligence/questionCoverageAnalyzer');
const { detectAllStrategies } = require('../seo/intelligence/strategyDetector');
const { calculateSeoScore, calculateGeoScore, calculateAeoScore } = require('../seo/intelligence/scoringEngines');
const { generateStructuredRecommendations } = require('../seo/intelligence/recommendationEngine');
const { PROVENANCE_LEVELS } = require('../seo/intelligence/evidenceValidator');
const { buildSeoIntelligenceReport } = require('../seo/intelligence');

const MOCK_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <title>WebVitals — Advanced Website Intelligence & Security Platform</title>
  <meta name="description" content="Discover WebVitals: The comprehensive website intelligence, security posture, and SEO/GEO/AEO analysis platform for engineers.">
  <meta name="robots" content="index, follow">
  <link rel="canonical" href="https://webvitals.dev">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "WebVitals Inc",
    "url": "https://webvitals.dev",
    "sameAs": ["https://twitter.com/webvitals", "https://linkedin.com/company/webvitals"]
  }
  </script>
</head>
<body>
  <header><nav><a href="/">Home</a><a href="/about">About</a><a href="/contact">Contact</a></nav></header>
  <main>
    <h1>WebVitals: Enterprise Website Intelligence & Cybersecurity Analysis</h1>
    <p>WebVitals is an automated security scanning and search discoverability platform built for security teams and engineering architects. Over 98.5% of modern web properties have unaddressed security header gaps or unindexed topical assets according to our recent benchmark study.</p>

    <h2>How Does WebVitals Scan and Audit Websites?</h2>
    <p>WebVitals executes 43 concurrent diagnostic checks spanning DNS delegation, TLS 1.3 handshake negotiation, HTTP security headers, and Sustainable Web Design carbon metrics in real time.</p>

    <h2>What Is the Pricing Structure for WebVitals?</h2>
    <p>WebVitals offers a free open-source scanner alongside dedicated Enterprise automation plans with continuous perimeter monitoring.</p>

    <div class="specs">
      <table>
        <thead><tr><th>Capability</th><th>Community Tier</th><th>Enterprise Tier</th></tr></thead>
        <tbody>
          <tr><td>Perimeter Diagnostics</td><td>43 Checks</td><td>Continuous Real-Time</td></tr>
          <tr><td>GEO & AEO Intelligence</td><td>Full Audit</td><td>Continuous Telemetry</td></tr>
        </tbody>
      </table>
    </div>

    <ul>
      <li>Automated TLS and SSL certificate expiry monitoring</li>
      <li>Comprehensive robots.txt and sitemap discoverability analysis</li>
      <li>Grounded Generative Engine Optimization (GEO) scoring</li>
    </ul>

    <dl>
      <dt>GEO (Generative Engine Optimization)</dt>
      <dd>The discipline of optimizing digital content and entity signals to maximize machine comprehension and citation potential in AI answer engines.</dd>
    </dl>

    <div class="cta">
      <a href="/signup" class="btn">Start Free Trial Now</a>
    </div>
  </main>
  <footer>
    <p>© 2026 WebVitals Inc. All rights reserved. <a href="https://twitter.com/webvitals">Follow on X</a></p>
  </footer>
</body>
</html>
`;

describe('Content Extractor', () => {
  it('extracts heading hierarchy, tables, lists, definitions, and word counts', () => {
    const parsedData = {
      title: 'WebVitals — Advanced Website Intelligence',
      links: [{ url: 'https://webvitals.dev/about', text: 'About', isInternal: true }],
      images: [],
    };
    const content = extractDeepContent(MOCK_HTML, parsedData, 'https://webvitals.dev');

    assert.ok(content.wordCount > 100);
    assert.equal(content.headingStats.h1, 1);
    assert.equal(content.headingStats.h2, 2);
    assert.equal(content.tables.length, 1);
    assert.equal(content.definitions.length, 1);
    assert.ok(content.qaBlocks.length >= 2);
    assert.equal(content.freshness.copyrightYear, 2026);
    assert.equal(content.freshness.isRecent, true);
  });
});

describe('Entity & Brand Analyzer', () => {
  it('extracts brand identity, Organization schema, social profiles, and assesses clarity', () => {
    const parsedData = {
      title: 'WebVitals — Advanced Website Intelligence',
      jsonLd: [{
        '@type': 'Organization',
        name: 'WebVitals Inc',
        sameAs: ['https://twitter.com/webvitals', 'https://linkedin.com/company/webvitals'],
      }],
      links: [
        { url: 'https://webvitals.dev/about', text: 'About' },
        { url: 'https://webvitals.dev/contact', text: 'Contact' },
      ],
      openGraph: { site_name: 'WebVitals' },
    };
    const contentData = extractDeepContent(MOCK_HTML, parsedData, 'https://webvitals.dev');
    const entity = analyzeEntityAndBrand(parsedData, contentData, 'https://webvitals.dev');

    assert.equal(entity.brandName, 'WebVitals Inc');
    assert.ok(entity.socialProfiles.length >= 2);
    assert.ok(entity.clarityScore >= 80);
    assert.equal(entity.clarityRating, 'High');
    assert.ok(entity.verifiedSignals.length >= 2);
  });
});

describe('Search Intent Classifier', () => {
  it('classifies primary search intent and identifies mismatches', () => {
    const parsedData = {
      title: 'Buy WebVitals Pricing & Plans',
      metaDescription: 'Purchase WebVitals enterprise cybersecurity platform.',
    };
    const contentData = {
      cleanBodyText: 'General overview of software without pricing or checkout buttons.',
      headingStats: { h1: 1 },
      headingsTree: [{ level: 1, text: 'Buy WebVitals Pricing' }],
      qaBlocks: [],
      tables: [],
      lists: { totalLists: 0 },
      wordCount: 250,
    };
    const intent = classifySearchIntent(parsedData, contentData, 'https://webvitals.dev/pricing');

    assert.equal(intent.primaryIntent, 'transactional');
    assert.ok(intent.hasMismatch);
    assert.ok(intent.mismatches.some(m => m.type === 'TRANSACTIONAL_CTA_GAP'));
  });
});

describe('Question Coverage Analyzer', () => {
  it('discovers answered questions and evaluates 6-stage user journey', () => {
    const contentData = {
      cleanBodyText: 'How does WebVitals scan websites? It audits DNS, TLS, and security headers. What is the pricing? Free trial available.',
      qaBlocks: [
        { question: 'How Does WebVitals Scan and Audit Websites?', answerSnippet: 'Audits DNS, TLS, and security headers in real time.' },
        { question: 'What Is the Pricing Structure for WebVitals?', answerSnippet: 'Free open-source scanner alongside Enterprise plans.' },
      ],
      definitions: [{ term: 'GEO', definition: 'Generative Engine Optimization' }],
      tables: [{ rowCount: 2 }],
      lists: { totalLists: 1 },
    };
    const entityData = { brandName: 'WebVitals', primaryCategory: 'Cybersecurity & Network Defense' };
    const intentData = { primaryIntentLabel: 'Informational' };

    const qResult = analyzeQuestionCoverage(contentData, entityData, intentData);

    assert.ok(qResult.score >= 50);
    assert.equal(qResult.answeredQuestionsCount, 2);
    assert.ok(qResult.coveredStagesCount >= 1);
    assert.ok(qResult.journeyCoverage.Awareness !== undefined);
  });
});

describe('Scoring Engines (SEO, GEO, AEO)', () => {
  it('calculates deterministic scores and weighted factors', () => {
    const parsedData = {
      title: 'WebVitals — Enterprise Website Intelligence Platform',
      metaDescription: 'Audit web security, performance, and SEO/GEO/AEO discoverability in real time.',
      canonicalUrl: 'https://webvitals.dev',
      viewport: 'width=device-width, initial-scale=1',
      jsonLd: [{ '@type': 'Organization', name: 'WebVitals' }],
    };
    const contentData = {
      wordCount: 1200,
      readingTimeMinutes: 6,
      boilerplateRatio: 0.15,
      headingStats: { h1: 1, hasHierarchyIssue: false },
      linksAnalysis: { internal: 15, genericAnchorsCount: 0 },
      tables: [{ rowCount: 5 }],
      lists: { totalLists: 3 },
      definitions: [{ term: 'AEO', definition: 'Answer Engine Optimization' }],
      freshness: { isRecent: true },
      cleanBodyText: 'Over 98% of websites have security gaps in our recent benchmark study.',
    };
    const entityData = {
      brandName: 'WebVitals',
      clarityScore: 90,
      clarityRating: 'High',
      verifiedSignals: ['Schema', 'Social'],
      ambiguitySignals: [],
      authorship: { authorName: 'Security Team', hasBio: true },
    };
    const crawlData = {
      url: 'https://webvitals.dev',
      robotsTxt: { exists: true, contentSample: 'User-agent: *\nAllow: /' },
    };
    const questionData = {
      score: 85,
      readinessRating: 'Featured-Snippet Ready',
      answeredQuestionsCount: 4,
      answeredQuestions: [{ hasDirectAnswer: true }, { hasDirectAnswer: true }],
      coveredStagesCount: 5,
      answerStructuresDetected: { hasFaqSchema: true, hasTables: true, hasLists: true },
    };
    const intentData = { hasMismatch: false };

    const seo = calculateSeoScore({ parsedData, contentData, crawlData, lighthouse: { scores: { performance: 95 } } });
    const geo = calculateGeoScore({ parsedData, contentData, entityData, crawlData });
    const aeo = calculateAeoScore({ contentData, questionData, intentData });

    assert.ok(seo.score >= 80);
    assert.equal(seo.factors.length, 8);
    assert.ok(geo.score >= 70);
    assert.equal(geo.factors.length, 6);
    assert.ok(aeo.score >= 75);
    assert.equal(aeo.factors.length, 5);
  });
});

describe('Recommendation Engine & Provenance', () => {
  it('groups recommendations into P0, P1, P2, P3 with structured fields', () => {
    const parsedData = {
      title: 'Short',
      metaDescription: '',
      metaRobots: 'noindex', // triggers P0
    };
    const contentData = {
      headingStats: { h1: 0, hasHierarchyIssue: true }, // triggers P1
      tables: [],
      lists: { totalLists: 0 }, // triggers P2
      linksAnalysis: { genericAnchorsCount: 3, genericAnchors: [{ anchor: 'click here' }] }, // triggers P3
      imagesAnalysis: { missingAlt: 2, total: 5 }, // triggers P3
    };
    const entityData = { clarityRating: 'Ambiguous', brandName: 'Target' };
    const intentData = { mismatches: [] };
    const questionData = { score: 40, answeredQuestionsCount: 0 };
    const crawlData = { url: 'http://insecure.com', robotsTxt: { exists: false } }; // triggers P0 HTTPS

    const recs = generateStructuredRecommendations({
      parsedData,
      contentData,
      entityData,
      intentData,
      questionData,
      crawlData,
      seoScores: { score: 45 },
      geoScores: { score: 40 },
      aeoScores: { score: 35 },
    });

    assert.ok(recs.grouped.P0.length >= 1);
    assert.ok(recs.grouped.P1.length >= 1);
    assert.ok(recs.grouped.P2.length >= 1);
    assert.ok(recs.grouped.P3.length >= 1);

    // Verify structured format
    const sample = recs.list[0];
    assert.ok(sample.problem);
    assert.ok(sample.evidence);
    assert.ok(sample.whyItMatters);
    assert.ok(sample.recommendedAction);
    assert.ok(sample.suggestedImplementation);
    assert.ok(sample.expectedOutcome);
    assert.ok(sample.validation);
  });
});

describe('Full SEO/GEO/AEO Intelligence Report Orchestrator', () => {
  it('assembles complete report with strategy matrix, roadmap, and provenance disclosures', async () => {
    const report = await buildSeoIntelligenceReport({
      targetUrl: 'https://webvitals.dev',
      crawlResult: {
        statusCode: 200,
        finalUrl: 'https://webvitals.dev',
        body: MOCK_HTML,
        chain: [{ url: 'https://webvitals.dev', status: 200 }],
        elapsedMs: 250,
      },
      parsedData: {
        title: 'WebVitals — Advanced Website Intelligence & Security Platform',
        metaDescription: 'Discover WebVitals: The comprehensive website intelligence, security posture, and SEO/GEO/AEO analysis platform for engineers.',
        canonicalUrl: 'https://webvitals.dev',
        viewport: 'width=device-width, initial-scale=1',
        jsonLd: [{
          '@type': 'Organization',
          name: 'WebVitals Inc',
          sameAs: ['https://twitter.com/webvitals'],
        }],
        links: [
          { url: 'https://webvitals.dev/about', text: 'About', isInternal: true },
          { url: 'https://webvitals.dev/contact', text: 'Contact', isInternal: true },
        ],
        images: [],
      },
      robotsTxt: { exists: true, status: 200, contentSample: 'User-agent: *\nAllow: /' },
      sitemapXml: { exists: true, status: 200 },
      brokenLinks: [],
      lighthouse: { scores: { performance: 95 } },
    });

    assert.ok(report.overview);
    assert.ok(report.overview.seoScore >= 70);
    assert.ok(report.overview.geoScore >= 60);
    assert.ok(report.overview.aeoScore >= 50);
    assert.equal(report.strategyMatrix.length, 6);
    assert.ok(report.roadmap.P1 !== undefined);
    assert.ok(report.aiIntelligence.executiveNarrative.length > 50);
    assert.ok(report.aiIntelligence.searchEngineInterpretation.length > 50);
    assert.ok(report.aiIntelligence.pageOptimizationDrafts.optimizedTitles.length >= 1);
    assert.equal(report.disclosures.length, 3);
  });
});
