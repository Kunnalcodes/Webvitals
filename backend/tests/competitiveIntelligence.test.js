/**
 * Test Suite: Competitive Business Intelligence & Keyword Opportunity Engine
 * WebVitals 2.0
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { validateCompetitivePair, validateAndNormalizeTarget } = require('../competitive/domainValidator');
const { discoverCompetitiveKeywords, extractNgrams, extractSlugKeywords } = require('../competitive/keywordDiscoveryService');
const { classifyKeywordIntent, categorizeKeyword, expandAndEnrichKeywords } = require('../competitive/keywordExpansionService');
const { clusterKeywords, buildTopicMap, detectCannibalizationRisks } = require('../competitive/keywordClusteringService');
const { analyzeKeywordGaps, calculateOpportunityScore } = require('../competitive/keywordGapEngine');
const { analyzeContentGaps } = require('../competitive/contentGapEngine');
const { compareSeoInfrastructure, reverseEngineerSeoStrategies } = require('../competitive/seoComparisonEngine');
const { compareGeoReadiness } = require('../competitive/geoComparisonEngine');
const { compareAeoReadiness } = require('../competitive/aeoComparisonEngine');
const { compareAuthoritySignals } = require('../competitive/authorityAnalysisService');
const { generateGrowthStrategy } = require('../competitive/growthStrategyGenerator');
const { generateCompetitiveAiAnalysis, buildDeterministicCompetitiveNarrative } = require('../competitive/vertexCompetitiveAnalyst');
const { evaluateCompetitivePosition } = require('../competitive/competitiveOrchestrator');

describe('Competitive Domain Validator', () => {
  it('validates distinct public targets and rejects invalid or identical inputs', () => {
    const valid = validateCompetitivePair('example.com', 'github.com', { industry: 'Tech' });
    assert.ok(valid.isValid);
    assert.equal(valid.primary.domain, 'example.com');
    assert.equal(valid.competitor.domain, 'github.com');
    assert.equal(valid.options.industry, 'Tech');

    // Rejects identical domains
    const same = validateCompetitivePair('https://example.com', 'https://www.example.com');
    assert.equal(same.isValid, false);
    assert.match(same.error, /same domain/i);

    // Rejects localhost / private IPs
    const privateCheck = validateAndNormalizeTarget('http://127.0.0.1:8080');
    assert.equal(privateCheck.isValid, false);

    // Rejects empty string
    const empty = validateCompetitivePair('', 'example.com');
    assert.equal(empty.isValid, false);
  });
});

describe('Multi-Source Keyword Discovery Pipeline', () => {
  it('discovers keywords from titles, headings, n-grams, slugs and questions', () => {
    const primaryInv = {
      domain: 'primary.dev',
      url: 'https://primary.dev',
      homepage: {
        title: 'PrimaryDev — Web Security Scanner & SSL Diagnostics',
        headings: {
          h1: ['Next-Gen Vulnerability Scanner'],
          h2: ['How to Audit SSL Certificates', 'Automated Penetration Testing'],
          h3: ['Pricing and Subscription Plans'],
        },
        semantic: {
          cleanBodyText: 'Our automated penetration testing tool detects vulnerabilities, open ports, and broken SSL certificates.',
          qaBlocks: [{ question: 'How Does PrimaryDev Audit SSL Certificates?' }],
        },
      },
      subPages: [
        {
          url: 'https://primary.dev/pricing',
          title: 'Pricing — PrimaryDev',
          headings: { h1: ['Simple Transparent Pricing'] },
        },
      ],
      sitemap: { sampleUrls: ['https://primary.dev/ssl-checker', 'https://primary.dev/dns-audit'] },
    };

    const competitorInv = {
      domain: 'competitor.io',
      url: 'https://competitor.io',
      homepage: {
        title: 'CompetitorIO — Complete Attack Surface Management',
        headings: {
          h1: ['Attack Surface Intelligence'],
          h2: ['Continuous Cyber Risk Monitoring', 'Cloud Security Posture'],
          h3: ['Why Choose CompetitorIO vs Alternatives'],
        },
        semantic: {
          cleanBodyText: 'Continuous cyber risk monitoring and attack surface intelligence for modern cloud infrastructure.',
          qaBlocks: [{ question: 'What Is Attack Surface Management?' }],
        },
      },
      subPages: [],
      sitemap: { sampleUrls: ['https://competitor.io/cloud-security'] },
    };

    const result = discoverCompetitiveKeywords(primaryInv, competitorInv, ['cybersecurity audit']);

    assert.ok(result.primaryKeywords.length >= 5);
    assert.ok(result.competitorKeywords.length >= 5);
    assert.ok(result.combinedKeywords.length >= 10);

    // Verify source attribution
    assert.ok(result.combinedKeywords.some(k => k.sourceType.startsWith('heading') || k.sourceType.startsWith('title')));
    assert.ok(result.combinedKeywords.some(k => k.sourceType === 'user_seed'));
  });

  it('extracts n-grams and slug keywords cleanly', () => {
    const text = 'cloud security posture management and automated penetration testing for modern engineering teams';
    const ngrams = extractNgrams(text, 2, 3, 5);
    assert.ok(ngrams.length > 0);
    assert.ok(ngrams[0].phrase.split(' ').length >= 2);

    const slugs = extractSlugKeywords(['https://test.com/network-scanner', 'https://test.com/docs/api-guide.html']);
    assert.ok(slugs.includes('network scanner'));
    assert.ok(slugs.includes('api guide'));
  });
});

describe('Keyword Expansion, Intent & Data Model', () => {
  it('classifies search intent and 12 strategic categories accurately', () => {
    assert.equal(classifyKeywordIntent('buy vulnerability scanner online'), 'transactional');
    assert.equal(classifyKeywordIntent('best web security tools 2026'), 'commercial');
    assert.equal(classifyKeywordIntent('how to audit ssl certificate'), 'informational');
    assert.equal(classifyKeywordIntent('security auditor in california near me'), 'local');

    const context = { primaryDomain: 'webvitals.dev', competitorDomain: 'acme-scanner.com' };
    assert.equal(categorizeKeyword('webvitals pricing', context), 'brand');
    assert.equal(categorizeKeyword('webvitals vs acme-scanner', context), 'comparison');
    assert.equal(categorizeKeyword('how does dnssec prevent spoofing', context), 'question');
    assert.equal(categorizeKeyword('fix ssl handshake failure error', context), 'pain_point');
    assert.equal(categorizeKeyword('fast automated api endpoint scanner for devops', context), 'long_tail');

    // Enrich and check non-zero metric policy
    const enriched = expandAndEnrichKeywords(
      [{ keyword: 'best web security scanner', source: 'heading_h1', sourceType: 'heading', primaryPresent: true }],
      context
    );

    assert.equal(enriched[0].searchVolume, null);
    assert.equal(enriched[0].volumeStatus, 'UNAVAILABLE — provider integration required');
    assert.ok(enriched[0].businessValue >= 50);
  });
});

describe('Keyword Clustering & Cannibalization', () => {
  it('clusters keywords and detects page cannibalization risks', () => {
    const rawKws = [
      { keyword: 'ssl certificate scanner', category: 'core', intent: 'commercial', primaryPresent: true },
      { keyword: 'ssl certificate audit', category: 'core', intent: 'commercial', primaryPresent: true },
      { keyword: 'ssl certificate validation tool', category: 'core', intent: 'commercial', primaryPresent: true },
      { keyword: 'cloud security posture', category: 'industry', intent: 'commercial', primaryPresent: false },
    ];

    const clusters = clusterKeywords(rawKws);
    assert.ok(clusters.length >= 1);
    assert.ok(clusters[0].keywordCount >= 2);

    const topicMap = buildTopicMap(clusters);
    assert.ok(topicMap.length >= 1);
    assert.ok(topicMap[0].mainTopic);

    // Test cannibalization detector
    const pages = [
      { url: 'https://site.com/ssl-check', title: 'SSL Certificate Scanner & Audit Tool' },
      { url: 'https://site.com/tools/ssl-scanner', title: 'SSL Certificate Scanner and Audit Tool' },
    ];
    const risks = detectCannibalizationRisks(pages, rawKws);
    assert.ok(risks.length >= 1);
    assert.equal(risks[0].type, 'CANONICAL_OR_TOPIC_OVERLAP');
  });
});

describe('Keyword Gap Analysis & Opportunity Scoring', () => {
  it('segregates keywords into dynamic buckets and calculates transparent scores', () => {
    const keywords = [
      {
        keyword: 'continuous vulnerability scanner',
        category: 'core',
        intent: 'commercial',
        businessValue: 70,
        primaryPresent: false,
        competitorPresent: true,
        competitorTargetPage: 'https://comp.io/vuln',
      },
      {
        keyword: 'web security platform',
        category: 'core',
        intent: 'commercial',
        businessValue: 75,
        primaryPresent: true,
        competitorPresent: true,
      },
      {
        keyword: 'how to fix ssl errors',
        category: 'question',
        intent: 'informational',
        businessValue: 60,
        primaryPresent: false,
        competitorPresent: true,
      },
    ];

    const gapReport = analyzeKeywordGaps(keywords, { primaryDomain: 'mysite.dev', competitorDomain: 'comp.io' });

    assert.equal(gapReport.buckets.competitorGaps.length, 1);
    assert.equal(gapReport.buckets.sharedKeywords.length, 1);
    assert.equal(gapReport.buckets.questionGaps.length, 1);

    const topOp = gapReport.topOpportunities[0];
    assert.ok(topOp.opportunityScore >= 50);
    assert.ok(['P0', 'P1', 'P2', 'P3'].includes(topOp.priority));
    assert.ok(topOp.whyItMatters);
    assert.ok(topOp.recommendedContentAction);
  });
});

describe('Content Gap & Strategy Engine', () => {
  it('detects page type differences and recommends original content assets', () => {
    const primaryInv = {
      domain: 'mysite.dev',
      homepage: { wordCount: 800 },
      subPages: [],
      pagesByType: { pricing: 0, service: 1, comparison: 0 },
    };
    const competitorInv = {
      domain: 'comp.io',
      homepage: { wordCount: 1600 },
      subPages: [{ type: 'pricing', url: 'https://comp.io/pricing', wordCount: 1200 }],
      pagesByType: { pricing: 1, service: 3, comparison: 1 },
    };

    const kwGaps = { buckets: { competitorGaps: [{ keyword: 'api scanner', intent: 'commercial', priority: 'P0' }] } };
    const contentReport = analyzeContentGaps(primaryInv, competitorInv, kwGaps);

    assert.ok(contentReport.totalGapsIdentified >= 2);
    assert.ok(contentReport.gaps.some(g => g.pageType === 'pricing'));
    assert.ok(contentReport.gaps.some(g => g.suggestedTitle && g.suggestedOutline));
    assert.equal(contentReport.contentDepth.depthAdvantage, 'Competitor');
  });
});

describe('SEO, GEO, AEO & Authority Comparisons', () => {
  it('benchmarks infrastructure, GEO entity clarity, AEO questions, and external signals', () => {
    const primaryInv = {
      domain: 'site-a.com',
      url: 'https://site-a.com',
      elapsedMs: 120,
      homepage: {
        title: 'Site A',
        canonicalUrl: 'https://site-a.com',
        schemaTypes: ['Organization', 'WebSite'],
        wordCount: 1200,
        headings: { h1: ['Site A'], h2: ['About', 'Services'] },
        links: { internalCount: 20 },
        semantic: { cleanBodyText: 'Site A provides enterprise network intelligence.', tables: [{}], definitions: [{}] },
      },
      sitemap: { exists: true, discoveredUrlsCount: 15 },
      robotsTxt: { exists: true, content: 'User-agent: *\nAllow: /' },
      pagesByType: { service: 2 },
    };

    const competitorInv = {
      domain: 'site-b.com',
      url: 'https://site-b.com',
      elapsedMs: 350,
      homepage: {
        title: 'Site B',
        canonicalUrl: '',
        schemaTypes: [],
        wordCount: 800,
        headings: { h1: ['Site B', 'Another H1'], h2: [] },
        links: { internalCount: 5 },
        semantic: { cleanBodyText: 'Site B security tools.' },
      },
      sitemap: { exists: false, discoveredUrlsCount: 0 },
      robotsTxt: { exists: false, content: '' },
      pagesByType: { service: 0 },
    };

    const seoInfra = compareSeoInfrastructure(primaryInv, competitorInv);
    assert.equal(seoInfra.summary.infrastructureLeader, 'Primary');

    const seoStrats = reverseEngineerSeoStrategies(primaryInv, competitorInv);
    assert.ok(seoStrats.length >= 5);

    const geo = compareGeoReadiness(primaryInv, competitorInv);
    assert.ok(geo.primaryGeoScore > geo.competitorGeoScore);

    const aeo = compareAeoReadiness(primaryInv, competitorInv, [
      { keyword: 'how does site a work', category: 'question', primaryPresent: true, competitorPresent: false },
    ]);
    assert.ok(aeo.primaryAeoScore >= 50);

    const auth = compareAuthoritySignals(primaryInv, competitorInv);
    assert.equal(auth.backlinks.status, 'UNAVAILABLE');
    assert.equal(auth.backlinks.displayMessage, 'Unavailable — data source required');
  });
});

describe('Growth Strategy & Vertex AI Competitive Analyst', async () => {
  it('generates 5-phase "How to Compete" roadmap with evidence', () => {
    const primaryInv = { domain: 'p.dev', url: 'https://p.dev', robotsTxt: { exists: false }, homepage: {} };
    const competitorInv = { domain: 'c.io', url: 'https://c.io', robotsTxt: { exists: true }, homepage: {} };
    const kwGaps = { buckets: { competitorGaps: [{ keyword: 'ssl checker', competitorTargetPage: 'https://c.io/ssl' }] } };
    const contentGaps = { gaps: [{ pageType: 'comparison', topic: 'P vs C' }] };

    const strategy = generateGrowthStrategy(primaryInv, competitorInv, kwGaps, contentGaps, {});
    assert.ok(strategy.phase1Fix.length >= 1);
    assert.ok(strategy.phase2Capture.length >= 1);
    assert.ok(strategy.totalRoadmapActions >= 3);
  });

  it('synthesizes AI narrative with deterministic zero-downtime fallback', async () => {
    const evidence = {
      primaryDomain: 'p.dev',
      competitorDomain: 'c.io',
      seoLeader: 'Primary',
      geoLeader: 'Primary',
      aeoLeader: 'Parity',
      topGaps: ['cloud compliance'],
    };

    const narrative = await generateCompetitiveAiAnalysis(evidence);
    assert.ok(narrative.executiveComparison);
    assert.ok(narrative.primaryAdvantages.length > 0);
    assert.ok(narrative.competitorStrategies.length > 0);
    assert.ok(narrative.confidence >= 0.85);

    const position = evaluateCompetitivePosition({ seoLeader: 'Primary', geoLeader: 'Primary', aeoLeader: 'Primary' });
    assert.equal(position.status, 'COMPETITIVE_ADVANTAGE');
  });
});
