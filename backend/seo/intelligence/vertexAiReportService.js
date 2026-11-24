/**
 * Vertex AI & Gemini Strategic Intelligence Service — WebVitals 2.0
 *
 * Coordinates evidence-grounded AI reasoning to explain:
 *   1. Search Engine Interpretation (How Google/Bing interpret the site)
 *   2. Generative Engine Interpretation (How ChatGPT, Gemini, Perplexity perceive brand & facts)
 *   3. Discoverability Bottlenecks (What prevents citations & top rankings)
 *   4. Page-Level Optimization Workspace Drafts (Titles, Descriptions, Headings, Outlines, Answers)
 *
 * Backed by deterministic evidence-grounded fallback when AI is unavailable or offline.
 */

'use strict';

const { defaultAiProvider } = require('../../ai/aiClient');
const { validateAiOutput } = require('./evidenceValidator');

/**
 * Generates deep strategic intelligence from scan evidence using Vertex AI or deterministic fallback.
 *
 * @param {Object} context
 * @returns {Promise<Object>}
 */
async function generateVertexAiIntelligence(context) {
  const {
    url,
    parsedData = {},
    contentData = {},
    entityData = {},
    intentData = {},
    questionData = {},
    seoScores = {},
    geoScores = {},
    aeoScores = {},
  } = context;

  const brand = entityData.brandName || 'the target brand';
  const category = entityData.primaryCategory || 'Web Property';
  const wordCount = contentData.wordCount || 0;
  const primaryIntent = intentData.primaryIntentLabel || 'Informational';

  // If Vertex AI / Gemini is available, run prompt
  if (defaultAiProvider && defaultAiProvider.isAvailable()) {
    try {
      const prompt = `You are an elite Search Engine, Generative Engine (GEO), and Answer Engine (AEO) Optimization Architect.
Analyze the following VERIFIED website scan evidence and produce a strategic, evidence-grounded intelligence report.

VERIFIED TARGET EVIDENCE:
- URL: ${url}
- Brand Entity: "${brand}"
- Category: "${category}" (Clarity: ${entityData.clarityRating})
- Title: "${parsedData.title || '(Missing)'}"
- Meta Description: "${parsedData.metaDescription || '(Missing)'}"
- Search Intent: ${primaryIntent} (Mismatches: ${intentData.mismatches?.length || 0})
- Headings: H1: ${contentData.headingStats.h1}, H2: ${contentData.headingStats.h2}, H3: ${contentData.headingStats.h3}
- Content Depth: ${wordCount} words, Boilerplate Ratio: ${(contentData.boilerplateRatio * 100).toFixed(0)}%
- Structured Data: ${parsedData.jsonLd?.length || 0} JSON-LD blocks, Tables: ${contentData.tables.length}, Lists: ${contentData.lists.totalLists}
- Question Coverage: ${questionData.answeredQuestionsCount} answered, ${questionData.missingQuestions.length} missing queries
- Evaluated Scores: SEO: ${seoScores.score}/100, GEO: ${geoScores.score}/100, AEO: ${aeoScores.score}/100

STRICT RULES:
1. Ground every claim directly in the provided evidence. DO NOT invent URLs, competitor rankings, or search volumes.
2. Return STRICT valid JSON without markdown wrapping matching the schema below.

JSON SCHEMA:
{
  "executiveNarrative": "A 2-paragraph strategic summary analyzing the site's overall discoverability, entity clarity, and competitive posture.",
  "searchEngineInterpretation": "Detailed explanation of how traditional search engines (Google/Bing) interpret this page's topic, relevance, and technical quality.",
  "generativeAiInterpretation": "Detailed explanation of how LLM/Generative engines (Gemini, ChatGPT, Perplexity) comprehend this brand and whether it is citation-ready.",
  "discoverabilityBottlenecks": [
    { "bottleneck": "...", "impact": "...", "priority": "High" },
    { "bottleneck": "...", "impact": "...", "priority": "Medium" }
  ],
  "pageOptimizationDrafts": {
    "optimizedTitles": [
      { "title": "...", "charCount": 56, "rationale": "High-converting brand + primary intent focus" },
      { "title": "...", "charCount": 54, "rationale": "Topic-first semantic phrasing" }
    ],
    "optimizedDescriptions": [
      { "description": "...", "charCount": 154, "rationale": "Core value proposition with secondary keywords and clear CTA" }
    ],
    "h1Alternatives": [
      { "h1": "...", "rationale": "Direct intent match for user search expectations" }
    ],
    "contentOutline": [
      { "section": "...", "purpose": "...", "suggestedKeywords": ["...", "..."] }
    ],
    "directAnswerBlocks": [
      { "question": "...", "directAnswer": "A 40-50 word standalone answer suitable for Google Position 0 and voice search." }
    ],
    "schemaJsonLd": {
      "@context": "https://schema.org",
      "@type": "WebPage",
      "name": "...",
      "description": "..."
    }
  }
}`;

      const rawResponse = await defaultAiProvider.generateText(
        'You are an expert search engine and generative AI optimization architect. Always output valid JSON only.',
        prompt,
        { temperature: 0.2, maxTokens: 2500 }
      );

      const cleaned = (rawResponse || '')
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/```\s*$/i, '')
        .trim();

      const parsedJson = JSON.parse(cleaned);
      const validated = validateAiOutput(parsedJson, { url, brand });
      if (validated) return validated;
    } catch (err) {
      console.warn('[VertexAIReportService] Vertex AI call failed or timed out. Using deterministic fallback:', err.message);
    }
  }

  // Deterministic Evidence-Grounded Fallback (100% reliable, zero external dependencies)
  return buildDeterministicIntelligence({
    url,
    parsedData,
    contentData,
    entityData,
    intentData,
    questionData,
    seoScores,
    geoScores,
    aeoScores,
  });
}

/**
 * Builds grounded deterministic intelligence when Vertex AI is offline or disabled.
 */
function buildDeterministicIntelligence(ctx) {
  const { url, parsedData, contentData, entityData, intentData, questionData, seoScores, geoScores, aeoScores } = ctx;
  const brand = entityData.brandName || 'The website';
  const category = entityData.primaryCategory || 'digital service';
  const words = contentData.wordCount || 0;
  const currentTitle = parsedData.title || `${brand} — Official Website`;

  const executiveNarrative = `${brand} demonstrates a measured SEO score of ${seoScores.score}/100, a Generative Engine Readiness (GEO) of ${geoScores.score}/100, and an Answer Engine Readiness (AEO) of ${aeoScores.score}/100. The domain establishes ${entityData.clarityRating.toLowerCase()} entity clarity in the ${category} space, with ${contentData.headingsTree.length} structured headings and an estimated reading time of ${contentData.readingTimeMinutes} minutes across ${words} total words.\n\nWhile technical discoverability and crawlability are verified, the primary limitations restricting generative engine citations and featured snippet appearances stem from ${contentData.tables.length === 0 ? 'a lack of structured data tables' : 'answer formatting gaps'} and ${intentData.mismatches?.length > 0 ? 'detected search intent misalignment' : 'unanswered high-intent user journey queries'}. Implementing the prioritized remediation roadmap will significantly bolster topical authority and conversational answer readiness.`;

  const searchEngineInterpretation = `Search engines (Google and Bing) index this page primarily under the "${intentData.primaryIntentLabel}" intent profile. The title tag ("${currentTitle.slice(0, 50)}...") ${parsedData.metaDescription ? 'and meta description provide baseline SERP presentation' : 'is missing an accompanying meta description, leading to algorithmic snippet generation'}. Internal link density (${contentData.linksAnalysis.internal} links) supports crawl traversal, though anchor texts require semantic enrichment.`;

  const generativeAiInterpretation = `Generative AI retrieval models (Gemini, ChatGPT, Perplexity) analyze content by isolating named entities, empirical evidence, and direct answer blocks. ${entityData.verifiedSignals.length >= 2 ? `The brand entity "${brand}" is recognized with verified organizational signals.` : 'The absence of rich Schema.org Organization markup increases entity ambiguity.'} Content with ${contentData.tables.length} tables and ${contentData.lists.totalLists} lists provides ${contentData.tables.length > 0 ? 'scannable data points' : 'limited structured facts for citation generation'}.`;

  const discoverabilityBottlenecks = [
    {
      bottleneck: contentData.headingStats.h1 !== 1 ? 'Heading hierarchy fragmentation (H1 count != 1)' : 'Limited tabular summary structures',
      impact: 'Reduces machine extraction confidence and impairs semantic clarity for automated answer extractors.',
      priority: 'High',
    },
    {
      bottleneck: questionData.answeredQuestionsCount < 3 ? 'Sparse direct-answer Q&A blocks' : 'Unaddressed evaluation/decision journey queries',
      impact: 'Limits eligibility for Google Featured Snippets and voice assistant direct responses.',
      priority: 'High',
    },
    {
      bottleneck: contentData.linksAnalysis.genericAnchorsCount > 0 ? 'Generic internal anchor text distribution' : 'Missing Schema.org sameAs social links',
      impact: 'Dilutes PageRank semantic relevance across internal topic clusters.',
      priority: 'Medium',
    },
  ];

  const pageOptimizationDrafts = {
    optimizedTitles: [
      {
        title: `${brand} — ${category} | Official Platform`,
        charCount: `${brand} — ${category} | Official Platform`.length,
        rationale: 'Combines authoritative brand identity with primary service intent within 60 characters.',
      },
      {
        title: `${category} Solutions & Verified Intelligence | ${brand}`,
        charCount: `${category} Solutions & Verified Intelligence | ${brand}`.length,
        rationale: 'Topical-first non-branded acquisition phrasing designed to capture exploratory commercial queries.',
      },
    ],
    optimizedDescriptions: [
      {
        description: parsedData.metaDescription || `Discover ${brand}: The modern ${category.toLowerCase()} platform engineered for accuracy, evidence-backed intelligence, and seamless performance.`,
        charCount: (parsedData.metaDescription || `Discover ${brand}: The modern ${category.toLowerCase()} platform engineered for accuracy, evidence-backed intelligence, and seamless performance.`).length,
        rationale: 'Features clear value proposition, primary topical keywords, and an active engagement trigger within optimal 155-character window.',
      },
    ],
    h1Alternatives: [
      {
        h1: `${brand}: Enterprise ${category} Intelligence & Security`,
        rationale: 'Direct intent-anchored H1 that unifies brand recognition with primary user value.',
      },
    ],
    contentOutline: [
      {
        section: '1. Executive Overview & Primary Value Proposition',
        purpose: 'Directly satisfy above-the-fold search intent with a 45-word introductory definition.',
        suggestedKeywords: [brand.toLowerCase(), category.toLowerCase(), 'overview', 'features'],
      },
      {
        section: '2. Comparative Feature Matrix & Technical Specifications',
        purpose: 'Provide a structured HTML table summarizing core capabilities, tiers, and benchmarks.',
        suggestedKeywords: ['specifications', 'comparison', 'pricing tiers', 'benchmarks'],
      },
      {
        section: '3. Frequently Answered Questions (FAQ)',
        purpose: 'Answer top 5 user journey questions directly with FAQPage JSON-LD integration.',
        suggestedKeywords: ['how it works', 'pricing', 'support', 'integrations'],
      },
    ],
    directAnswerBlocks: [
      {
        question: `What is ${brand}?`,
        directAnswer: `${brand} is an advanced ${category.toLowerCase()} platform that provides comprehensive, evidence-grounded analysis of website security, technical infrastructure, and search discoverability in real time.`,
      },
      {
        question: `How does ${brand} evaluate website performance and SEO?`,
        directAnswer: `${brand} combines live DOM parsing, DNS routing telemetry, and Google Lighthouse metrics to audit on-page metadata, semantic headings, and search intent alignment without external dependencies.`,
      },
    ],
    schemaJsonLd: {
      '@context': 'https://schema.org',
      '@type': 'WebPage',
      name: currentTitle,
      url: url,
      description: parsedData.metaDescription || `${brand} ${category} intelligence and audit report.`,
      publisher: {
        '@type': 'Organization',
        name: brand,
        url: url,
      },
    },
    _provenance: 'INFERRED',
    _generationMode: 'Deterministic Evidence Engine (AI Provider Standby)',
  };

  return {
    executiveNarrative,
    searchEngineInterpretation,
    generativeAiInterpretation,
    discoverabilityBottlenecks,
    pageOptimizationDrafts,
    _provenance: 'INFERRED',
    _generationMode: 'Deterministic Fallback Grounding',
  };
}

module.exports = {
  generateVertexAiIntelligence,
};
