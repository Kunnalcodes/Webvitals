/**
 * Vertex AI / Gemini SEO Meta & Keyword Generator — WebVitals
 * Generates high-CTR meta titles, conversion descriptions, semantic keywords,
 * and JSON-LD schema recommendations for audited pages.
 */

'use strict';

const { defaultAiProvider } = require('../ai/aiClient');

/**
 * Generates AI-optimized SEO assets (Titles, Descriptions, Keywords, Structured Data).
 *
 * @param {object} params
 * @param {string} params.url
 * @param {string} params.title
 * @param {string} params.metaDescription
 * @param {string[]} params.headings
 * @param {string[]} params.keywords
 * @param {object} [params.lighthouseScores]
 * @returns {Promise<object>}
 */
async function generateAiSeoRecommendations({
  url,
  title = '',
  metaDescription = '',
  headings = [],
  keywords = [],
  lighthouseScores = {},
}) {
  const prompt = `You are a world-class SEO Strategist and Technical Growth Architect.
Analyze the following audited web page data and produce high-converting, search-optimized metadata, rich semantic keywords, and structured data recommendations.

TARGET AUDIT DATA:
- URL: ${url}
- Current Title: ${title || '(Missing)'}
- Current Meta Description: ${metaDescription || '(Missing)'}
- Key Headings (H1/H2): ${JSON.stringify(headings.slice(0, 8))}
- Detected Keywords: ${JSON.stringify(keywords.slice(0, 15))}
- Lighthouse Scores: Performance: ${lighthouseScores.performance || 0}/100, SEO: ${lighthouseScores.seo || 0}/100

INSTRUCTIONS:
Return STRICT valid JSON without markdown fences matching the following structure:
{
  "optimizedTitles": [
    { "title": "...", "charCount": 55, "rationale": "High CTR brand + primary keyword placement" },
    { "title": "...", "charCount": 58, "rationale": "Action-oriented intent" },
    { "title": "...", "charCount": 52, "rationale": "Authoritative search focus" }
  ],
  "optimizedDescriptions": [
    { "description": "...", "charCount": 155, "rationale": "Includes primary CTA and core value proposition" },
    { "description": "...", "charCount": 158, "rationale": "Problem-solution hook with semantic keywords" }
  ],
  "richKeywords": {
    "primaryKeywords": ["...", "..."],
    "secondaryKeywords": ["...", "..."],
    "longTailKeywords": ["...", "..."],
    "lsiSemanticKeywords": ["...", "..."]
  },
  "contentActionItems": [
    "...",
    "..."
  ],
  "schemaJsonLd": {
    "@context": "https://schema.org",
    "@type": "WebSite",
    "name": "...",
    "url": "${url}",
    "description": "..."
  }
}`;

  try {
    const rawResponse = await defaultAiProvider.generateText(
      'You are an expert search engine optimization (SEO) architect and metadata optimizer. Always output valid JSON only.',
      prompt,
      { temperature: 0.2, maxOutputTokens: 2048 }
    );

    const cleaned = (rawResponse || '')
      .replace(/^```json\s*/i, '')
      .replace(/^```\s*/i, '')
      .replace(/```\s*$/i, '')
      .trim();

    return JSON.parse(cleaned);
  } catch (err) {
    // Graceful fallback if AI is offline
    const baseDomain = url.replace(/^https?:\/\//i, '').split('/')[0];
    return {
      optimizedTitles: [
        {
          title: title ? `${title} | Verified Security & Performance` : `${baseDomain} — Official Website`,
          charCount: (title ? `${title} | Verified Security & Performance` : `${baseDomain} — Official Website`).length,
          rationale: 'Clean brand authority with primary service identifier',
        },
      ],
      optimizedDescriptions: [
        {
          description: metaDescription || `Discover the verified platform for ${baseDomain}. Fast, secure, and optimized for modern web performance standards.`,
          charCount: 120,
          rationale: 'Baseline descriptive summary with core value hook',
        },
      ],
      richKeywords: {
        primaryKeywords: keywords.slice(0, 5),
        secondaryKeywords: keywords.slice(5, 10),
        longTailKeywords: [`${baseDomain} security audit`, `${baseDomain} online review`],
        lsiSemanticKeywords: ['web security', 'core web vitals', 'ssl encryption', 'seo optimization'],
      },
      contentActionItems: [
        'Ensure the primary H1 tag accurately matches the target search query.',
        'Add descriptive alt text to all visual assets to improve image search indexation.',
      ],
      schemaJsonLd: {
        '@context': 'https://schema.org',
        '@type': 'WebSite',
        name: baseDomain,
        url: url,
        description: metaDescription || 'Official website',
      },
      isAiFallback: true,
    };
  }
}

module.exports = {
  generateAiSeoRecommendations,
};
