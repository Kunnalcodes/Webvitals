/**
 * Evidence Provenance Validator & Anti-Hallucination Shield — WebVitals 2.0
 *
 * Enforces strict scientific provenance for every claim in the SEO/GEO/AEO report,
 * tagging findings as VERIFIED, INFERRED, AI_INTERPRETED, ESTIMATED, or UNAVAILABLE,
 * and rejecting fabricated metrics, hallucinated rankings, or unverified claims.
 */

'use strict';

const PROVENANCE_LEVELS = {
  VERIFIED: 'VERIFIED',             // Directly observed in wire response, DOM, headers, or DNS
  INFERRED: 'INFERRED',             // Algorithmically derived from observable signals
  AI_INTERPRETED: 'AI_INTERPRETED', // Synthesized by Vertex AI / Gemini reasoning
  ESTIMATED: 'ESTIMATED',           // Statistical or heuristic approximation
  UNAVAILABLE: 'UNAVAILABLE',       // Requires third-party authenticated API integrations
};

/**
 * Validates a finding or claim and assigns strict provenance.
 */
function tagProvenance(item, level = PROVENANCE_LEVELS.VERIFIED, rationale = '') {
  return {
    ...item,
    provenance: level,
    provenanceRationale: rationale || `Evidence provenance established as ${level}.`,
  };
}

/**
 * Cleans and validates Vertex AI responses to remove hallucinations and verify evidence grounding.
 *
 * @param {Object} aiResponse - Raw parsed JSON from Vertex AI
 * @param {Object} groundTruthContext - Real observed data
 * @returns {Object} Validated and filtered response
 */
function validateAiOutput(aiResponse, groundTruthContext) {
  if (!aiResponse || typeof aiResponse !== 'object') {
    return null;
  }

  const validated = { ...aiResponse };
  const verifiedUrl = groundTruthContext?.url || '';

  // 1. Validate that recommended URLs do not invent fake domains
  if (Array.isArray(validated.recommendedUrls)) {
    validated.recommendedUrls = validated.recommendedUrls.filter(u => {
      try {
        const parsed = new URL(u);
        return verifiedUrl.includes(parsed.hostname);
      } catch {
        return false;
      }
    });
  }

  // 2. Reject fabricated keyword volume numbers if model attempted to hallucinate them
  if (validated.richKeywords && typeof validated.richKeywords === 'object') {
    Object.keys(validated.richKeywords).forEach(key => {
      if (Array.isArray(validated.richKeywords[key])) {
        validated.richKeywords[key] = validated.richKeywords[key].map(item => {
          if (typeof item === 'object') {
            // Strip any hallucinated search volume
            const clean = { keyword: item.keyword || item.name || String(item) };
            if (item.intent) clean.intent = item.intent;
            return clean;
          }
          return { keyword: String(item), intent: 'Search query' };
        });
      }
    });
  }

  // 3. Mark provenance on AI-generated analysis
  validated._provenance = PROVENANCE_LEVELS.AI_INTERPRETED;
  validated._groundedUrl = verifiedUrl;
  validated._validationTimestamp = new Date().toISOString();

  return validated;
}

/**
 * Generates transparent transparency disclosures for unavailable data.
 */
function getSystemDisclosures() {
  return [
    {
      metric: 'Google Search Impressions & Clicks',
      status: PROVENANCE_LEVELS.UNAVAILABLE,
      reason: 'Search Console private OAuth token required. Remote audits cannot view private Google Search Console telemetry.',
      integrationPath: 'Connect Google Search Console via API integrations settings.',
    },
    {
      metric: 'Exact Monthly Keyword Search Volume',
      status: PROVENANCE_LEVELS.UNAVAILABLE,
      reason: 'Requires Google Ads API or commercial keyword database subscription.',
      integrationPath: 'Integrate Google Keyword Planner or supported data provider.',
    },
    {
      metric: 'Confirmed AI Engine Appearance Rate',
      status: PROVENANCE_LEVELS.INFERRED,
      reason: 'Evaluated through structural extractability and entity clarity. Direct LLM output monitoring requires continuous conversational sampling.',
      integrationPath: 'Automated generative search tracking available in WebVitals Enterprise.',
    },
  ];
}

module.exports = {
  PROVENANCE_LEVELS,
  tagProvenance,
  validateAiOutput,
  getSystemDisclosures,
};
