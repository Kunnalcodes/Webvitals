/**
 * AI Response Validator — Phase 4
 * WebVitals
 *
 * Validates structured JSON responses from LLM outputs against required schemas.
 * Rejects malformed or hallucinated responses and triggers fallback.
 */

'use strict';

function cleanJsonString(str) {
  if (typeof str !== 'string') return str;
  let cleaned = str.trim();
  if (cleaned.startsWith('```json')) {
    cleaned = cleaned.slice(7);
  } else if (cleaned.startsWith('```')) {
    cleaned = cleaned.slice(3);
  }
  if (cleaned.endsWith('```')) {
    cleaned = cleaned.slice(0, -3);
  }
  return cleaned.trim();
}

/**
 * Validates and normalizes an AI-generated finding explanation.
 *
 * @param {string|object} rawResponse
 * @param {string} expectedFindingId
 * @returns {{ valid: boolean, data?: object, error?: string }}
 */
function validateExplanationResponse(rawResponse, expectedFindingId) {
  let parsed;
  try {
    const cleaned = typeof rawResponse === 'string' ? cleanJsonString(rawResponse) : rawResponse;
    parsed = typeof cleaned === 'string' ? JSON.parse(cleaned) : cleaned;
  } catch (err) {
    return { valid: false, error: `Invalid JSON output: ${err.message}` };
  }

  if (!parsed || typeof parsed !== 'object') {
    return { valid: false, error: 'Output is not an object' };
  }

  if (parsed.findingId && parsed.findingId !== expectedFindingId) {
    return { valid: false, error: `Finding ID mismatch: expected ${expectedFindingId}, got ${parsed.findingId}` };
  }

  // Ensure required fields exist
  const requiredFields = ['summary', 'whyItMatters', 'attackScenario', 'whatThisProves', 'remediationGuidance'];
  for (const field of requiredFields) {
    if (!parsed[field] || typeof parsed[field] !== 'string') {
      return { valid: false, error: `Missing or invalid required field: ${field}` };
    }
  }

  return {
    valid: true,
    data: {
      findingId: expectedFindingId,
      audience: parsed.audience || 'developer',
      title: parsed.title || '',
      summary: parsed.summary,
      whyItMatters: parsed.whyItMatters,
      attackScenario: parsed.attackScenario,
      whatThisProves: parsed.whatThisProves,
      whatThisDoesNotProve: parsed.whatThisDoesNotProve || 'Remote observation cannot determine internal application state or unindexed endpoints.',
      remediationGuidance: parsed.remediationGuidance,
      validationSteps: parsed.validationSteps || 'Verify response headers using: curl -I <url>',
      limitations: Array.isArray(parsed.limitations) ? parsed.limitations : [],
      isAiGenerated: true,
    },
  };
}

/**
 * Validates and normalizes an AI-generated executive summary.
 *
 * @param {string|object} rawResponse
 * @param {object} groundedContext
 * @returns {{ valid: boolean, data?: object, error?: string }}
 */
function validateExecutiveSummaryResponse(rawResponse, groundedContext) {
  let parsed;
  try {
    const cleaned = typeof rawResponse === 'string' ? cleanJsonString(rawResponse) : rawResponse;
    parsed = typeof cleaned === 'string' ? JSON.parse(cleaned) : cleaned;
  } catch (err) {
    return { valid: false, error: `Invalid JSON output: ${err.message}` };
  }

  if (!parsed || typeof parsed !== 'object') {
    return { valid: false, error: 'Output is not an object' };
  }

  if (!parsed.postureHeadline || !parsed.executiveNarrative) {
    return { valid: false, error: 'Missing postureHeadline or executiveNarrative' };
  }

  return {
    valid: true,
    data: {
      target: groundedContext.target.hostname,
      overallScore: groundedContext.score.value,
      grade: groundedContext.score.grade,
      gradeLabel: groundedContext.score.gradeLabel,
      postureHeadline: parsed.postureHeadline,
      executiveNarrative: parsed.executiveNarrative,
      topPriorityActions: Array.isArray(parsed.topPriorityActions) ? parsed.topPriorityActions : [],
      quickWins: Array.isArray(parsed.quickWins) ? parsed.quickWins : [],
      strategicRecommendations: Array.isArray(parsed.strategicRecommendations) ? parsed.strategicRecommendations : [],
      limitations: groundedContext.limitations || [],
      isAiGenerated: true,
    },
  };
}

module.exports = {
  validateExplanationResponse,
  validateExecutiveSummaryResponse,
};
