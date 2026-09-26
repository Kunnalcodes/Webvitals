/**
 * AI Service & Intelligence Coordinator — Phase 4
 * WebVitals
 *
 * Coordinates grounded AI explanations, executive briefings, remediation playbooks,
 * and scan-scoped interactive security chat with robust offline fallbacks.
 */

'use strict';

const { defaultAiProvider } = require('./aiClient');
const { buildGroundedContext, buildFindingContext } = require('./groundingEngine');
const { buildExplainPrompt, buildExecutiveSummaryPrompt, buildChatPrompt, AI_PROMPT_VERSION } = require('./promptBuilder');
const { validateExplanationResponse, validateExecutiveSummaryResponse } = require('./responseValidator');
const { resolveRemediation } = require('../remediation/remediationEngine');
const { generateDeterministicExecutiveSummary } = require('../executive/executiveSummaryEngine');
const { scanRepository } = require('../storage/scanRepository');

// Cache: key -> { data, timestamp }
const _explanationCache = new Map();

// Chat sessions: conversationId -> { scanId, messages: [], updatedAt }
const _chatSessions = new Map();
const MAX_CHAT_MESSAGES = 20;
const MAX_MESSAGE_LENGTH = 1000;

/**
 * Explains a specific finding with grounded AI or deterministic fallback.
 *
 * @param {string} scanId
 * @param {string} findingId
 * @param {'developer'|'executive'} [audience='developer']
 * @returns {Promise<object>}
 */
async function explainFinding(scanId, findingId, audience = 'developer') {
  const scanReport = scanRepository.getScan(scanId);
  if (!scanReport) {
    const err = new Error(`Scan not found: ${scanId}`);
    err.code = 'SCAN_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }

  const findingContext = buildFindingContext(scanReport, findingId);
  if (!findingContext) {
    const err = new Error(`Finding '${findingId}' not found in scan ${scanId}`);
    err.code = 'FINDING_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }

  // Check cache
  const cacheKey = `${scanId}:${findingId}:${audience}:${AI_PROMPT_VERSION}`;
  if (_explanationCache.has(cacheKey)) {
    return _explanationCache.get(cacheKey);
  }

  // If AI is available, attempt grounded generation
  if (defaultAiProvider.isAvailable()) {
    try {
      const { systemInstruction, userPrompt } = buildExplainPrompt(findingContext, audience);
      const rawResponse = await defaultAiProvider.generateText(systemInstruction, userPrompt, { jsonMode: true });
      const validation = validateExplanationResponse(rawResponse, findingId);

      if (validation.valid) {
        _explanationCache.set(cacheKey, validation.data);
        return validation.data;
      } else {
        console.warn(`[AIService] Validation failed for finding ${findingId}:`, validation.error);
      }
    } catch (aiErr) {
      console.warn(`[AIService] AI generation error for finding ${findingId}:`, aiErr.message);
    }
  }

  // Deterministic Fallback
  const deterministicExplanation = {
    findingId: findingContext.finding.id,
    audience,
    title: findingContext.finding.title,
    summary: findingContext.finding.description,
    whyItMatters: findingContext.finding.impact || `Channel ${findingContext.finding.channel} evaluates defensive security controls.`,
    attackScenario: findingContext.finding.status === 'FAIL' ? 'Without this control, attackers have greater ability to exploit application weaknesses.' : 'Control is active; direct exploitation is mitigated.',
    whatThisProves: `Scanner observed state '${findingContext.finding.status}' with confidence ${findingContext.finding.confidence}.`,
    whatThisDoesNotProve: 'Remote auditing cannot observe internal code or unindexed resources.',
    remediationGuidance: findingContext.finding.recommendation || 'Implement recommended security header or configuration.',
    validationSteps: 'Inspect HTTP response headers with: curl -I <url>',
    limitations: findingContext.finding.limitations || [],
    isAiGenerated: false,
    fallbackReason: defaultAiProvider.isAvailable() ? 'AI response validation failed' : 'AI provider disabled / offline mode',
  };

  _explanationCache.set(cacheKey, deterministicExplanation);
  return deterministicExplanation;
}

/**
 * Generates an executive summary briefing for a scan.
 *
 * @param {string} scanId
 * @returns {Promise<object>}
 */
async function generateExecutiveSummary(scanId) {
  const scanReport = scanRepository.getScan(scanId);
  if (!scanReport) {
    const err = new Error(`Scan not found: ${scanId}`);
    err.code = 'SCAN_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }

  const deterministicSummary = generateDeterministicExecutiveSummary(scanReport);
  const groundedContext = buildGroundedContext(scanReport);

  if (defaultAiProvider.isAvailable() && groundedContext) {
    try {
      const { systemInstruction, userPrompt } = buildExecutiveSummaryPrompt(groundedContext);
      const rawResponse = await defaultAiProvider.generateText(systemInstruction, userPrompt, { jsonMode: true });
      const validation = validateExecutiveSummaryResponse(rawResponse, groundedContext);

      if (validation.valid) {
        return {
          ...deterministicSummary,
          ...validation.data,
          counts: deterministicSummary.counts,
          topPriorityActions: deterministicSummary.topPriorityActions,
          effortVsImpact: deterministicSummary.effortVsImpact,
          isAiGenerated: true,
        };
      }
    } catch (aiErr) {
      console.warn(`[AIService] AI Executive Summary error for scan ${scanId}:`, aiErr.message);
    }
  }

  return deterministicSummary;
}

/**
 * Handles interactive scan-scoped security consultation.
 *
 * @param {string} scanId
 * @param {string} userMessage
 * @param {string} [conversationId]
 * @returns {Promise<object>}
 */
async function chatWithScan(scanId, userMessage, conversationId = null) {
  const scanReport = scanRepository.getScan(scanId);
  if (!scanReport) {
    const err = new Error(`Scan not found: ${scanId}`);
    err.code = 'SCAN_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }

  if (!userMessage || typeof userMessage !== 'string' || userMessage.trim().length === 0) {
    const err = new Error('Message cannot be empty');
    err.code = 'INVALID_INPUT';
    err.statusCode = 400;
    throw err;
  }

  const cleanMessage = userMessage.trim().slice(0, MAX_MESSAGE_LENGTH);
  const convId = conversationId || `conv_${scanId.slice(0, 8)}_${Date.now()}`;

  if (!_chatSessions.has(convId)) {
    _chatSessions.set(convId, {
      conversationId: convId,
      scanId,
      messages: [],
      updatedAt: Date.now(),
    });
  }

  const session = _chatSessions.get(convId);
  // Enforce scan scoping
  if (session.scanId !== scanId) {
    const err = new Error('Conversation is scoped to a different scanId');
    err.code = 'SCAN_SCOPE_MISMATCH';
    err.statusCode = 400;
    throw err;
  }

  const groundedContext = buildGroundedContext(scanReport);

  // If AI is available
  if (defaultAiProvider.isAvailable() && groundedContext) {
    try {
      const { systemInstruction, userPrompt } = buildChatPrompt(groundedContext, session.messages, cleanMessage);
      const aiReply = await defaultAiProvider.generateText(systemInstruction, userPrompt, { jsonMode: false });

      session.messages.push({ role: 'user', text: cleanMessage });
      session.messages.push({ role: 'model', text: aiReply });

      // Prune history
      if (session.messages.length > MAX_CHAT_MESSAGES) {
        session.messages = session.messages.slice(-MAX_CHAT_MESSAGES);
      }
      session.updatedAt = Date.now();

      return {
        conversationId: convId,
        scanId,
        reply: aiReply,
        groundedIn: {
          target: scanReport.hostname,
          score: scanReport.score,
          findingsCount: scanReport.findings?.length || 0,
        },
        isAiGenerated: true,
      };
    } catch (aiErr) {
      console.warn(`[AIService] Chat error for scan ${scanId}:`, aiErr.message);
    }
  }

  // Deterministic Chat Fallback
  const fallbackReply = `**Based on this Scan (${scanReport.hostname})**\n\nWebVitals evaluated ${scanReport.findings?.length || 0} controls with an overall security score of ${scanReport.score}/100 (Grade: ${scanReport.grade}).\n\n*Note: AI assistance is currently operating in offline mode. Please review the specific finding tabs and remediation playbooks in the report for detailed configuration instructions.*`;

  return {
    conversationId: convId,
    scanId,
    reply: fallbackReply,
    groundedIn: {
      target: scanReport.hostname,
      score: scanReport.score,
      findingsCount: scanReport.findings?.length || 0,
    },
    isAiGenerated: false,
  };
}

module.exports = {
  explainFinding,
  generateExecutiveSummary,
  chatWithScan,
  resolveRemediation,
};
