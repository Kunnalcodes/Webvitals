/**
 * Security Evidence & Finding Models — Phase 3
 * WebVitals
 *
 * Canonical schema definitions for raw evidence, findings, confidence, and determination states.
 */

'use strict';

const crypto = require('crypto');

/**
 * Determination States
 * @enum {string}
 */
const DETERMINATION = {
  PASS: 'PASS',
  FAIL: 'FAIL',
  WARNING: 'WARNING',
  NOT_EVALUATED: 'NOT_EVALUATED',
};

/**
 * Finding Severity Levels
 * @enum {string}
 */
const SEVERITY = {
  INFO: 'INFO',
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
};

/**
 * Evidence Sources
 * @enum {string}
 */
const EVIDENCE_SOURCE = {
  HTTP: 'HTTP',
  HTTPS: 'HTTPS',
  TLS: 'TLS',
  DNS: 'DNS',
  HTML: 'HTML',
  COOKIE: 'COOKIE',
  CORS: 'CORS',
  PROBE: 'PROBE',
  HEURISTIC: 'HEURISTIC',
  EXTERNAL: 'EXTERNAL',
};

/**
 * Evidence Quality Classification
 * @enum {string}
 */
const EVIDENCE_QUALITY = {
  DIRECT: 'DIRECT',               // Directly observed response header / network telemetry
  CORROBORATED: 'CORROBORATED',   // Multiple independent signals verify the finding
  HEURISTIC: 'HEURISTIC',         // Inferred based on structural patterns or scoring rules
  INSUFFICIENT: 'INSUFFICIENT',   // Inconclusive observation, yields NOT_EVALUATED
};

/**
 * Creates a normalized SecurityEvidence object.
 *
 * @param {object} params
 * @param {string} params.source - Member of EVIDENCE_SOURCE
 * @param {string} [params.quality] - Member of EVIDENCE_QUALITY
 * @param {object} [params.request] - { method, url, headers }
 * @param {object} [params.response] - { status, headers, contentType, contentLength, bodyHash }
 * @param {*} [params.observedValue] - Raw observed data
 * @param {*} [params.normalizedValue] - Cleaned/decomposed representation
 * @param {string} [params.signature] - Matched signature ID if any
 * @param {number} [params.confidence] - Value between 0.0 and 1.0
 * @param {string[]} [params.notes] - Additional audit notes
 * @returns {object}
 */
function createEvidence({
  source,
  quality = EVIDENCE_QUALITY.DIRECT,
  request = null,
  response = null,
  observedValue = null,
  normalizedValue = null,
  signature = null,
  confidence = 1.0,
  notes = [],
}) {
  return {
    id: `ev_${crypto.randomBytes(6).toString('hex')}`,
    source,
    quality,
    collectedAt: new Date().toISOString(),
    request: request ? {
      method: request.method || 'GET',
      url: request.url || null,
      headers: request.headers || null,
    } : null,
    response: response ? {
      status: response.status ?? null,
      headers: response.headers ?? null,
      contentType: response.contentType ?? null,
      contentLength: response.contentLength ?? null,
      bodyHash: response.bodyHash ?? null,
    } : null,
    observedValue,
    normalizedValue,
    signature,
    confidence: Math.max(0, Math.min(1, typeof confidence === 'number' ? confidence : 1.0)),
    notes: Array.isArray(notes) ? notes : [],
  };
}

/**
 * Creates a structured SecurityFinding object.
 *
 * @param {object} params
 * @param {string} params.id - Unique finding identifier (e.g. 'HSTS_MISSING', 'CORS_WILDCARD_CREDENTIALS')
 * @param {string} params.channel - Security channel (e.g. 'HTTPS', 'TLS', 'HSTS', 'CSP', 'COOKIES', 'CORS', 'DNS', 'SENSITIVE_FILES', 'PHISHING')
 * @param {string} params.title - Clear, human-readable finding title
 * @param {string} params.status - DETERMINATION (PASS, FAIL, WARNING, NOT_EVALUATED)
 * @param {string} params.severity - SEVERITY (INFO, LOW, MEDIUM, HIGH, CRITICAL)
 * @param {number} params.confidence - Confidence score 0.0 - 1.0
 * @param {number} [params.scoreImpact] - Exact points deducted or awarded
 * @param {string} params.description - Technical breakdown of finding
 * @param {string} [params.impact] - Risk to application / users
 * @param {Array} [params.evidence] - Array of supporting SecurityEvidence items
 * @param {string} [params.recommendation] - Exact remediation instruction
 * @param {string[]} [params.limitations] - Explicit bounds or unknowns
 * @returns {object}
 */
function createFinding({
  id,
  channel,
  title,
  status = DETERMINATION.NOT_EVALUATED,
  severity = SEVERITY.INFO,
  confidence = 1.0,
  scoreImpact = 0,
  description = '',
  impact = '',
  evidence = [],
  recommendation = '',
  limitations = [],
}) {
  return {
    id,
    channel,
    title,
    status,
    severity,
    confidence: Math.max(0, Math.min(1, typeof confidence === 'number' ? confidence : 1.0)),
    scoreImpact: typeof scoreImpact === 'number' ? scoreImpact : 0,
    description,
    impact,
    evidence: Array.isArray(evidence) ? evidence : [],
    recommendation,
    limitations: Array.isArray(limitations) ? limitations : [],
    detectedAt: new Date().toISOString(),
  };
}

module.exports = {
  DETERMINATION,
  SEVERITY,
  EVIDENCE_SOURCE,
  EVIDENCE_QUALITY,
  createEvidence,
  createFinding,
};
