/**
 * Standard Result Schema Specification — WebVitals
 *
 * Every check executed by any worker MUST conform to this exact contract.
 */

'use strict';

/**
 * Valid values for check properties
 */
const CHECK_CATEGORIES = ['network', 'security', 'domain', 'content', 'performance', 'email'];
const CHECK_STATUSES   = ['pass', 'finding', 'info', 'unknown', 'skipped', 'error'];
const CHECK_SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational', 'none'];

/**
 * Creates a standardized check result object.
 *
 * @param {Object} params
 * @param {string} params.checkId - e.g. "security.hsts", "network.dns.a"
 * @param {string} params.category - "network" | "security" | "domain" | "content" | "performance" | "email"
 * @param {string} params.title - Human-readable check title
 * @param {string} params.status - "pass" | "finding" | "info" | "unknown" | "skipped" | "error"
 * @param {string} [params.severity="none"] - "critical" | "high" | "medium" | "low" | "informational" | "none"
 * @param {number} [params.confidence=1.0] - Float 0.0 to 1.0
 * @param {string} [params.summary=""] - Concise verdict
 * @param {string} [params.details=""] - Thorough diagnostic context
 * @param {Object} [params.evidence={}] - Raw inspectable evidence (headers, records, handshakes)
 * @param {string} [params.recommendation=""] - Actionable fix instructions
 * @param {string[]} [params.references=[]] - NIST, RFC, OWASP, MDN links
 * @param {string} [params.source="native"] - Origin of signal (e.g. "authoritative-dns", "tls-handshake")
 * @param {string} [params.timestamp] - ISO date string
 * @param {number} [params.durationMs=0] - Check execution time in milliseconds
 * @returns {Object}
 */
function createCheckResult({
  checkId,
  category,
  title,
  status = 'unknown',
  severity = 'none',
  confidence = 1.0,
  summary = '',
  details = '',
  evidence = {},
  recommendation = '',
  references = [],
  source = 'native',
  timestamp,
  durationMs = 0,
}) {
  const normCategory = CHECK_CATEGORIES.includes(category) ? category : 'security';
  const normStatus = CHECK_STATUSES.includes(status) ? status : 'unknown';
  const normSeverity = CHECK_SEVERITIES.includes(severity) ? severity : (normStatus === 'pass' ? 'none' : 'low');
  const normConfidence = Math.max(0.0, Math.min(1.0, typeof confidence === 'number' ? confidence : 1.0));

  return {
    checkId: String(checkId || 'unknown.check'),
    category: normCategory,
    title: String(title || 'Check Result'),
    status: normStatus,
    severity: normSeverity,
    confidence: normConfidence,
    summary: String(summary || ''),
    details: String(details || ''),
    evidence: typeof evidence === 'object' && evidence !== null ? evidence : { raw: String(evidence) },
    recommendation: String(recommendation || ''),
    references: Array.isArray(references) ? references : [],
    source: String(source || 'native'),
    timestamp: timestamp || new Date().toISOString(),
    durationMs: Math.max(0, Math.round(durationMs || 0)),
  };
}

module.exports = {
  createCheckResult,
  CHECK_CATEGORIES,
  CHECK_STATUSES,
  CHECK_SEVERITIES,
};
