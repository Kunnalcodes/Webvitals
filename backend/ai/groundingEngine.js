/**
 * AI Grounding Engine & Context Builder — Phase 4
 * WebVitals
 *
 * Enforces strict grounding firewalls:
 *   - Whitelists only verified Phase 3 scan fields
 *   - Applies deep redaction via redactionEngine
 *   - Wraps target-controlled text in untrusted data boundaries
 *   - Ensures AI context cannot be manipulated to invent facts or modify scores
 */

'use strict';

const { redactObject } = require('./redactionEngine');

const UNTRUSTED_BOUNDARY_OPEN  = '<<<UNTRUSTED_TARGET_DATA_START>>>';
const UNTRUSTED_BOUNDARY_CLOSE = '<<<UNTRUSTED_TARGET_DATA_END>>>';

/**
 * Builds a sanitized, grounded AI context from a completed Phase 3 scan report.
 *
 * @param {object} scanReport - Canonical Phase 3 scan report from scanRepository
 * @returns {object} Grounded AI Context
 */
function buildGroundedContext(scanReport) {
  if (!scanReport) return null;

  // 1. Whitelist top-level scan metadata
  const target = {
    requestedUrl: scanReport.requestedUrl || null,
    finalUrl:     scanReport.finalUrl || null,
    hostname:     scanReport.hostname || null,
    https:        Boolean(scanReport.https),
    httpStatus:   scanReport.httpStatus ?? null,
    redirects:    scanReport.redirects ?? 0,
  };

  const score = {
    value:          scanReport.score ?? 0,
    grade:          scanReport.grade ?? 'F',
    gradeLabel:     scanReport.gradeLabel || '',
    classification: scanReport.classification || '',
  };

  const scanMetadata = {
    scanId:         scanReport.scanId,
    scannerVersion: scanReport.scannerVersion || '3.0.0',
    startedAt:      scanReport.startedAt || scanReport.timestamp,
    completedAt:    scanReport.completedAt || scanReport.timestamp,
    scanTimeMs:     scanReport.scanTimeMs || 0,
  };

  // 2. Whitelist and sanitize findings
  const findings = (scanReport.findings || []).map((f) => {
    const evArray = Array.isArray(f.evidence)
      ? f.evidence
      : (f.evidence && typeof f.evidence === 'object' ? [f.evidence] : []);

    return {
      id:             f.id,
      channel:        f.channel || f.category,
      title:          f.title,
      status:         f.status || 'FAIL', // PASS | FAIL | WARNING | NOT_EVALUATED
      severity:       f.severity || 'MEDIUM', // CRITICAL | HIGH | MEDIUM | LOW | INFO
      confidence:     f.confidence ?? 1.0,
      scoreImpact:    f.scoreImpact ?? 0,
      description:    f.description || '',
      impact:         f.impact || null,
      recommendation: f.recommendation || null,
      limitations:    f.limitations || [],
      evidenceCount:  evArray.length,
      evidenceSummary: evArray.map((ev) => ({
        source: ev.source || 'telemetry',
        quality: ev.quality || 'VERIFIED',
        signature: ev.signature || null,
        confidence: ev.confidence ?? 1.0,
        notes: ev.notes || (ev.description ? [ev.description] : []),
        observedValue: ev.observedValue !== undefined ? redactObject(ev.observedValue) : null,
      })),
    };
  });

  // 3. Whitelist detected technologies
  const techList = Array.isArray(scanReport.technologies)
    ? scanReport.technologies
    : (Array.isArray(scanReport.techStack) ? scanReport.techStack : []);

  const technologies = techList.map((t) => ({
    name:       t.name || t,
    category:   t.category || 'framework',
    confidence: t.confidence ?? 1.0,
    evidence:   t.evidence || null,
  }));

  // 4. Sanitize whole structure
  const rawContext = {
    target,
    score,
    scanMetadata,
    findings,
    technologies,
    limitations: scanReport.limitations || [],
  };

  return redactObject(rawContext);
}

/**
 * Builds grounded context scoped to a single specific finding.
 *
 * @param {object} scanReport
 * @param {string} findingId
 * @returns {object|null}
 */
function buildFindingContext(scanReport, findingId) {
  const fullContext = buildGroundedContext(scanReport);
  if (!fullContext) return null;

  const targetFinding = fullContext.findings.find((f) => f.id === findingId);
  if (!targetFinding) return null;

  return {
    target: fullContext.target,
    score: fullContext.score,
    scanMetadata: fullContext.scanMetadata,
    finding: targetFinding,
    detectedTechnologies: fullContext.technologies,
    otherFindingsOverview: fullContext.findings.map((f) => ({ id: f.id, channel: f.channel, status: f.status, severity: f.severity })),
    limitations: fullContext.limitations,
  };
}

/**
 * Wraps untrusted target content (e.g. HTML snippet or reflected strings)
 * in protective boundaries for the prompt.
 *
 * @param {string} content
 * @returns {string}
 */
function wrapUntrustedData(content) {
  if (!content || typeof content !== 'string') return '';
  return `${UNTRUSTED_BOUNDARY_OPEN}\n${content}\n${UNTRUSTED_BOUNDARY_CLOSE}`;
}

module.exports = {
  buildGroundedContext,
  buildFindingContext,
  wrapUntrustedData,
  UNTRUSTED_BOUNDARY_OPEN,
  UNTRUSTED_BOUNDARY_CLOSE,
};
