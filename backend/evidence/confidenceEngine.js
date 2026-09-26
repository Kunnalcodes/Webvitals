/**
 * Confidence Engine — Phase 3
 * WebVitals
 *
 * Calculates mathematically bounded confidence scores (0.0 to 1.0)
 * grounded in evidence quality, corroborating signals, and source reliability.
 */

'use strict';

const { EVIDENCE_QUALITY, EVIDENCE_SOURCE } = require('./evidenceModel');

// Baseline reliability weighting per evidence source
const SOURCE_WEIGHTS = {
  [EVIDENCE_SOURCE.HTTP]: 0.95,
  [EVIDENCE_SOURCE.HTTPS]: 0.95,
  [EVIDENCE_SOURCE.TLS]: 0.98,
  [EVIDENCE_SOURCE.DNS]: 0.95,
  [EVIDENCE_SOURCE.COOKIE]: 0.92,
  [EVIDENCE_SOURCE.CORS]: 0.90,
  [EVIDENCE_SOURCE.PROBE]: 0.88,
  [EVIDENCE_SOURCE.HTML]: 0.80,
  [EVIDENCE_SOURCE.HEURISTIC]: 0.65,
  [EVIDENCE_SOURCE.EXTERNAL]: 0.75,
};

// Quality multiplier
const QUALITY_MULTIPLIERS = {
  [EVIDENCE_QUALITY.DIRECT]: 1.0,
  [EVIDENCE_QUALITY.CORROBORATED]: 1.0,
  [EVIDENCE_QUALITY.HEURISTIC]: 0.75,
  [EVIDENCE_QUALITY.INSUFFICIENT]: 0.30,
};

/**
 * Computes an overall confidence score from a list of SecurityEvidence objects.
 *
 * @param {import('./evidenceModel').SecurityEvidence[]} evidenceList
 * @param {object} [options]
 * @param {number} [options.corroborationBonus=0.05]
 * @param {number} [options.baseMin=0.20]
 * @returns {number} Value between 0.00 and 1.00 rounded to 2 decimal places
 */
function computeConfidence(evidenceList = [], options = {}) {
  if (!Array.isArray(evidenceList) || evidenceList.length === 0) {
    return 0.0;
  }

  const { corroborationBonus = 0.05, baseMin = 0.20 } = options;

  let weightedSum = 0;
  let totalWeights = 0;
  const distinctSources = new Set();

  for (const ev of evidenceList) {
    const srcWeight = SOURCE_WEIGHTS[ev.source] || 0.70;
    const qMultiplier = QUALITY_MULTIPLIERS[ev.quality] || 0.70;
    const itemConfidence = typeof ev.confidence === 'number' ? ev.confidence : 1.0;

    const effectiveWeight = srcWeight * qMultiplier;
    weightedSum += itemConfidence * effectiveWeight;
    totalWeights += effectiveWeight;

    if (ev.source) distinctSources.add(ev.source);
  }

  let baseConfidence = totalWeights > 0 ? (weightedSum / totalWeights) : baseMin;

  // Corroboration bonus for multiple distinct sources confirming same finding
  if (distinctSources.size > 1) {
    baseConfidence += (distinctSources.size - 1) * corroborationBonus;
  }

  // Bound to [0.0, 1.0]
  const finalScore = Math.max(0.0, Math.min(1.0, baseConfidence));
  return Math.round(finalScore * 100) / 100;
}

module.exports = {
  computeConfidence,
  SOURCE_WEIGHTS,
  QUALITY_MULTIPLIERS,
};
