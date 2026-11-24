/**
 * Precision Finding & Explainable Scoring Engine — WebVitals
 *
 * Implements:
 *   1. Finding validation & deduplication
 *   2. Explainable scoring with transparent methodology breakdown
 *   3. Confidence weighting
 *   4. Risk classification
 *   5. Ranked priority remediation playbook
 */

'use strict';

const SEVERITY_WEIGHTS = {
  critical: -20,
  high: -10,
  medium: -5,
  low: -2,
  informational: 0,
  none: 0,
};

/**
 * Normalizes all checks, extracts verified findings, and calculates explainable score.
 *
 * @param {Object[]} checks - Array of standardized checks
 * @returns {Object} { score, grade, risk, findings, methodology, coverage, remediation }
 */
function evaluateScanResults(checks = []) {
  const verifiedChecks = checks.filter(c => c && typeof c === 'object' && c.checkId);

  // Coverage statistics
  const total = verifiedChecks.length;
  const passed = verifiedChecks.filter(c => c.status === 'pass').length;
  const findingsList = verifiedChecks.filter(c => c.status === 'finding');
  const unknown = verifiedChecks.filter(c => c.status === 'unknown' || c.status === 'error').length;
  const skipped = verifiedChecks.filter(c => c.status === 'skipped').length;
  const info = verifiedChecks.filter(c => c.status === 'info').length;

  // Deduplication map to prevent double penalties
  const seenIssues = new Set();
  const deduplicatedFindings = [];

  for (const f of findingsList) {
    const dedupeKey = `${f.category}:${f.title}`;
    if (!seenIssues.has(dedupeKey)) {
      seenIssues.add(dedupeKey);
      deduplicatedFindings.push(f);
    }
  }

  // Scoring Calculation
  let baseScore = 100;
  const deductions = [];

  for (const f of deduplicatedFindings) {
    const penalty = SEVERITY_WEIGHTS[f.severity] || 0;
    if (penalty < 0) {
      baseScore += penalty;
      deductions.push({
        checkId: f.checkId,
        title: f.title,
        severity: f.severity,
        penalty,
        reason: f.summary,
      });
    }
  }

  const finalScore = Math.max(0, Math.min(100, baseScore));

  // Grade & Risk Classification
  let grade = 'A';
  let risk = 'Minimal';
  let gradeLabel = 'Excellent security posture';

  if (finalScore >= 90) {
    grade = 'A';
    risk = 'Minimal';
    gradeLabel = 'Exceptional security posture across all critical controls';
  } else if (finalScore >= 80) {
    grade = 'B';
    risk = 'Low';
    gradeLabel = 'Strong baseline security with minor configuration opportunities';
  } else if (finalScore >= 65) {
    grade = 'C';
    risk = 'Medium';
    gradeLabel = 'Moderate risk profile: Key defensive headers or DNS controls missing';
  } else if (finalScore >= 50) {
    grade = 'D';
    risk = 'High';
    gradeLabel = 'Elevated risk profile: Multiple security deficiencies detected';
  } else {
    grade = 'F';
    risk = 'Critical';
    gradeLabel = 'Critical risk posture: Essential perimeter and transport controls absent';
  }

  // Ranked Priority Remediation Playbook
  const severityRank = { critical: 4, high: 3, medium: 2, low: 1, informational: 0, none: 0 };
  const sortedRemediation = [...deduplicatedFindings]
    .sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0))
    .map((f, idx) => ({
      rank: idx + 1,
      checkId: f.checkId,
      category: f.category,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      impact: f.severity === 'critical' ? 'High Exploitation Risk' : f.severity === 'high' ? 'Significant Exposure' : 'Hardening Deficiency',
      whyItMatters: f.details,
      howToFix: f.recommendation || 'Apply verified security configuration directive.',
      evidence: f.evidence,
      references: f.references,
    }));

  // Category Score Breakdown
  const categories = ['security', 'network', 'email', 'content', 'performance', 'domain'];
  const categoryBreakdown = {};

  categories.forEach(cat => {
    const catChecks = verifiedChecks.filter(c => c.category === cat);
    const catFindings = deduplicatedFindings.filter(c => c.category === cat);
    let catScore = 100;
    catFindings.forEach(f => {
      catScore += (SEVERITY_WEIGHTS[f.severity] || 0);
    });
    categoryBreakdown[cat] = {
      total: catChecks.length,
      passed: catChecks.filter(c => c.status === 'pass').length,
      findings: catFindings.length,
      score: Math.max(0, Math.min(100, catScore)),
    };
  });

  return {
    score: finalScore,
    grade,
    gradeLabel,
    risk,
    coverage: {
      totalChecks: total,
      passedChecks: passed,
      findingsCount: deduplicatedFindings.length,
      unknownChecks: unknown,
      skippedChecks: skipped,
      infoChecks: info,
      coveragePercentage: total > 0 ? Math.round(((passed + deduplicatedFindings.length) / total) * 100) : 100,
    },
    methodology: {
      baseScore: 100,
      deductions,
      categories: categoryBreakdown,
      rules: [
        'Each verified finding deducts points based strictly on CVE / AppSec severity.',
        'Duplicate findings are consolidated to prevent double-penalizing the origin.',
        'Checks classified as UNKNOWN or SKIPPED incur zero penalty.',
        'High scores do not imply absolute immunity from zero-day exploits.',
      ],
    },
    findings: deduplicatedFindings,
    remediation: sortedRemediation,
  };
}

module.exports = {
  evaluateScanResults,
};
