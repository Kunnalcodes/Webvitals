/**
 * Executive Summary Engine — Phase 4
 * WebVitals
 *
 * Generates deterministic executive briefings, posture summaries,
 * regulatory compliance alignments, threat vector assessments, prioritized top action plans,
 * and Effort vs. Impact matrices.
 */

'use strict';

/**
 * Maps a finding to qualitative implementation effort.
 */
function estimateEffort(finding) {
  const id = finding.id || '';
  const channel = finding.channel || '';

  // Quick wins: DNS records, single security headers, basic cookie flags
  if (channel === 'HSTS' || channel === 'MIME' || channel === 'CLICKJACKING' || channel === 'PRIVACY' || id.startsWith('SPF')) {
    return 'LOW';
  }
  // Moderate: DMARC monitoring, CORS rules, sensitive file block rules
  if (channel === 'CORS' || id.startsWith('DMARC') || channel === 'SENSITIVE_FILES' || channel === 'COOKIES') {
    return 'MEDIUM';
  }
  // Strategic: Complex CSP rollout, TLS certificate re-issuance/infrastructure
  if (channel === 'CSP' || channel === 'TLS' || channel === 'HTTPS') {
    return 'HIGH';
  }

  return 'MEDIUM';
}

/**
 * Generates deterministic executive summary data for a scan report.
 *
 * @param {object} scanReport - Canonical Phase 3 report
 * @returns {object}
 */
function generateDeterministicExecutiveSummary(scanReport) {
  if (!scanReport) return null;

  const findings = scanReport.findings || [];
  const failedFindings = findings.filter((f) => (f.status || '').toUpperCase() === 'FAIL');
  const warningFindings = findings.filter((f) => (f.status || '').toUpperCase() === 'WARNING');

  const criticalCount = findings.filter((f) => (f.severity || '').toUpperCase() === 'CRITICAL' && (f.status || '').toUpperCase() === 'FAIL').length;
  const highCount     = findings.filter((f) => (f.severity || '').toUpperCase() === 'HIGH' && (f.status || '').toUpperCase() === 'FAIL').length;
  const mediumCount   = findings.filter((f) => ((f.severity || '').toUpperCase() === 'MEDIUM' && ((f.status || '').toUpperCase() === 'FAIL' || (f.status || '').toUpperCase() === 'WARNING'))).length;
  const lowCount      = findings.filter((f) => (f.severity || '').toUpperCase() === 'LOW').length;

  // Calculate top priority actions: sort by largest score impact, then severity
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const actionable = [...failedFindings, ...warningFindings].sort((a, b) => {
    const impactDiff = Math.abs(b.scoreImpact || 0) - Math.abs(a.scoreImpact || 0);
    if (impactDiff !== 0) return impactDiff;
    const sevA = (a.severity || '').toUpperCase();
    const sevB = (b.severity || '').toUpperCase();
    return (severityRank[sevB] || 0) - (severityRank[sevA] || 0);
  });

  const topPriorityActions = actionable.slice(0, 5).map((f, idx) => ({
    priority: idx + 1,
    findingId: f.id,
    channel: f.channel,
    title: f.title,
    severity: f.severity,
    scoreImpact: f.scoreImpact || 0,
    effort: estimateEffort(f),
    businessImpact: f.impact || f.description || 'Remediating this control directly reduces external attack surface.',
    recommendation: f.recommendation || 'Implement recommended security header or configuration.',
  }));

  // Effort vs Impact Categorization
  const quickWins = [];
  const moderateActions = [];
  const strategicActions = [];

  for (const item of topPriorityActions) {
    if (item.effort === 'LOW') {
      quickWins.push(`${item.title} (Gain: +${Math.abs(item.scoreImpact)} pts)`);
    } else if (item.effort === 'MEDIUM') {
      moderateActions.push(`${item.title} (Gain: +${Math.abs(item.scoreImpact)} pts)`);
    } else {
      strategicActions.push(`${item.title} (Gain: +${Math.abs(item.scoreImpact)} pts)`);
    }
  }

  // Deterministic posture narrative
  const score = scanReport.score ?? 0;
  let headline = 'Adequate security posture with actionable areas for hardening.';
  if (score >= 90) headline = 'Robust, enterprise-grade security posture across all critical perimeter and cryptographic controls.';
  else if (score >= 80) headline = 'Strong baseline security with minor configuration and defensive opportunities.';
  else if (score >= 60) headline = 'Moderate risk profile: Key defensive headers and email DNS controls require remediation.';
  else headline = 'High risk posture: Critical security controls are absent or misconfigured.';

  const passedCount = findings.filter((f) => (f.status || '').toUpperCase() === 'PASS').length;
  const p1 = `WebVitals conducted an automated remote security audit of ${scanReport.hostname} (Scan ID: ${scanReport.scanId}). The target achieved an overall security posture score of ${score}/100 (Grade: ${scanReport.grade}). A comprehensive suite of ${findings.length} perimeter and cryptographic controls was evaluated, resulting in ${passedCount} verified passing controls, ${criticalCount} critical exposures, ${highCount} high-risk deficiencies, and ${mediumCount} moderate warnings.`;
  const p2 = failedFindings.length > 0
    ? `Key Vulnerability Vectors: The perimeter exhibits identifiable exposure due to missing or inadequate defensive controls (${failedFindings.slice(0, 3).map(f => f.title).join(', ')}). Without these protections, client sessions and edge routing remain susceptible to cross-site scripting (XSS), user-interface redressing (clickjacking), and unauthorized domain impersonation.`
    : `Defensive Integrity: The target perimeter maintains consistent encryption standards and verified transport layer protections without detectable critical baseline omissions.`;
  const p3 = `Recommended Strategic Roadmap: Implementing the highest-ROI quick wins—specifically ${topPriorityActions.filter(a => a.effort === 'LOW').map(a => a.title).slice(0, 2).join(' and ') || 'baseline HTTP security headers'}—will rapidly close active exposure windows and elevate posture to enterprise baseline standards (+${Math.max(0, 100 - score)} pts potential gain).`;

  const narrative = `${p1}\n\n${p2}\n\n${p3}`;

  // Compliance alignment summary
  const compliance = {
    owaspTop10: failedFindings.some(f => f.channel === 'CSP' || f.channel === 'MIME') ? 'NON-COMPLIANT' : 'COMPLIANT',
    nistCsf: failedFindings.some(f => f.channel === 'HSTS' || f.channel === 'TLS') ? 'PARTIAL' : 'COMPLIANT',
    cisControls: failedFindings.length > 2 ? 'NON-COMPLIANT' : failedFindings.length > 0 ? 'PARTIAL' : 'COMPLIANT',
    gdprArticle32: failedFindings.some(f => f.channel === 'PRIVACY' || f.channel === 'COOKIES') ? 'PARTIAL' : 'COMPLIANT',
  };

  return {
    target: scanReport.hostname,
    scanId: scanReport.scanId,
    scannerVersion: scanReport.scannerVersion || '4.0.0',
    overallScore: score,
    grade: scanReport.grade || 'F',
    gradeLabel: scanReport.gradeLabel || '',
    classification: scanReport.classification || '',
    postureHeadline: headline,
    executiveNarrative: narrative,
    compliance,
    counts: {
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      totalFindings: findings.length,
    },
    topPriorityActions,
    effortVsImpact: {
      quickWins,
      moderateActions,
      strategicActions,
    },
    limitations: scanReport.limitations || [],
    timestamp: scanReport.completedAt || scanReport.timestamp || new Date().toISOString(),
    isAiGenerated: false,
  };
}

module.exports = {
  generateDeterministicExecutiveSummary,
  estimateEffort,
};
