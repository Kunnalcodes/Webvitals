/**
 * SARIF 2.1.0 Exporter — Phase 4
 * WebVitals
 *
 * Generates official OASIS SARIF 2.1.0 reports for GitHub Advanced Security,
 * GitLab Security Dashboards, and CI/CD security pipelines.
 */

'use strict';

const SARIF_RULE_MAP = {
  HSTS: 'WEBVITALS-HSTS-001',
  CSP: 'WEBVITALS-CSP-001',
  TLS: 'WEBVITALS-TLS-001',
  HTTPS: 'WEBVITALS-HTTPS-001',
  CLICKJACKING: 'WEBVITALS-XFO-001',
  MIME: 'WEBVITALS-MIME-001',
  COOKIES: 'WEBVITALS-COOKIE-001',
  CORS: 'WEBVITALS-CORS-001',
  DNS: 'WEBVITALS-DNS-001',
  SENSITIVE_FILES: 'WEBVITALS-EXPOSURE-001',
  PHISHING: 'WEBVITALS-HEURISTIC-001',
  PRIVACY: 'WEBVITALS-PRIVACY-001',
  INFO_DISCLOSURE: 'WEBVITALS-INFO-001',
};

function mapSeverityToSarifLevel(severity, status) {
  if (status === 'PASS' || status === 'NOT_EVALUATED') return 'none';
  if (severity === 'CRITICAL' || severity === 'HIGH') return 'error';
  if (severity === 'MEDIUM') return 'warning';
  return 'note';
}

/**
 * Converts a Phase 3 scan report into valid SARIF 2.1.0 JSON.
 *
 * @param {object} scanReport
 * @returns {object} SARIF 2.1.0 Object
 */
function exportToSarif(scanReport) {
  if (!scanReport) return null;

  const findings = scanReport.findings || [];
  const rules = [];
  const results = [];
  const targetUrl = scanReport.finalUrl || scanReport.requestedUrl || 'https://target.local';

  for (const finding of findings) {
    const ruleId = SARIF_RULE_MAP[finding.channel] || `WEBVITALS-${finding.channel}-001`;

    if (!rules.some((r) => r.id === ruleId)) {
      rules.push({
        id: ruleId,
        name: `${finding.channel}Rule`,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: { text: finding.recommendation || finding.description },
        properties: {
          category: finding.channel,
          precision: finding.confidence >= 0.9 ? 'high' : 'medium',
        },
      });
    }

    // Only include actionable/failed/warning results in SARIF findings list
    if (finding.status === 'FAIL' || finding.status === 'WARNING') {
      results.push({
        ruleId,
        level: mapSeverityToSarifLevel(finding.severity, finding.status),
        message: {
          text: `[${finding.status}] ${finding.title}: ${finding.description}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: targetUrl,
              },
            },
          },
        ],
        properties: {
          status: finding.status,
          severity: finding.severity,
          confidence: finding.confidence,
          scoreImpact: finding.scoreImpact,
        },
      });
    }
  }

  return {
    version: '2.1.0',
    $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'WebVitals Web Security Intelligence',
            version: scanReport.scannerVersion || '3.0.0',
            informationUri: 'https://github.com/webvitals/analyzer',
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: scanReport.completedAt || scanReport.timestamp || new Date().toISOString(),
          },
        ],
        results,
      },
    ],
  };
}

module.exports = {
  exportToSarif,
  mapSeverityToSarifLevel,
  SARIF_RULE_MAP,
};
