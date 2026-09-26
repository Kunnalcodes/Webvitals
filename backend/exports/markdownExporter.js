/**
 * Markdown Audit Report Exporter — Phase 4
 * WebVitals
 *
 * Generates formatted, comprehensive, audit-ready Markdown security intelligence reports.
 */

'use strict';

/**
 * Converts a Phase 3 scan report into clean, comprehensive GitHub Flavored Markdown.
 *
 * @param {object} scanReport
 * @returns {string} Markdown document
 */
function exportToMarkdown(scanReport) {
  if (!scanReport) return '';

  const findings = scanReport.findings || [];
  const technologies = scanReport.technologies || [];
  const limitations = scanReport.limitations || [];

  const passed = findings.filter((f) => f.status === 'PASS');
  const failed = findings.filter((f) => f.status === 'FAIL');
  const warning = findings.filter((f) => f.status === 'WARNING');
  const notEvaluated = findings.filter((f) => f.status === 'NOT_EVALUATED');

  const score = scanReport.score ?? 0;
  const grade = scanReport.grade || 'F';
  const gradeLabel = scanReport.gradeLabel || (score >= 80 ? 'Safe' : score >= 60 ? 'Needs Attention' : 'High Risk');

  const md = [];

  md.push(`# WebVitals Security Intelligence Audit Report`);
  md.push(`**Target Host:** \`${scanReport.hostname}\` | **Scan ID:** \`${scanReport.scanId}\` | **Timestamp:** \`${scanReport.completedAt || scanReport.timestamp || new Date().toISOString()}\``);
  md.push(`**Requested URL:** \`${scanReport.requestedUrl || scanReport.hostname}\` | **Final Endpoint:** \`${scanReport.finalUrl || scanReport.requestedUrl || scanReport.hostname}\``);
  md.push(`**Audit Engine:** \`WebVitals Core v${scanReport.scannerVersion || '4.0.0'}\``);
  md.push('');
  md.push(`---`);
  md.push('');

  // Executive Summary Narrative
  md.push(`## 🏛️ Executive Summary & Threat Briefing`);
  md.push('');
  let postureVerdict = 'Adequate security posture with actionable areas for hardening.';
  if (score >= 90) postureVerdict = 'Robust, modern security posture across all critical perimeter controls.';
  else if (score >= 80) postureVerdict = 'Strong baseline security with minor configuration opportunities.';
  else if (score >= 60) postureVerdict = 'Moderate risk profile: Key defensive headers and DNS controls require remediation.';
  else postureVerdict = 'High risk posture: Critical security controls are absent or misconfigured.';

  md.push(`> **Executive Posture Verdict:** ${postureVerdict}`);
  md.push('');
  md.push(`WebVitals conducted an automated remote perimeter audit of \`${scanReport.hostname}\`. The target achieved an overall security score of **${score}/100** (Grade: **${grade}** - ${gradeLabel}). Out of **${findings.length}** evaluated controls, **${passed.length}** passed verification, **${warning.length}** produced warnings, and **${failed.length}** failed security baseline requirements.`);
  md.push('');
  if (failed.length > 0) {
    md.push(`**Immediate Action Items:** Remediate missing perimeter controls (${failed.map(f => f.title).join(', ')}) to protect the target from XSS, clickjacking, protocol downgrade, and email spoofing threats.`);
    md.push('');
  }
  md.push(`---`);
  md.push('');

  // Score Posture Table
  md.push(`## 📊 Security Posture & Score`);
  md.push('');
  md.push(`| Metric | Value | Baseline Status |`);
  md.push(`| :--- | :--- | :--- |`);
  md.push(`| **Overall Score** | **${score}/100** | ${score >= 80 ? '🟢 Safe' : score >= 60 ? '🟡 Needs Attention' : '🔴 High Risk'} |`);
  md.push(`| **Letter Grade** | **${grade}** (${gradeLabel}) | ${score >= 80 ? 'Compliant' : 'Non-Compliant'} |`);
  md.push(`| **Classification** | **${scanReport.classification || gradeLabel}** | Assessed |`);
  md.push(`| **Failed Controls** | **${failed.length}** | ${failed.length === 0 ? '🟢 Zero Failures' : '🔴 Requires Immediate Action'} |`);
  md.push(`| **Warnings** | **${warning.length}** | ${warning.length === 0 ? '🟢 None' : '🟡 Review Recommended'} |`);
  md.push(`| **Passed Controls** | **${passed.length}** | 🟢 Verified Active |`);
  if (notEvaluated.length > 0) {
    md.push(`| **Not Evaluated** | **${notEvaluated.length}** | Out of Scope / Inaccessible |`);
  }
  md.push('');
  md.push(`---`);
  md.push('');

  // Regulatory & Compliance Matrix
  md.push(`## 📋 Regulatory & Compliance Alignment Matrix`);
  md.push('');
  md.push(`| Standard / Framework | Domain | Target Status | Guidance & Requirements |`);
  md.push(`| :--- | :--- | :--- | :--- |`);
  md.push(`| **OWASP Top 10 (2021)** | A05: Security Misconfiguration | ${failed.some(f => f.channel === 'CSP' || f.channel === 'MIME') ? '🔴 Non-Compliant' : '🟢 Compliant'} | Enforce strict Content Security Policy and nosniff directives |`);
  md.push(`| **OWASP Top 10 (2021)** | A02: Cryptographic Failures | ${scanReport.https ? '🟢 Compliant' : '🔴 Non-Compliant'} | Enforce HSTS with long max-age and modern TLS encryption |`);
  md.push(`| **NIST CSF 2.0** | PR.DS (Data Security in Transit) | ${failed.some(f => f.channel === 'HSTS' || f.channel === 'TLS') ? '🟡 Partial' : '🟢 Compliant'} | Protect in-transit confidentiality and integrity |`);
  md.push(`| **CIS Controls v8** | Control 4 (Secure Configuration) | ${failed.length > 2 ? '🔴 Non-Compliant' : failed.length > 0 ? '🟡 Partial' : '🟢 Compliant'} | Baseline secure application server hardening |`);
  md.push(`| **GDPR Article 32** | Security of Processing | ${failed.some(f => f.channel === 'PRIVACY' || f.channel === 'COOKIES') ? '🟡 Partial' : '🟢 Compliant'} | Prevent data leakage via Referrer-Policy and insecure cookies |`);
  md.push('');
  md.push(`---`);
  md.push('');

  // Detected Tech Stack
  if (technologies.length > 0) {
    md.push(`## 🛠️ Detected Technology Stack`);
    md.push('');
    md.push(`| Technology / Component | Category | Confidence | Detection Evidence |`);
    md.push(`| :--- | :--- | :--- | :--- |`);
    for (const t of technologies) {
      md.push(`| **${t.name}** | \`${t.category}\` | ${(t.confidence * 100).toFixed(0)}% | _${t.evidence}_ |`);
    }
    md.push('');
    md.push(`---`);
    md.push('');
  }

  // Actionable Findings
  md.push(`## 🚨 Actionable Findings (${failed.length + warning.length})`);
  md.push('');

  const actionable = [...failed, ...warning];
  if (actionable.length === 0) {
    md.push(`*✅ No critical or high-risk findings detected. Perimeter defenses are optimally configured.*`);
    md.push('');
  } else {
    for (const f of actionable) {
      const icon = f.status === 'FAIL' ? '❌' : '⚠️';
      md.push(`### ${icon} [${f.status}] ${f.title}`);
      md.push(`* **Channel:** \`${f.channel}\` | **Severity:** \`${f.severity}\` | **Confidence:** ${(f.confidence * 100).toFixed(0)}% | **Score Impact:** \`${f.scoreImpact} pts\``);
      md.push(`* **Observed Issue:** ${f.description}`);
      if (f.impact) md.push(`* **Business & Security Risk:** ${f.impact}`);
      if (f.recommendation) md.push(`* **Remediation Directive:** ${f.recommendation}`);
      if (f.limitations?.length > 0) md.push(`* **Audit Limitations:** ${f.limitations.join('; ')}`);
      md.push('');
    }
  }

  md.push(`---`);
  md.push('');

  // Verified Controls
  md.push(`## ✅ Verified Defensive Controls (${passed.length})`);
  md.push('');
  if (passed.length === 0) {
    md.push(`*No passed controls recorded.*`);
  } else {
    for (const f of passed) {
      md.push(`* **[PASS] ${f.title}** (\`${f.channel}\`): ${f.description}`);
    }
  }
  md.push('');
  md.push(`---`);
  md.push('');

  // Multi-Stack Remediation Playbooks
  md.push(`## 💻 Multi-Stack Remediation Snippets`);
  md.push('');
  md.push(`### 1. Nginx Web Server (\`/etc/nginx/conf.d/security.conf\`)`);
  md.push('```nginx');
  md.push('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;');
  md.push('add_header X-Content-Type-Options "nosniff" always;');
  md.push('add_header X-Frame-Options "DENY" always;');
  md.push('add_header Referrer-Policy "strict-origin-when-cross-origin" always;');
  md.push('add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;');
  md.push('add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'none\';" always;');
  md.push('```');
  md.push('*Verification:* `nginx -t && systemctl reload nginx`');
  md.push('');

  md.push(`### 2. Apache HTTPD (\`.htaccess\` or \`httpd.conf\`)`);
  md.push('```apache');
  md.push('<IfModule mod_headers.c>');
  md.push('  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"');
  md.push('  Header always set X-Content-Type-Options "nosniff"');
  md.push('  Header always set X-Frame-Options "DENY"');
  md.push('  Header always set Referrer-Policy "strict-origin-when-cross-origin"');
  md.push('  Header always set Content-Security-Policy "default-src \'self\';"');
  md.push('</IfModule>');
  md.push('```');
  md.push('*Verification:* `apachectl configtest && systemctl reload apache2`');
  md.push('');

  md.push(`### 3. Next.js (\`next.config.js\`)`);
  md.push('```javascript');
  md.push('module.exports = {');
  md.push('  async headers() {');
  md.push('    return [{');
  md.push('      source: "/(.*)",');
  md.push('      headers: [');
  md.push('        { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },');
  md.push('        { key: "X-Content-Type-Options", value: "nosniff" },');
  md.push('        { key: "X-Frame-Options", value: "DENY" },');
  md.push('        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }');
  md.push('      ]');
  md.push('    }];');
  md.push('  }');
  md.push('};');
  md.push('```');
  md.push('');

  md.push(`### 4. Authoritative DNS Records`);
  md.push('```text');
  md.push('Host: @       Type: TXT  Value: "v=spf1 include:_spf.google.com ~all"');
  md.push('Host: _dmarc  Type: TXT  Value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"');
  md.push('Host: @       Type: CAA  Value: "0 issue \\"letsencrypt.org\\""');
  md.push('```');
  md.push('');
  md.push(`---`);
  md.push('');

  // Limitations & Scope
  md.push(`## ⚠️ Audit Limitations & Scope`);
  md.push('');
  if (limitations.length > 0) {
    for (const lim of limitations) {
      md.push(`* ${lim}`);
    }
  } else {
    md.push(`* **Remote Non-Invasive Scope:** Assessment evaluates externally visible HTTP response headers, TLS negotiation, DNS resource records, and exposed endpoint metadata.`);
    md.push(`* **No Intrusive Fuzzing:** Internal application logic, SQL injection, authenticated user workflows, and denial-of-service vulnerabilities are not tested.`);
    md.push(`* **Point-in-Time Telemetry:** Results reflect target configuration at the moment of scan execution.`);
  }
  md.push('');
  md.push(`---`);
  md.push(`*Generated by WebVitals Automated Intelligence Platform — Confidential*`);

  return md.join('\n');
}

module.exports = {
  exportToMarkdown,
};
