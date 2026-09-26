/**
 * Apache Remediation Generator — Phase 4
 * WebVitals
 *
 * Generates verified .htaccess and httpd.conf mod_headers directives.
 */

'use strict';

const APACHE_TEMPLATES = {
  HSTS_MISSING: {
    file: '.htaccess or /etc/apache2/sites-available/000-default-le-ssl.conf',
    snippet: `
<IfModule mod_headers.c>
    # HTTP Strict Transport Security
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
`.trim(),
    explanation: 'Enforces HTTPS for 1 year across all subdomains in Apache.',
    compatibilityWarnings: ['Ensure mod_headers is enabled (sudo a2enmod headers) and AllowOverride All is set.'],
    validationSteps: 'apachectl configtest && sudo systemctl reload apache2\ncurl -I https://yourdomain.com | grep -i strict-transport-security',
    rollbackSteps: 'Remove the Header directive from .htaccess and reload Apache.',
  },
  CSP_MISSING: {
    file: '.htaccess',
    snippet: `
<IfModule mod_headers.c>
    # Content Security Policy (Starter Policy)
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https: data:; object-src 'none'; frame-ancestors 'self';"
</IfModule>
`.trim(),
    explanation: 'Deploys CSP directives restricting script and resource execution origins.',
    compatibilityWarnings: ['Test with Content-Security-Policy-Report-Only first to discover all required CDN origins.'],
    validationSteps: 'Inspect browser console for CSP violation reports.',
    rollbackSteps: 'Remove the Header directive from .htaccess.',
  },
  CLICKJACKING_UNPROTECTED: {
    file: '.htaccess',
    snippet: `
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
</IfModule>
`.trim(),
    explanation: 'Blocks unauthorized iframe embedding of this site.',
    compatibilityWarnings: ['Use SAMEORIGIN if internal framing across your domain is required.'],
    validationSteps: 'curl -I https://yourdomain.com | grep -i x-frame-options',
    rollbackSteps: 'Remove the Header directive from .htaccess.',
  },
  MIME_SNIFFING_UNPROTECTED: {
    file: '.htaccess',
    snippet: `
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
</IfModule>
`.trim(),
    explanation: 'Prevents MIME-type confusion and executable masquerading in Apache.',
    compatibilityWarnings: ['Requires mod_headers enabled.'],
    validationSteps: 'curl -I https://yourdomain.com | grep -i x-content-type-options',
    rollbackSteps: 'Remove directive from .htaccess.',
  },
  SERVER_HEADER_DISCLOSURE: {
    file: '/etc/apache2/conf-available/security.conf',
    snippet: `
# Suppress Apache Version and OS Signature
ServerTokens Prod
ServerSignature Off
`.trim(),
    explanation: 'Minimizes Apache information disclosure in headers and error pages.',
    compatibilityWarnings: ['Place in main Apache configuration (not in .htaccess).'],
    validationSteps: 'curl -I https://yourdomain.com | grep -i server',
    rollbackSteps: 'Change ServerTokens to Full and ServerSignature to On.',
  },
};

/**
 * Generates Apache remediation.
 * @param {string} findingId
 */
function generateApacheRemediation(findingId) {
  const template = APACHE_TEMPLATES[findingId];
  if (!template) return null;

  return {
    stack: 'Apache',
    applicability: 'DIRECT',
    confidence: 0.95,
    file: template.file,
    snippet: template.snippet,
    explanation: template.explanation,
    compatibilityWarnings: template.compatibilityWarnings,
    validationSteps: template.validationSteps,
    rollbackSteps: template.rollbackSteps,
  };
}

module.exports = {
  generateApacheRemediation,
  APACHE_TEMPLATES,
};
