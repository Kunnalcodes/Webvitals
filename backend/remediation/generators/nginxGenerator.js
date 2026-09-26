/**
 * Nginx Remediation Generator — Phase 4
 * WebVitals
 *
 * Generates verified, server-specific Nginx configuration blocks with placement,
 * compatibility warnings, validation, and rollback instructions.
 */

'use strict';

const NGINX_TEMPLATES = {
  HSTS_MISSING: {
    file: '/etc/nginx/conf.d/security.conf',
    snippet: `
# HTTP Strict Transport Security (HSTS)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
`.trim(),
    explanation: 'Instructs modern browsers to strictly use HTTPS connections for all subdomains for 1 year.',
    compatibilityWarnings: ['Ensure all subdomains support valid HTTPS certificates before deploying includeSubDomains.'],
    validationSteps: 'nginx -t && systemctl reload nginx\ncurl -I https://yourdomain.com | grep -i strict-transport-security',
    rollbackSteps: 'Remove the add_header directive from security.conf and run: nginx -s reload',
  },
  CSP_MISSING: {
    file: '/etc/nginx/conf.d/security.conf',
    snippet: `
# Starter Content Security Policy (Test with Report-Only first)
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https: data:; object-src 'none'; frame-ancestors 'self';" always;
`.trim(),
    explanation: 'Restricts script and resource loading origins, mitigating XSS and data exfiltration vectors.',
    compatibilityWarnings: ['Deploy initially as Content-Security-Policy-Report-Only to identify and allowlist any external CDNs or analytics.'],
    validationSteps: 'Check browser Console for any CSP violation reports on complex pages.',
    rollbackSteps: 'Comment out the Content-Security-Policy header and reload Nginx.',
  },
  CLICKJACKING_UNPROTECTED: {
    file: '/etc/nginx/conf.d/security.conf',
    snippet: `
# Clickjacking Defense
add_header X-Frame-Options "DENY" always;
`.trim(),
    explanation: 'Prevents third-party websites from rendering your application inside iframes.',
    compatibilityWarnings: ['If intentional iframe embedding is required, use SAMEORIGIN or CSP frame-ancestors directive instead.'],
    validationSteps: 'curl -I https://yourdomain.com | grep -i x-frame-options',
    rollbackSteps: 'Remove the add_header X-Frame-Options line and reload Nginx.',
  },
  MIME_SNIFFING_UNPROTECTED: {
    file: '/etc/nginx/conf.d/security.conf',
    snippet: `
# MIME Sniffing Defense
add_header X-Content-Type-Options "nosniff" always;
`.trim(),
    explanation: 'Forces browsers to strictly obey the declared Content-Type, blocking executable masquerading.',
    compatibilityWarnings: ['Ensure your web server sets correct Content-Type headers for CSS and JS assets.'],
    validationSteps: 'curl -I https://yourdomain.com | grep -i x-content-type-options',
    rollbackSteps: 'Remove the add_header X-Content-Type-Options line and reload Nginx.',
  },
  SERVER_HEADER_DISCLOSURE: {
    file: '/etc/nginx/nginx.conf',
    snippet: `
# Hide Nginx Version
server_tokens off;
`.trim(),
    explanation: 'Suppresses Nginx version numbers in Server response headers and default error pages.',
    compatibilityWarnings: ['Requires placement inside the http { ... } block of nginx.conf.'],
    validationSteps: 'curl -I https://yourdomain.com | grep -i server',
    rollbackSteps: 'Set server_tokens on; and reload Nginx.',
  },
  SENSITIVE_FILES_PROTECTED: {
    file: '/etc/nginx/conf.d/security.conf',
    snippet: `
# Block access to hidden files and version control directories
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}

# Block backup and environment files
location ~* \\.(env|bak|config|sql|tar|gz|zip)$ {
    deny all;
    return 404;
}
`.trim(),
    explanation: 'Returns 404 for any probe requesting .env, .git, or database backup archives.',
    compatibilityWarnings: ['Place inside the server { ... } block before general routing rules.'],
    validationSteps: 'curl -I https://yourdomain.com/.env (should return 404)',
    rollbackSteps: 'Remove the location block and reload Nginx.',
  },
};

/**
 * Generates Nginx remediation for a given finding ID.
 *
 * @param {string} findingId
 * @returns {object|null}
 */
function generateNginxRemediation(findingId) {
  const template = NGINX_TEMPLATES[findingId];
  if (!template) return null;

  return {
    stack: 'Nginx',
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
  generateNginxRemediation,
  NGINX_TEMPLATES,
};
