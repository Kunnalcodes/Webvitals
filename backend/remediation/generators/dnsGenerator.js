/**
 * Caddy, Cloudflare & DNS Remediation Generators — Phase 4
 * WebVitals
 *
 * Provides targeted snippets and guidance for Caddy Caddyfile,
 * Cloudflare Transform Rules/WAF, and DNS SPF/DMARC/CAA records.
 */

'use strict';

/**
 * Caddy Caddyfile Generator
 */
const CADDY_TEMPLATES = {
  HSTS_MISSING: {
    file: 'Caddyfile',
    snippet: `
yourdomain.com {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Content-Security-Policy "default-src 'self'; script-src 'self' https:; object-src 'none';"
    }
    reverse_proxy localhost:8080
}
`.trim(),
    explanation: 'Configures comprehensive security headers block inside Caddyfile.',
    compatibilityWarnings: ['Ensure reverse proxy backend port matches your application.'],
    validationSteps: 'caddy validate --config Caddyfile\ncaddy reload\ncurl -I https://yourdomain.com',
    rollbackSteps: 'Remove header directive and run: caddy reload',
  },
};

function generateCaddyRemediation(findingId) {
  const template = CADDY_TEMPLATES[findingId] || CADDY_TEMPLATES['HSTS_MISSING'];
  return {
    stack: 'Caddy',
    applicability: 'DIRECT',
    confidence: 0.90,
    file: template.file,
    snippet: template.snippet,
    explanation: template.explanation,
    compatibilityWarnings: template.compatibilityWarnings,
    validationSteps: template.validationSteps,
    rollbackSteps: template.rollbackSteps,
  };
}

/**
 * Cloudflare Edge Rule Generator
 */
function generateCloudflareRemediation(findingId) {
  return {
    stack: 'Cloudflare',
    applicability: 'DIRECT',
    confidence: 0.95,
    file: 'Cloudflare Dashboard → Rules → Transform Rules → Modify Response Header',
    snippet: `
Rule Name: WebVitals HTTP Security Headers
Matching Criteria: (http.request.uri.path ne "")

Actions (Set dynamic/static headers):
1. Strict-Transport-Security: "max-age=31536000; includeSubDomains; preload"
2. X-Content-Type-Options: "nosniff"
3. X-Frame-Options: "DENY"
4. Referrer-Policy: "strict-origin-when-cross-origin"
5. Content-Security-Policy: "default-src 'self'; script-src 'self' https:; object-src 'none';"
`.trim(),
    explanation: 'Applies security headers directly at the Cloudflare edge without touching backend application code.',
    compatibilityWarnings: ['Verify if existing origin web servers also send duplicate headers (Cloudflare will override or merge).'],
    validationSteps: 'Deploy Transform Rule and verify with: curl -I https://yourdomain.com',
    rollbackSteps: 'Toggle the Transform Rule off in the Cloudflare Dashboard.',
  };
}

/**
 * DNS SPF / DMARC / CAA Record Generator
 */
function generateDnsRemediation(findingId, domain = 'yourdomain.com') {
  if (findingId.startsWith('SPF')) {
    return {
      stack: 'DNS Provider (Cloudflare / Route53 / BIND)',
      applicability: 'DIRECT',
      confidence: 1.0,
      file: `DNS Zone File for ${domain}`,
      snippet: `
Type: TXT
Name: @ (or ${domain})
Value: "v=spf1 include:_spf.google.com include:mailgun.org ~all"
TTL: 3600
`.trim(),
      explanation: 'Authorizes designated email senders and instructs receivers to soft-fail (~all) or hard-fail (-all) unauthorized mail.',
      compatibilityWarnings: [
        'CRITICAL: Do NOT publish this record without merging all of your domain\'s existing legitimate email services (e.g. Google Workspace, Sendgrid, Mailgun).',
        'Never create multiple TXT records starting with v=spf1; merge them into a single record.',
      ],
      validationSteps: `dig +short TXT ${domain} | grep -i v=spf1`,
      rollbackSteps: 'Revert TXT record value in DNS provider dashboard.',
    };
  }

  if (findingId.startsWith('DMARC')) {
    return {
      stack: 'DNS Provider (Cloudflare / Route53 / BIND)',
      applicability: 'DIRECT',
      confidence: 1.0,
      file: `DNS Zone File for _dmarc.${domain}`,
      snippet: `
Type: TXT
Name: _dmarc (or _dmarc.${domain})
Value: "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain}; pct=100; adkim=r; aspf=r"
TTL: 3600
`.trim(),
      explanation: 'Instructs mail receivers to quarantine unauthenticated emails claiming to originate from your domain and report violations.',
      compatibilityWarnings: ['Begin with p=none or p=quarantine and monitor incoming aggregate reports (rua) before enforcing p=reject.'],
      validationSteps: `dig +short TXT _dmarc.${domain}`,
      rollbackSteps: 'Change policy to p=none or remove _dmarc TXT record.',
    };
  }

  if (findingId.startsWith('CAA')) {
    return {
      stack: 'DNS Provider (Cloudflare / Route53 / BIND)',
      applicability: 'DIRECT',
      confidence: 1.0,
      file: `DNS Zone File for ${domain}`,
      snippet: `
Type: CAA
Name: @ (or ${domain})
Flags: 0
Tag: issue
Value: "letsencrypt.org"

Type: CAA
Name: @ (or ${domain})
Flags: 0
Tag: issuewild
Value: "letsencrypt.org"
`.trim(),
      explanation: 'Restricts SSL/TLS certificate issuance strictly to authorized Certificate Authorities (e.g. Let\'s Encrypt).',
      compatibilityWarnings: ['Include ALL Certificate Authorities currently used across your domain and wildcard subdomains.'],
      validationSteps: `dig +short CAA ${domain}`,
      rollbackSteps: 'Remove CAA records from DNS manager.',
    };
  }

  return null;
}

module.exports = {
  generateCaddyRemediation,
  generateCloudflareRemediation,
  generateDnsRemediation,
};
