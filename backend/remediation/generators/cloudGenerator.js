/**
 * Cloud & Modern Edge Remediation Generator — Phase 4
 * WebVitals
 *
 * Generates copy-paste configurations for Vercel, Netlify, Caddy, and Container Ingress.
 */

'use strict';

const CLOUD_TEMPLATES = {
  vercel: {
    file: 'vercel.json',
    snippet: `
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' blob: data: https:; object-src 'none'; frame-ancestors 'none';" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" },
        { "key": "Cross-Origin-Opener-Policy", "value": "same-origin" }
      ]
    }
  ]
}
`.trim(),
    explanation: 'Applies zero-trust HTTP security headers across all edge serverless routes and static assets in Vercel deployments.',
    compatibilityWarnings: ['Place vercel.json in the project root.'],
    validationSteps: 'Deploy preview with "vercel" CLI and inspect edge headers with: curl -I https://<preview>.vercel.app',
    rollbackSteps: 'Remove or revert vercel.json.',
  },
  netlify: {
    file: '_headers or netlify.toml',
    snippet: `
/*
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' blob: data: https:; object-src 'none'; frame-ancestors 'none';
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Cross-Origin-Opener-Policy: same-origin
`.trim(),
    explanation: 'Deploys defense headers at Netlify edge CDN nodes before reaching application origin.',
    compatibilityWarnings: ['Save as "_headers" inside the build output / publish directory (e.g. dist/ or public/).'],
    validationSteps: 'Run "netlify dev" or deploy and check HTTP response headers.',
    rollbackSteps: 'Delete or edit _headers file.',
  },
  caddy: {
    file: 'Caddyfile',
    snippet: `
yourdomain.com {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Cross-Origin-Opener-Policy "same-origin"
        -Server
    }
    reverse_proxy localhost:8080
}
`.trim(),
    explanation: 'Configures Caddy v2 modern automatic HTTPS reverse proxy with hardened headers and stripped Server disclosure.',
    compatibilityWarnings: ['Requires Caddy v2+.'],
    validationSteps: 'caddy validate --config Caddyfile && caddy reload',
    rollbackSteps: 'Revert Caddyfile and run caddy reload.',
  },
};

function generateVercelRemediation(findingId) {
  return {
    stack: 'Vercel Edge Platform',
    applicability: 'RECOMMENDED',
    confidence: 0.98,
    ...CLOUD_TEMPLATES.vercel,
  };
}

function generateNetlifyRemediation(findingId) {
  return {
    stack: 'Netlify Edge CDN',
    applicability: 'RECOMMENDED',
    confidence: 0.98,
    ...CLOUD_TEMPLATES.netlify,
  };
}

function generateCaddyRemediation(findingId) {
  return {
    stack: 'Caddy Modern Web Server',
    applicability: 'RECOMMENDED',
    confidence: 0.95,
    ...CLOUD_TEMPLATES.caddy,
  };
}

module.exports = {
  generateVercelRemediation,
  generateNetlifyRemediation,
  generateCaddyRemediation,
};
