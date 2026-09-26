/**
 * Next.js Remediation Generator — Phase 4
 * WebVitals
 *
 * Generates next.config.js headers() configuration for Next.js applications.
 */

'use strict';

const NEXT_TEMPLATES = {
  HSTS_MISSING: {
    file: 'next.config.js',
    snippet: `
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
        ],
      },
    ];
  },
};
`.trim(),
    explanation: 'Configures Next.js router to attach HSTS headers to all pages, API routes, and static assets.',
    compatibilityWarnings: ['Requires Next.js 12+ or 13/14 App Router.'],
    validationSteps: 'npm run build && npm start\ncurl -I http://localhost:3000/ | grep -i strict-transport-security',
    rollbackSteps: 'Remove headers() array from next.config.js and re-run build.',
  },
  CSP_MISSING: {
    file: 'next.config.js or middleware.ts',
    snippet: `
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' blob: data: https:; font-src 'self' https: data:; object-src 'none'; frame-ancestors 'self';",
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
];

module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};
`.trim(),
    explanation: 'Configures comprehensive security headers array inside next.config.js.',
    compatibilityWarnings: ['If using Next.js Image Optimization with external CDNs, add domains to next.config.js images.remotePatterns.'],
    validationSteps: 'Run Next.js dev server and check Network headers in DevTools.',
    rollbackSteps: 'Revert next.config.js to previous state.',
  },
};

/**
 * Generates Next.js remediation.
 * @param {string} findingId
 */
function generateNextRemediation(findingId) {
  const template = NEXT_TEMPLATES[findingId];
  if (!template) return null;

  return {
    stack: 'Next.js',
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
  generateNextRemediation,
  NEXT_TEMPLATES,
};
