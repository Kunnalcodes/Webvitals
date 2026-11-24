/**
 * Technology Signatures & Fingerprinting — Phase 3 & 4
 * WebVitals
 *
 * Evidence-backed technology detection based on live headers, cookies, and HTML structures.
 * Expanded with modern frameworks, libraries, CDNs, servers, and cloud platforms.
 */

'use strict';

const { EVIDENCE_SOURCE, EVIDENCE_QUALITY, createEvidence } = require('../evidence/evidenceModel');

const TECH_SIGNATURES = [
  // ─── Frameworks & Libraries ────────────────────────────────────────────────
  {
    name: 'Next.js',
    category: 'Framework',
    match: (headers, html) => {
      const hasNextData = html && html.includes('__NEXT_DATA__');
      const hasNextStatic = html && html.includes('/_next/static');
      const hasNextHeader = (headers['x-powered-by'] || '').toLowerCase().includes('next.js');
      if (hasNextData || hasNextStatic || hasNextHeader) {
        return {
          matched: true,
          confidence: hasNextData && hasNextStatic ? 0.98 : 0.90,
          evidence: hasNextData ? 'Observed __NEXT_DATA__ hydration block' : 'Detected /_next/static asset path',
        };
      }
      return { matched: false };
    },
  },
  {
    name: 'React',
    category: 'Library',
    match: (headers, html) => {
      const hasReactRoot = html && (html.includes('data-reactroot') || html.includes('react-dom') || html.includes('_reactRootContainer') || html.includes('react-jsx'));
      if (hasReactRoot) {
        return { matched: true, confidence: 0.95, evidence: 'Observed React DOM root markers' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Vue.js',
    category: 'Framework',
    match: (headers, html) => {
      const hasVueAttr = html && (html.includes('data-v-') || html.includes('vue-router') || html.includes('v-cloak') || html.includes('__vue__'));
      if (hasVueAttr) {
        return { matched: true, confidence: 0.95, evidence: 'Observed Vue.js component scoped attributes (data-v-)' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Nuxt.js',
    category: 'Framework',
    match: (headers, html) => {
      const hasNuxt = html && (html.includes('__NUXT__') || html.includes('/_nuxt/') || html.includes('data-n-head'));
      if (hasNuxt) {
        return { matched: true, confidence: 0.98, evidence: 'Observed Nuxt.js hydration state __NUXT__' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Angular',
    category: 'Framework',
    match: (headers, html) => {
      const hasNg = html && (html.includes('ng-version') || html.includes('ng-app') || html.includes('_ngcontent'));
      if (hasNg) {
        return { matched: true, confidence: 0.95, evidence: 'Observed Angular ng-version / _ngcontent markers' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Svelte / SvelteKit',
    category: 'Framework',
    match: (headers, html) => {
      const hasSvelte = html && (html.includes('class="svelte-') || html.includes('/_app/immutable/'));
      if (hasSvelte) {
        return { matched: true, confidence: 0.95, evidence: 'Observed Svelte CSS scoped class or immutable app chunks' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Tailwind CSS',
    category: 'UI Framework',
    match: (headers, html) => {
      const hasTailwind = html && (/class="[^"]*(?:flex|grid|items-center|justify-between|rounded-[a-z]+|bg-[a-z]+-\d+|text-[a-z]+-\d+)[^"]*"/i.test(html) && html.includes('tailwind'));
      if (hasTailwind) {
        return { matched: true, confidence: 0.92, evidence: 'Detected utility-first Tailwind CSS class signatures and runtime markers' };
      }
      return { matched: false };
    },
  },
  {
    name: 'jQuery',
    category: 'Library',
    match: (headers, html) => {
      const hasJquery = html && (/jquery(?:[-.]min)?\.js/i.test(html) || html.includes('jQuery('));
      if (hasJquery) {
        return { matched: true, confidence: 0.94, evidence: 'Detected jQuery script inclusion' };
      }
      return { matched: false };
    },
  },

  // ─── Backend & Servers ─────────────────────────────────────────────────────
  {
    name: 'Express',
    category: 'Backend Framework',
    match: (headers) => {
      const poweredBy = (headers['x-powered-by'] || '').toLowerCase();
      if (poweredBy.includes('express')) {
        return { matched: true, confidence: 0.95, evidence: 'Observed X-Powered-By: Express' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Nginx',
    category: 'Web Server',
    match: (headers) => {
      const server = (headers['server'] || '').toLowerCase();
      if (server.includes('nginx')) {
        return { matched: true, confidence: 0.95, evidence: `Observed Server header: ${headers['server']}` };
      }
      return { matched: false };
    },
  },
  {
    name: 'Apache',
    category: 'Web Server',
    match: (headers) => {
      const server = (headers['server'] || '').toLowerCase();
      if (server.includes('apache')) {
        return { matched: true, confidence: 0.95, evidence: `Observed Server header: ${headers['server']}` };
      }
      return { matched: false };
    },
  },
  {
    name: 'Caddy',
    category: 'Web Server',
    match: (headers) => {
      const server = (headers['server'] || '').toLowerCase();
      if (server.includes('caddy')) {
        return { matched: true, confidence: 0.95, evidence: 'Observed Server: Caddy' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Laravel / PHP',
    category: 'Backend Framework',
    match: (headers, html) => {
      const hasCookie = headers['set-cookie'] ? JSON.stringify(headers['set-cookie']).toLowerCase().includes('laravel_session') : false;
      const hasPowered = (headers['x-powered-by'] || '').toLowerCase().includes('php');
      const hasCsrf = html && html.includes('name="csrf-token"');
      if (hasCookie || (hasPowered && hasCsrf)) {
        return { matched: true, confidence: 0.95, evidence: hasCookie ? 'Observed laravel_session cookie' : 'Observed PHP X-Powered-By and Laravel CSRF token' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Django / Python',
    category: 'Backend Framework',
    match: (headers) => {
      const hasCsrf = headers['set-cookie'] ? JSON.stringify(headers['set-cookie']).toLowerCase().includes('csrftoken') : false;
      const isWsg = (headers['server'] || '').toLowerCase().includes('gunicorn') || (headers['server'] || '').toLowerCase().includes('uvicorn');
      if (hasCsrf || isWsg) {
        return { matched: true, confidence: 0.90, evidence: hasCsrf ? 'Observed Django csrftoken cookie' : `Observed Python WSGI server (${headers['server']})` };
      }
      return { matched: false };
    },
  },
  {
    name: 'Spring Boot / Java',
    category: 'Backend Framework',
    match: (headers) => {
      const hasSession = headers['set-cookie'] ? JSON.stringify(headers['set-cookie']).includes('JSESSIONID') : false;
      const hasHeader = (headers['x-application-context'] !== undefined);
      if (hasSession || hasHeader) {
        return { matched: true, confidence: 0.92, evidence: hasHeader ? 'Observed X-Application-Context header' : 'Observed Java JSESSIONID session cookie' };
      }
      return { matched: false };
    },
  },

  // ─── Cloud & Edge Infrastructure ───────────────────────────────────────────
  {
    name: 'Cloudflare',
    category: 'CDN / Security',
    match: (headers) => {
      const hasCfRay = Boolean(headers['cf-ray']);
      const isCfServer = (headers['server'] || '').toLowerCase().includes('cloudflare');
      if (hasCfRay || isCfServer) {
        return {
          matched: true,
          confidence: hasCfRay && isCfServer ? 0.99 : 0.95,
          evidence: hasCfRay ? `Observed CF-Ray: ${headers['cf-ray']}` : 'Observed Server: cloudflare',
        };
      }
      return { matched: false };
    },
  },
  {
    name: 'Vercel',
    category: 'Cloud Platform',
    match: (headers) => {
      const hasVercelId = Boolean(headers['x-vercel-id']);
      const isVercelServer = (headers['server'] || '').toLowerCase().includes('vercel');
      if (hasVercelId || isVercelServer) {
        return {
          matched: true,
          confidence: 0.99,
          evidence: hasVercelId ? `Observed X-Vercel-Id: ${headers['x-vercel-id']}` : 'Observed Server: Vercel',
        };
      }
      return { matched: false };
    },
  },
  {
    name: 'Netlify',
    category: 'Cloud Platform',
    match: (headers) => {
      const hasNetlify = Boolean(headers['x-nf-request-id']) || (headers['server'] || '').toLowerCase().includes('netlify');
      if (hasNetlify) {
        return { matched: true, confidence: 0.98, evidence: 'Observed Netlify edge router header (x-nf-request-id)' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Amazon CloudFront',
    category: 'CDN',
    match: (headers) => {
      const hasCf = Boolean(headers['x-amz-cf-id']) || Boolean(headers['x-amz-cf-pop']) || (headers['via'] || '').toLowerCase().includes('cloudfront');
      if (hasCf) {
        return { matched: true, confidence: 0.98, evidence: 'Observed Amazon CloudFront routing headers' };
      }
      return { matched: false };
    },
  },
  {
    name: 'Fastly',
    category: 'CDN',
    match: (headers) => {
      const hasFastly = Boolean(headers['x-fastly-request-id']) || Boolean(headers['fastly-debug-digest']);
      if (hasFastly) {
        return { matched: true, confidence: 0.98, evidence: 'Observed Fastly edge routing signature' };
      }
      return { matched: false };
    },
  },

  // ─── CMS & E-Commerce ──────────────────────────────────────────────────────
  {
    name: 'WordPress',
    category: 'CMS',
    match: (headers, html) => {
      const hasWpContent = html && (html.includes('/wp-content/') || html.includes('/wp-includes/'));
      const hasWpGen = html && /<meta name="generator" content="WordPress/i.test(html);
      if (hasWpContent || hasWpGen) {
        return {
          matched: true,
          confidence: hasWpGen ? 0.99 : 0.90,
          evidence: hasWpGen ? 'Observed WordPress generator meta tag' : 'Detected /wp-content/ directory structure',
        };
      }
      return { matched: false };
    },
  },
  {
    name: 'Shopify',
    category: 'E-Commerce',
    match: (headers, html) => {
      const hasShopify = html && (html.includes('cdn.shopify.com') || html.includes('Shopify.shop'));
      const hasHeader = (headers['x-shopid'] !== undefined);
      if (hasShopify || hasHeader) {
        return { matched: true, confidence: 0.98, evidence: 'Detected Shopify platform CDN scripts and global objects' };
      }
      return { matched: false };
    },
  },
];

/**
 * Fingerprints technologies from observed response headers and HTML body.
 *
 * @param {Record<string, string>} headers
 * @param {string} html
 * @returns {Array<{ name: string, category: string, confidence: number, evidence: string }>}
 */
function detectTechnologies(headers = {}, html = '') {
  const detected = [];
  for (const sig of TECH_SIGNATURES) {
    const res = sig.match(headers, html);
    if (res.matched) {
      detected.push({
        name: sig.name,
        category: sig.category,
        confidence: res.confidence,
        evidence: res.evidence,
      });
    }
  }
  return detected;
}

module.exports = {
  detectTechnologies,
  TECH_SIGNATURES,
};
