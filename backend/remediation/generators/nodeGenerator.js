/**
 * Node.js / Express Remediation Generator — Phase 4
 * WebVitals
 *
 * Generates native Node.js / Express security header middleware
 * (Zero external dependencies by default, with optional Helmet alternative).
 */

'use strict';

const NODE_TEMPLATES = {
  HSTS_MISSING: {
    file: 'server.js (Middleware)',
    snippet: `
// Native Express / Node.js Middleware (Zero-dependency)
app.use((req, res, next) => {
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );
  next();
});

// Optional dependency-based approach (using helmet):
// const helmet = require('helmet');
// app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));
`.trim(),
    explanation: 'Sets Strict-Transport-Security header natively on all outgoing HTTP responses.',
    compatibilityWarnings: ['Ensure application is accessed via HTTPS before enabling in production.'],
    validationSteps: 'curl -I http://localhost:PORT | grep -i strict-transport-security',
    rollbackSteps: 'Remove the app.use() middleware block.',
  },
  CSP_MISSING: {
    file: 'server.js (Middleware)',
    snippet: `
// Native CSP Middleware
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https:; style-src 'self' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; object-src 'none'; frame-ancestors 'self';"
  );
  next();
});
`.trim(),
    explanation: 'Attaches a strong Content-Security-Policy header to every HTTP response.',
    compatibilityWarnings: ['Audit all frontend inline scripts and external CDN dependencies.'],
    validationSteps: 'Open browser console and check for CSP violation warnings.',
    rollbackSteps: 'Comment out the res.setHeader() line.',
  },
  CLICKJACKING_UNPROTECTED: {
    file: 'server.js (Middleware)',
    snippet: `
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
`.trim(),
    explanation: 'Sets X-Frame-Options: DENY natively without third-party libraries.',
    compatibilityWarnings: ['Use SAMEORIGIN if your application embeds its own sub-pages in iframes.'],
    validationSteps: 'curl -I http://localhost:PORT | grep -i x-frame-options',
    rollbackSteps: 'Remove the middleware line.',
  },
  MIME_SNIFFING_UNPROTECTED: {
    file: 'server.js (Middleware)',
    snippet: `
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
`.trim(),
    explanation: 'Enforces exact MIME-type handling across all Express/Node responses.',
    compatibilityWarnings: ['Ensure all static files are served with valid Content-Type headers.'],
    validationSteps: 'curl -I http://localhost:PORT | grep -i x-content-type-options',
    rollbackSteps: 'Remove the middleware line.',
  },
  SERVER_HEADER_DISCLOSURE: {
    file: 'server.js',
    snippet: `
// Disable Express fingerprint header
app.disable('x-powered-by');
`.trim(),
    explanation: 'Prevents Express from broadcasting the X-Powered-By: Express header.',
    compatibilityWarnings: ['Call app.disable(\'x-powered-by\') immediately after creating the app instance.'],
    validationSteps: 'curl -I http://localhost:PORT | grep -i x-powered-by (should return nothing)',
    rollbackSteps: 'Remove app.disable(\'x-powered-by\').',
  },
  COOKIE_SESSION_HTTPONLY_MISSING: {
    file: 'server.js / session configuration',
    snippet: `
// Secure Cookie Configuration
res.cookie('session_token', tokenValue, {
  httpOnly: true, // Prevents JavaScript XSS access
  secure: process.env.NODE_ENV === 'production', // Transmit only over HTTPS
  sameSite: 'lax', // Protects against CSRF
  maxAge: 24 * 60 * 60 * 1000,
});
`.trim(),
    explanation: 'Configures httpOnly, secure, and sameSite flags for all authentication cookies.',
    compatibilityWarnings: ['Do not read this cookie via document.cookie in client-side code.'],
    validationSteps: 'Inspect Set-Cookie response in browser DevTools Application > Cookies tab.',
    rollbackSteps: 'Adjust cookie options.',
  },
};

/**
 * Generates Node.js remediation.
 * @param {string} findingId
 */
function generateNodeRemediation(findingId) {
  const template = NODE_TEMPLATES[findingId];
  if (!template) return null;

  return {
    stack: 'Node.js / Express',
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
  generateNodeRemediation,
  NODE_TEMPLATES,
};
