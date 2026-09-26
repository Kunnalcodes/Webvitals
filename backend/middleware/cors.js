/**
 * CORS Middleware — Phase 1
 * WebVitals
 *
 * Fixes P2-1: Wildcard CORS was unconditional on all routes.
 * Now restricts to configured ALLOWED_ORIGINS with proper preflight handling.
 */

'use strict';

const { ALLOWED_ORIGINS, IS_PRODUCTION } = require('../config/env');

/**
 * Applies CORS headers to the response.
 * - In production: only allows explicitly configured origins.
 * - In development: allows localhost variants.
 * - Preflight (OPTIONS) requests are handled correctly.
 *
 * @returns {boolean} true to continue handling; false if preflight was handled.
 */
function applyCors(req, res) {
  const origin = req.headers.origin;

  if (ALLOWED_ORIGINS.length === 0 && IS_PRODUCTION) {
    // Misconfiguration guard: no origins set in production → refuse all cross-origin requests
    // but still respond to OPTIONS so browser errors are clear.
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return false;
    }
    return true;
  }

  if (origin) {
    const isAllowed = ALLOWED_ORIGINS.includes(origin);
    if (isAllowed) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
    // Do not set the header at all if origin is not allowed.
    // The browser will block the request with a CORS error.
  } else {
    // No origin header = same-origin or non-browser request (e.g. curl, server-to-server).
    // Allow it — no CORS header needed.
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Expose-Headers', 'X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After');
  res.setHeader('Access-Control-Max-Age', '86400'); // Cache preflight for 24h

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return false; // handled
  }

  return true; // continue
}

module.exports = { applyCors };
