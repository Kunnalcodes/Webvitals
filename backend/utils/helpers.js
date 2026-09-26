/**
 * URL Utilities — Phase 1
 * WebVitals
 */

'use strict';

const { URL } = require('url');

/**
 * Normalizes a raw user URL string into a URL object.
 * Adds https:// if no protocol is present.
 */
function normalizeUrl(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    throw new Error('Invalid URL input');
  }
  const trimmed = rawInput.trim();
  const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return new URL(withProto);
}

/**
 * Parses a Content-Security-Policy header string into a directive map.
 * { 'script-src': ['self', 'nonce-abc'], ... }
 */
function parseCsp(cspHeader) {
  if (!cspHeader || typeof cspHeader !== 'string') return {};
  const result = {};
  for (const part of cspHeader.split(';')) {
    const tokens = part.trim().split(/\s+/);
    if (!tokens[0]) continue;
    result[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  return result;
}

/**
 * Safely reads the body of an HTTP request as a string.
 * Limits body size to prevent memory exhaustion.
 */
function readBody(req, maxBytes = 65_536) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.destroy();
        return reject(Object.assign(new Error('Request body too large'), { code: 'BODY_TOO_LARGE' }));
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/**
 * Sends a standardised JSON response.
 */
function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(payload));
  res.writeHead(statusCode);
  res.end(payload);
}

/**
 * Sends a standardised success response.
 */
function sendSuccess(res, data, meta = {}) {
  sendJson(res, 200, { success: true, data, meta });
}

/**
 * Sends a standardised error response.
 */
function sendError(res, statusCode, code, message) {
  sendJson(res, statusCode, {
    success: false,
    error: { code, message },
  });
}

module.exports = {
  normalizeUrl,
  parseCsp,
  readBody,
  sendJson,
  sendSuccess,
  sendError,
};
