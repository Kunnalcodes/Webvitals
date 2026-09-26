/**
 * Rate Limiter & Concurrency Guard — Phase 1
 * WebVitals
 *
 * Fixes P0-1: Rate limiter was broken (10,000 req/min = unlimited).
 *
 * Features:
 *  - Per-IP sliding window rate limiting (configurable per endpoint)
 *  - Per-IP concurrent scan limit
 *  - Global concurrent scan limit
 *  - Standard rate limit response headers
 *  - Periodic memory cleanup (prevents unbounded Map growth)
 */

'use strict';

const { RATE_LIMITS, MAX_CONCURRENT_SCANS_PER_IP, MAX_TOTAL_CONCURRENT_SCANS } = require('../config/env');

// ─── State ────────────────────────────────────────────────────────────────────
// ip → { count, resetTime }
const _windows = new Map();

// ip → number (active scans for this IP)
const _ipScanCounts = new Map();

// global active scan count
let _globalScanCount = 0;

// ─── Cleanup ──────────────────────────────────────────────────────────────────
// Clear expired sliding windows every 5 minutes to prevent memory leaks.
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of _windows.entries()) {
    if (now > data.resetTime) _windows.delete(ip);
  }
}, 5 * 60_000).unref(); // .unref() so the timer does not keep the process alive

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Extracts the real client IP, respecting X-Forwarded-For when present.
 * NOTE: In production behind a trusted proxy/load balancer only.
 */
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '0.0.0.0';
}

/**
 * Sends a standardised 429 response.
 */
function send429(res, config, clientData) {
  const now = Date.now();
  const resetSeconds = Math.max(0, Math.ceil((clientData.resetTime - now) / 1000));

  res.setHeader('Retry-After', String(resetSeconds));
  res.setHeader('X-RateLimit-Limit',     String(config.maxRequests));
  res.setHeader('X-RateLimit-Remaining', '0');
  res.setHeader('X-RateLimit-Reset',     String(Math.ceil(clientData.resetTime / 1000)));
  res.setHeader('Content-Type', 'application/json');
  res.writeHead(429);
  res.end(JSON.stringify({
    success: false,
    error: {
      code: 'RATE_LIMITED',
      message: `Rate limit exceeded. Please wait ${resetSeconds} second(s) before retrying.`,
      retryAfterSeconds: resetSeconds,
      limit: config.maxRequests,
      windowSeconds: Math.ceil(config.windowMs / 1000),
    },
  }));
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Sliding-window rate limiter.
 * Returns true if the request is allowed; returns false and sends 429 if not.
 *
 * @param {object} req
 * @param {object} res
 * @param {'scan'|'seo'|'techstack'|'benchmark'|'general'} endpoint
 */
function checkRateLimit(req, res, endpoint = 'general') {
  const config = RATE_LIMITS[endpoint] || RATE_LIMITS.general;
  const ip = getClientIp(req);
  const now = Date.now();

  let data = _windows.get(ip);
  if (!data || now > data.resetTime) {
    data = { count: 1, resetTime: now + config.windowMs };
    _windows.set(ip, data);
  } else {
    data.count += 1;
  }

  const remaining = Math.max(0, config.maxRequests - data.count);
  res.setHeader('X-RateLimit-Limit',     String(config.maxRequests));
  res.setHeader('X-RateLimit-Remaining', String(remaining));
  res.setHeader('X-RateLimit-Reset',     String(Math.ceil(data.resetTime / 1000)));

  if (data.count > config.maxRequests) {
    send429(res, config, data);
    return false;
  }

  return true;
}

/**
 * Acquires a scan slot. Returns false (and sends 429/503) if limits exceeded.
 * MUST be paired with releaseScanSlot() in a finally block.
 */
function acquireScanSlot(req, res) {
  const ip = getClientIp(req);
  const ipCount = _ipScanCounts.get(ip) || 0;

  if (ipCount >= MAX_CONCURRENT_SCANS_PER_IP) {
    res.setHeader('Retry-After', '15');
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(429);
    res.end(JSON.stringify({
      success: false,
      error: {
        code: 'CONCURRENT_SCAN_LIMIT',
        message: `You already have ${ipCount} active scan(s). Please wait for them to complete.`,
        limit: MAX_CONCURRENT_SCANS_PER_IP,
      },
    }));
    return false;
  }

  if (_globalScanCount >= MAX_TOTAL_CONCURRENT_SCANS) {
    res.setHeader('Retry-After', '10');
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(503);
    res.end(JSON.stringify({
      success: false,
      error: {
        code: 'SERVER_CAPACITY',
        message: 'Server is at capacity. Please retry in a few seconds.',
      },
    }));
    return false;
  }

  _ipScanCounts.set(ip, ipCount + 1);
  _globalScanCount += 1;
  return true;
}

/**
 * Releases a scan slot. Call in a finally block after every scan attempt.
 */
function releaseScanSlot(req) {
  const ip = getClientIp(req);
  const current = _ipScanCounts.get(ip) || 0;
  const next = Math.max(0, current - 1);
  if (next === 0) {
    _ipScanCounts.delete(ip);
  } else {
    _ipScanCounts.set(ip, next);
  }
  _globalScanCount = Math.max(0, _globalScanCount - 1);
}

/**
 * Returns current rate limit status for the client (non-incrementing read).
 */
function getRateLimitStatus(req, endpoint = 'general') {
  const config = RATE_LIMITS[endpoint] || RATE_LIMITS.general;
  const ip = getClientIp(req);
  const now = Date.now();
  const data = _windows.get(ip);

  if (!data || now > data.resetTime) {
    return {
      limit: config.maxRequests,
      remaining: config.maxRequests,
      resetSeconds: Math.ceil(config.windowMs / 1000),
      clientIp: ip,
    };
  }

  return {
    limit: config.maxRequests,
    remaining: Math.max(0, config.maxRequests - data.count),
    resetSeconds: Math.max(0, Math.ceil((data.resetTime - now) / 1000)),
    clientIp: ip,
  };
}

module.exports = {
  checkRateLimit,
  acquireScanSlot,
  releaseScanSlot,
  getRateLimitStatus,
  getClientIp,
};
