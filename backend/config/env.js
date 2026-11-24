/**
 * Backend Environment Configuration — Zero-dependency .env loader
 * WebVitals — Phase 1
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..', '..');

// Zero-dependency .env loader
(function loadDotEnv() {
  try {
    const envPath = path.join(ROOT_DIR, '.env');
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx < 0) continue;
        const key = trimmed.slice(0, eqIdx).trim();
        const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
        if (key && !(key in process.env)) process.env[key] = val;
      }
    }
  } catch {
    /* .env is optional */
  }
})();

// ─── Server ──────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '8888', 10);
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';

// ─── Static assets ───────────────────────────────────────────────────────────
const DIST_DIR = path.join(ROOT_DIR, 'frontend', 'dist');
const PUBLIC_DIR = fs.existsSync(DIST_DIR) ? DIST_DIR : path.join(ROOT_DIR, 'public');

// ─── Rate limits (per IP, per 60-second window) ───────────────────────────────
const RATE_LIMITS = {
  scan:      { maxRequests: 5,   windowMs: 60_000 },  // expensive — strict
  seo:         { maxRequests: 10,  windowMs: 60_000 },
  competitive: { maxRequests: 5,   windowMs: 60_000 },
  techstack:   { maxRequests: 10,  windowMs: 60_000 },
  benchmark: { maxRequests: 5,   windowMs: 60_000 },
  ai:        { maxRequests: 25,  windowMs: 60_000 },  // Phase 4 AI requests
  general:   { maxRequests: 60,  windowMs: 60_000 },  // health, status, history, exports
};

// ─── Concurrency ─────────────────────────────────────────────────────────────
const MAX_CONCURRENT_SCANS_PER_IP = parseInt(process.env.MAX_CONCURRENT_SCANS_PER_IP || '2', 10);
const MAX_TOTAL_CONCURRENT_SCANS  = parseInt(process.env.MAX_TOTAL_CONCURRENT_SCANS  || '20', 10);

// ─── Storage ─────────────────────────────────────────────────────────────────
const MAX_HISTORY = parseInt(process.env.MAX_HISTORY || '100', 10);
const STORAGE_BACKEND = process.env.STORAGE_BACKEND || 'memory'; // 'memory' | 'firestore'

// ─── CORS ─────────────────────────────────────────────────────────────────────
// Comma-separated list of allowed origins. In dev, allow localhost variants.
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
  : IS_PRODUCTION
    ? []  // must be explicitly set in production
    : ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:4173'];

// ─── External API keys & AI settings (server-side only — never expose to frontend)
const MASTER_GOOGLE_KEY        = process.env.GOOGLE_CLOUD_API_KEY     || process.env.GOOGLE_API_KEY || null;

const GEMINI_API_KEY           = process.env.GEMINI_API_KEY           || MASTER_GOOGLE_KEY || null;
const AI_ENABLED               = process.env.AI_ENABLED !== 'false' && Boolean(GEMINI_API_KEY);
const GEMINI_MODEL             = process.env.GEMINI_MODEL             || 'gemini-3.5-flash-lite';
const GEMINI_TIMEOUT_MS        = parseInt(process.env.GEMINI_TIMEOUT_MS || '20000', 10);
const GEMINI_MAX_OUTPUT_TOKENS = parseInt(process.env.GEMINI_MAX_OUTPUT_TOKENS || '4096', 10);

const GOOGLE_PAGESPEED_API_KEY = process.env.GOOGLE_PAGESPEED_API_KEY || MASTER_GOOGLE_KEY || null;
const SAFE_BROWSING_API_KEY    = process.env.SAFE_BROWSING_API_KEY    || MASTER_GOOGLE_KEY || null;
const VIRUSTOTAL_API_KEY       = process.env.VIRUSTOTAL_API_KEY       || null;

// ─── Scan network settings ────────────────────────────────────────────────────
const SCAN_TIMEOUT_MS    = parseInt(process.env.SCAN_TIMEOUT_MS    || '10000', 10);
const SCAN_MAX_REDIRECTS = parseInt(process.env.SCAN_MAX_REDIRECTS || '5',     10);

module.exports = {
  PORT,
  NODE_ENV,
  IS_PRODUCTION,
  ROOT_DIR,
  PUBLIC_DIR,
  RATE_LIMITS,
  MAX_CONCURRENT_SCANS_PER_IP,
  MAX_TOTAL_CONCURRENT_SCANS,
  MAX_HISTORY,
  STORAGE_BACKEND,
  ALLOWED_ORIGINS,
  GEMINI_API_KEY,
  AI_ENABLED,
  GEMINI_MODEL,
  GEMINI_TIMEOUT_MS,
  GEMINI_MAX_OUTPUT_TOKENS,
  GOOGLE_PAGESPEED_API_KEY,
  SAFE_BROWSING_API_KEY,
  VIRUSTOTAL_API_KEY,
  SCAN_TIMEOUT_MS,
  SCAN_MAX_REDIRECTS,
};

