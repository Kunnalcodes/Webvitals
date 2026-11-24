/**
 * HTTP Router — Phase 1
 * WebVitals
 */

'use strict';

const { URL } = require('url');
const { applySecurityHeaders } = require('../middleware/abuseProtection');
const { applyCors }            = require('../middleware/cors');
const { handleHealth, handleIntegrationsStatus } = require('../controllers/healthController');
const { handleScan, handleScanStatus, handleHistory, handleDomainTrend } = require('../controllers/scanController');
const { handleBenchmark }   = require('../controllers/benchmarkController');
const { handleTechStack }   = require('../controllers/techStackController');
const { handleDomainRecon } = require('../controllers/domainReconController');
const { handleSeoAnalyze, handleSeoHistory } = require('../controllers/seoController');
const {
  handleCompetitiveAnalyze,
  handleCompetitiveStatus,
  handleCompetitiveHistory,
  handleCompetitiveExport,
} = require('../controllers/competitiveController');
const { handleExplain, handleRemediate, handleChat, handleExecutiveSummary } = require('../controllers/aiController');
const { handleSarifExport, handleMarkdownExport, handleQualityGate } = require('../controllers/exportController');
const { checkRateLimit }    = require('../middleware/rateLimiter');
const { sendError, sendSuccess } = require('../utils/helpers');
const { getRateLimitStatus } = require('../middleware/rateLimiter');
const { subscribe } = require('../scan/progressEmitter');
const fs   = require('fs');
const path = require('path');
const { PUBLIC_DIR } = require('../config/env');


// ─── Static file server ────────────────────────────────────────────────────────
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.mjs':  'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff2':'font/woff2',
  '.woff': 'font/woff',
  '.ttf':  'font/ttf',
  '.webp': 'image/webp',
  '.txt':  'text/plain',
  '.xml':  'application/xml',
};

function serveStatic(req, res) {
  let urlPath = new URL(req.url, 'http://localhost').pathname;
  // Normalize path traversal
  urlPath = path.normalize(urlPath).replace(/^(\.\.(\/|\\|$))+/, '');

  let filePath = path.join(PUBLIC_DIR, urlPath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    // Path traversal attempt
    sendError(res, 403, 'FORBIDDEN', 'Access denied.');
    return;
  }

  try {
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) filePath = path.join(filePath, 'index.html');
  } catch {
    // File not found → SPA fallback
    filePath = path.join(PUBLIC_DIR, 'index.html');
  }

  const ext  = path.extname(filePath).toLowerCase();
  const mime = MIME_TYPES[ext] || 'application/octet-stream';

  try {
    const content = fs.readFileSync(filePath);
    res.setHeader('Content-Type', mime);
    res.writeHead(200);
    res.end(content);
  } catch {
    res.setHeader('Content-Type', 'text/plain');
    res.writeHead(404);
    res.end('Not found');
  }
}

// ─── Main request handler ─────────────────────────────────────────────────────

async function handleRequest(req, res) {
  const parsed   = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsed.pathname;
  const method   = req.method.toUpperCase();
  const isApi    = pathname.startsWith('/api/');

  // 1. Security headers on every response (strict CSP for API, rich CSP for SPA)
  applySecurityHeaders(res, isApi);

  // 2. CORS (returns false if it handled an OPTIONS preflight)
  if (!applyCors(req, res)) return;

  // ── Health ──────────────────────────────────────────────────────────────────
  if (pathname === '/api/health' && method === 'GET') {
    return handleHealth(req, res);
  }

  // ── Integrations Status ─────────────────────────────────────────────────────
  if (pathname === '/api/integrations/status' && method === 'GET') {
    return handleIntegrationsStatus(req, res);
  }

  // ── Security / rate-limit status ────────────────────────────────────────────
  if (pathname === '/api/security-status' && method === 'GET') {
    return sendSuccess(res, {
      status: 'OPERATIONAL',
      shields: {
        ssrfProtection:   'ACTIVE — RFC-1918 + IPv6 private + cloud metadata blocked + redirect re-validation',
        rateLimiting:     'ACTIVE — per-endpoint sliding window (scan: 5/min)',
        concurrencyGuard: 'ACTIVE — per-IP and global concurrent scan limits',
        inputValidation:  'ACTIVE — URL length, scheme blocklist, injection patterns',
        corsPolicy:       'ACTIVE — allowlist-based (no wildcard)',
        securityHeaders:  'ACTIVE — nosniff, DENY, CSP, HSTS, COOP, CORP',
      },
      clientRateLimit: getRateLimitStatus(req, 'general'),
    });
  }

  // ── Scan ────────────────────────────────────────────────────────────────────
  if (pathname === '/api/scan' && (method === 'POST' || method === 'GET')) {
    return handleScan(req, res);
  }

  if (pathname === '/api/scan/status' && method === 'GET') {
    return handleScanStatus(req, res);
  }

  // ── Scan SSE Stream (Server-Sent Events) ────────────────────────────────────
  if (pathname === '/api/scan/stream' && method === 'GET') {
    const scanId = parsed.searchParams.get('scanId');
    if (!scanId) {
      return sendError(res, 400, 'MISSING_SCAN_ID', 'Missing scanId parameter for SSE stream.');
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    res.write(': keepalive\n\n');

    const unsubscribe = subscribe(scanId, (event) => {
      try {
        res.write(`data: ${JSON.stringify(event)}\n\n`);
        if (event.status === 'COMPLETE' || event.status === 'FAILED') {
          setTimeout(() => {
            unsubscribe();
            res.end();
          }, 1000);
        }
      } catch {
        unsubscribe();
      }
    });

    req.on('close', () => {
      unsubscribe();
    });
    return;
  }

  // ── History ─────────────────────────────────────────────────────────────────
  if (pathname === '/api/history' && method === 'GET') {
    return handleHistory(req, res);
  }

  if (pathname === '/api/history/trend' && method === 'GET') {
    return handleDomainTrend(req, res);
  }

  // ── Tech Stack ──────────────────────────────────────────────────────────────
  if ((pathname === '/api/techstack' || pathname === '/api/tech/analyze' || pathname === '/api/tech') && (method === 'GET' || method === 'POST')) {
    if (!checkRateLimit(req, res, 'techstack')) return;
    return handleTechStack(req, res, parsed);
  }

  // ── Domain Recon (Autonomous Perimeter OSINT & Network Probes) ─────────────
  if ((pathname === '/api/domain/recon' || pathname === '/api/recon' || pathname === '/api/webcheck' || pathname === '/api/whatweb') && (method === 'GET' || method === 'POST')) {
    if (!checkRateLimit(req, res, 'techstack')) return;
    return handleDomainRecon(req, res, parsed);
  }

  // ── Benchmark ────────────────────────────────────────────────────────────────
  if (pathname === '/api/benchmark' && method === 'GET') {
    if (!checkRateLimit(req, res, 'benchmark')) return;
    return handleBenchmark(req, res, parsed);
  }

  // ── SEO ─────────────────────────────────────────────────────────────────────
  if (pathname === '/api/seo/analyze' && (method === 'GET' || method === 'POST')) {
    if (!checkRateLimit(req, res, 'seo')) return;
    return handleSeoAnalyze(req, res, parsed);
  }

  if (pathname === '/api/seo/history' && method === 'GET') {
    return handleSeoHistory(req, res);
  }

  // ── Competitive Intelligence ────────────────────────────────────────────────
  if (pathname === '/api/competitive/analyze' && (method === 'GET' || method === 'POST')) {
    if (!checkRateLimit(req, res, 'competitive')) return;
    return handleCompetitiveAnalyze(req, res, parsed);
  }

  if (pathname === '/api/competitive/status' && method === 'GET') {
    return handleCompetitiveStatus(req, res, parsed);
  }

  if (pathname === '/api/competitive/history' && method === 'GET') {
    return handleCompetitiveHistory(req, res);
  }

  if (pathname === '/api/competitive/export' && method === 'GET') {
    return handleCompetitiveExport(req, res, parsed);
  }

  // ── Phase 4: AI Intelligence & Remediation ─────────────────────────────────
  if (pathname === '/api/ai/explain' && method === 'POST') {
    return handleExplain(req, res);
  }

  if (pathname === '/api/ai/remediate' && method === 'POST') {
    return handleRemediate(req, res);
  }

  if (pathname === '/api/ai/chat' && method === 'POST') {
    return handleChat(req, res);
  }

  if (pathname === '/api/ai/executive-summary' && method === 'GET') {
    return handleExecutiveSummary(req, res, parsed);
  }

  // ── Phase 4: DevSecOps Exports & CI Quality Gate ────────────────────────────
  if (pathname === '/api/scan/export/sarif' && method === 'GET') {
    return handleSarifExport(req, res, parsed);
  }

  if (pathname === '/api/scan/export/markdown' && method === 'GET') {
    return handleMarkdownExport(req, res, parsed);
  }

  if (pathname === '/api/scan/gate' && method === 'GET') {
    return handleQualityGate(req, res, parsed);
  }

  // ── Unknown API routes → 404 ─────────────────────────────────────────────────
  if (pathname.startsWith('/api/')) {
    return sendError(res, 404, 'NOT_FOUND', `Unknown API endpoint: ${pathname}`);
  }


  // ── Static / SPA fallback ────────────────────────────────────────────────────
  serveStatic(req, res);
}

module.exports = { handleRequest };
