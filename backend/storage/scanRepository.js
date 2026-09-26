/**
 * Storage Repository Interface + Implementations — Phase 1
 * WebVitals
 *
 * Fixes P1-5: No storage abstraction — historyStore was a global singleton.
 *
 * Pattern: IScanRepository interface with MemoryRepository for dev.
 * FirestoreRepository stub is wired but not yet implemented (Phase 3).
 *
 * Repositories expose:
 *   saveScan(scan)          → scan
 *   getScan(scanId)         → scan | null
 *   listScans(opts)         → scan[]
 *   getDomainTrend(domain)  → trendPoint[]
 *   deleteOldScans(before)  → number deleted
 */

'use strict';

const crypto = require('crypto');
const { MAX_HISTORY, STORAGE_BACKEND } = require('../config/env');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractHostname(urlStr) {
  if (!urlStr) return '';
  try {
    const withProto = /^https?:\/\//i.test(urlStr) ? urlStr : `https://${urlStr}`;
    return new URL(withProto).hostname.replace(/^www\./i, '');
  } catch {
    return (urlStr || '').replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0];
  }
}

// ─── Memory Repository ────────────────────────────────────────────────────────

class MemoryRepository {
  constructor() {
    /** @type {Map<string, object>} scanId → scanRecord */
    this._scans = new Map();

    /** @type {Map<string, object[]>} domain → trendPoint[] */
    this._trends = new Map();

    // Pre-seed popular domain baseline trends for immediate visualization
    const now = Date.now();
    const day = 86400000;
    
    this._trends.set('github.com', [
      { timestamp: new Date(now - 4 * day).toISOString(), score: 88, grade: 'A', classification: 'LOW_RISK', latencyMs: 142, domain: 'github.com' },
      { timestamp: new Date(now - 3 * day).toISOString(), score: 92, grade: 'A+', classification: 'LOW_RISK', latencyMs: 135, domain: 'github.com' },
      { timestamp: new Date(now - 2 * day).toISOString(), score: 90, grade: 'A+', classification: 'LOW_RISK', latencyMs: 128, domain: 'github.com' },
      { timestamp: new Date(now - 1 * day).toISOString(), score: 95, grade: 'A+', classification: 'LOW_RISK', latencyMs: 110, domain: 'github.com' },
    ]);

    this._trends.set('google.com', [
      { timestamp: new Date(now - 4 * day).toISOString(), score: 85, grade: 'A', classification: 'LOW_RISK', latencyMs: 95, domain: 'google.com' },
      { timestamp: new Date(now - 2 * day).toISOString(), score: 89, grade: 'A', classification: 'LOW_RISK', latencyMs: 88, domain: 'google.com' },
      { timestamp: new Date(now - 1 * day).toISOString(), score: 94, grade: 'A+', classification: 'LOW_RISK', latencyMs: 82, domain: 'google.com' },
    ]);

    this._trends.set('amazon.com', [
      { timestamp: new Date(now - 4 * day).toISOString(), score: 76, grade: 'B', classification: 'MODERATE_RISK', latencyMs: 160, domain: 'amazon.com' },
      { timestamp: new Date(now - 2 * day).toISOString(), score: 80, grade: 'A', classification: 'LOW_RISK', latencyMs: 152, domain: 'amazon.com' },
      { timestamp: new Date(now - 1 * day).toISOString(), score: 84, grade: 'A', classification: 'LOW_RISK', latencyMs: 145, domain: 'amazon.com' },
    ]);

    this._trends.set('example.com', [
      { timestamp: new Date(now - 3 * day).toISOString(), score: 55, grade: 'C', classification: 'HIGH_RISK', latencyMs: 110, domain: 'example.com' },
      { timestamp: new Date(now - 2 * day).toISOString(), score: 62, grade: 'C', classification: 'MODERATE_RISK', latencyMs: 105, domain: 'example.com' },
      { timestamp: new Date(now - 1 * day).toISOString(), score: 70, grade: 'B', classification: 'LOW_RISK', latencyMs: 98, domain: 'example.com' },
    ]);

    this._trends.set('threadsecurity.in', [
      { timestamp: new Date(now - 3 * day).toISOString(), score: 65, grade: 'C', classification: 'MODERATE_RISK', latencyMs: 220, domain: 'threadsecurity.in' },
      { timestamp: new Date(now - 1 * day).toISOString(), score: 78, grade: 'B', classification: 'LOW_RISK', latencyMs: 195, domain: 'threadsecurity.in' },
    ]);
  }

  /**
   * Persist a completed scan record.
   * @param {object} scan - Must include scanId, timestamp, finalUrl, score, grade
   */
  saveScan(scan) {
    if (!scan?.scanId) throw new Error('saveScan: scan.scanId is required');

    this._scans.set(scan.scanId, scan);

    // Prune oldest if over limit
    if (this._scans.size > MAX_HISTORY) {
      const oldest = Array.from(this._scans.keys())[0];
      this._scans.delete(oldest);
    }

    // Update domain trend
    const domain = extractHostname(scan.finalUrl || scan.requestedUrl);
    if (domain) {
      if (!this._trends.has(domain)) this._trends.set(domain, []);
      const trend = this._trends.get(domain);
      trend.push({
        timestamp:      scan.timestamp,
        score:          scan.score,
        grade:          scan.grade,
        classification: scan.classification,
        latencyMs:      scan.scanTimeMs || null,
        url:            scan.finalUrl || scan.requestedUrl,
        domain,
      });
      // Keep last 30 data points per domain
      if (trend.length > 30) trend.shift();
    }

    return scan;
  }

  /**
   * Retrieve a single scan by ID.
   */
  getScan(scanId) {
    return this._scans.get(scanId) || null;
  }

  /**
   * Alias for listScans for backward compatibility.
   */
  getRecentScans(limit = 30) {
    return this.listScans({ limit });
  }

  /**
   * List recent scans, newest first.
   * @param {{ limit?: number, domain?: string }} opts
   */
  listScans({ limit = 50, domain } = {}) {
    let records = Array.from(this._scans.values()).reverse();
    if (domain) {
      const h = extractHostname(domain);
      records = records.filter((r) => {
        const rh = extractHostname(r.finalUrl || r.requestedUrl);
        return rh === h || rh.includes(h) || h.includes(rh);
      });
    }
    return records.slice(0, limit);
  }

  /**
   * Return historical score trend for a domain.
   */
  getDomainTrend(domainOrUrl) {
    if (!domainOrUrl) return [];
    const domain = extractHostname(domainOrUrl);

    if (this._trends.has(domain)) return this._trends.get(domain);

    // Case-insensitive fuzzy match
    for (const [key, val] of this._trends.entries()) {
      if (key.toLowerCase() === domain.toLowerCase()) return val;
    }
    return [];
  }

  /**
   * Return all tracked domains.
   */
  listDomains() {
    return Array.from(this._trends.keys());
  }

  /**
   * Delete scans older than a given Date. Returns count deleted.
   */
  deleteOldScans(before) {
    const cutoff = before instanceof Date ? before.getTime() : Number(before);
    let deleted = 0;
    for (const [id, scan] of this._scans.entries()) {
      const ts = new Date(scan.timestamp).getTime();
      if (ts < cutoff) {
        this._scans.delete(id);
        deleted++;
      }
    }
    return deleted;
  }
}

// ─── Firestore Repository Stub (Phase 3) ──────────────────────────────────────
class FirestoreRepository {
  constructor() {
    console.warn('[WebVitals] FirestoreRepository: Not yet implemented. Falling back to MemoryRepository.');
    return new MemoryRepository();
  }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

function createRepository() {
  if (STORAGE_BACKEND === 'firestore') {
    return new FirestoreRepository();
  }
  return new MemoryRepository();
}

// Export a singleton instance
const scanRepository = createRepository();

module.exports = {
  scanRepository,
  MemoryRepository,
  FirestoreRepository,
  extractHostname,
};
