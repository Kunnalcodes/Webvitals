/**
 * Competitive Scan Repository — WebVitals 2.0
 *
 * Persists competitive scan reports and provides historical trend lookups.
 */

'use strict';

const { MAX_HISTORY } = require('../config/env');

class CompetitiveRepository {
  constructor() {
    /** @type {Map<string, Object>} scanId -> report */
    this._scans = new Map();
    /** @type {Array<Object>} summary history */
    this._history = [];
  }

  saveScan(report) {
    if (!report?.scanId) return null;
    this._scans.set(report.scanId, report);

    const summary = {
      scanId: report.scanId,
      timestamp: report.timestamp,
      primaryDomain: report.primary?.domain,
      competitorDomain: report.competitor?.domain,
      competitivePosition: report.competitivePosition?.label,
      primaryGeoScore: report.geoComparison?.primaryGeoScore,
      competitorGeoScore: report.geoComparison?.competitorGeoScore,
      primaryAeoScore: report.aeoComparison?.primaryAeoScore,
      competitorAeoScore: report.aeoComparison?.competitorAeoScore,
      totalKeywordsDiscovered: report.keywordIntelligence?.summary?.totalDiscovered || 0,
      totalGaps: report.keywordIntelligence?.summary?.competitorOnlyCount || 0,
    };

    this._history.unshift(summary);
    if (this._history.length > MAX_HISTORY) {
      this._history.length = MAX_HISTORY;
    }

    if (this._scans.size > MAX_HISTORY) {
      const oldestKey = Array.from(this._scans.keys())[0];
      this._scans.delete(oldestKey);
    }

    return report;
  }

  getScan(scanId) {
    return this._scans.get(scanId) || null;
  }

  listHistory(limit = 20) {
    return this._history.slice(0, limit);
  }
}

const defaultCompetitiveRepository = new CompetitiveRepository();

module.exports = {
  CompetitiveRepository,
  defaultCompetitiveRepository,
};
