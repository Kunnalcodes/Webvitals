/**
 * Baseline Engine — Phase 3
 * WebVitals
 *
 * Establishes behavioral baseline response by probing a guaranteed-random non-existent path.
 * Used to detect soft-404s, SPA catch-all routing (React/Vite/Next.js), and reverse-proxy errors.
 */

'use strict';

const crypto = require('crypto');
const { URL } = require('url');
const { collectHttpTelemetry } = require('../telemetry/httpTelemetry');
const { structuralHash } = require('../evidence/evidenceHasher');

/**
 * Probes a guaranteed random path on the target site to establish baseline 404 behavior.
 *
 * @param {URL|string} baseUrl
 * @returns {Promise<object>}
 */
async function establish404Baseline(baseUrl) {
  const urlObj = typeof baseUrl === 'string' ? new URL(baseUrl) : baseUrl;
  const randomProbeToken = `_webvitals_probe_${crypto.randomBytes(8).toString('hex')}`;
  const baselineUrl = new URL(randomProbeToken, urlObj.origin);

  const telemetry = await collectHttpTelemetry(baselineUrl, {
    method: 'GET',
    maxRedirects: 3,
    maxBodyBytes: 64 * 1024,
  });

  const contentType = (telemetry.contentType || '').toLowerCase();
  const isHtml = contentType.includes('text/html');
  const is200 = telemetry.status === 200;
  const structHash = structuralHash(telemetry.bodySnippet);

  const isSpaCatchAll = is200 && isHtml;

  return {
    probeUrl: baselineUrl.toString(),
    status: telemetry.status,
    contentType: telemetry.contentType,
    contentLength: telemetry.contentLength,
    bodyHash: telemetry.bodyHash,
    structuralHash: structHash,
    isSpaCatchAll,
    isSoft404Active: is200,
  };
}

/**
 * Evaluates whether a probe response is actually a soft 404 by comparing it against the baseline.
 *
 * @param {import('../telemetry/httpTelemetry').HttpTelemetry} probeTelemetry
 * @param {object} baseline
 * @returns {{ isSoft404: boolean, reason?: string }}
 */
function isSoft404(probeTelemetry, baseline) {
  if (!probeTelemetry || probeTelemetry.status === null) {
    return { isSoft404: false };
  }

  // If probe returned non-200 (e.g. 404, 403, 500), it is not a false 200
  if (probeTelemetry.status !== 200) {
    return { isSoft404: false };
  }

  if (!baseline) {
    // If no baseline exists, check basic HTML heuristic
    const cType = (probeTelemetry.contentType || '').toLowerCase();
    if (cType.includes('text/html') && (probeTelemetry.bodySnippet.includes('<html') || probeTelemetry.bodySnippet.includes('<!DOCTYPE'))) {
      return { isSoft404: true, reason: 'Returned HTML page without baseline verification' };
    }
    return { isSoft404: false };
  }

  // 1. Exact body hash match with random baseline
  if (baseline.bodyHash && probeTelemetry.bodyHash === baseline.bodyHash) {
    return { isSoft404: true, reason: 'Exact hash match with random non-existent path baseline' };
  }

  // 2. Structural hash match with random baseline (stripping dynamic tokens)
  const probeStructHash = structuralHash(probeTelemetry.bodySnippet);
  if (baseline.structuralHash && probeStructHash === baseline.structuralHash) {
    return { isSoft404: true, reason: 'Structural layout match with random non-existent path baseline' };
  }

  // 3. Baseline is SPA catch-all (200 HTML) and probe returned same content type and HTML shell
  if (baseline.isSpaCatchAll) {
    const cType = (probeTelemetry.contentType || '').toLowerCase();
    if (cType.includes('text/html') && (probeTelemetry.bodySnippet.includes('<div id="root"') || probeTelemetry.bodySnippet.includes('__next') || probeTelemetry.bodySnippet.includes('<!DOCTYPE html>'))) {
      return { isSoft404: true, reason: 'Matched SPA fallback router shell (React/Next.js/Vite)' };
    }
  }

  return { isSoft404: false };
}

module.exports = {
  establish404Baseline,
  isSoft404,
};
