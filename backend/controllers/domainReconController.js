/**
 * Domain Reconnaissance Controller
 * Handles /api/domain/recon & /api/webcheck
 */

'use strict';

const { performDomainRecon } = require('../services/domainReconService');
const { sendSuccess, sendError } = require('../utils/helpers');

async function handleDomainRecon(req, res, parsedUrl) {
  let target = parsedUrl?.searchParams?.get('url') || parsedUrl?.searchParams?.get('domain');

  if (!target && (req.method === 'POST' || req.method === 'PUT')) {
    try {
      const body = await new Promise((resolve) => {
        let b = '';
        req.on('data', (c) => (b += c));
        req.on('end', () => resolve(b));
      });
      if (body) {
        const parsed = JSON.parse(body);
        target = parsed.url || parsed.domain || parsed.target;
      }
    } catch {}
  }

  if (!target || typeof target !== 'string' || !target.trim()) {
    return sendError(res, 400, 'INVALID_INPUT', 'Missing or empty "url" / "domain" parameter.');
  }

  try {
    const reconData = await performDomainRecon(target.trim());
    return sendSuccess(res, reconData);
  } catch (err) {
    return sendError(res, 400, 'RECON_FAILED', err.message || 'Failed to perform domain reconnaissance.');
  }
}

module.exports = {
  handleDomainRecon,
};
