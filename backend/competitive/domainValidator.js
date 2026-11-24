/**
 * Competitive Domain Validator & Normalizer — WebVitals 2.0
 *
 * Validates, normalizes, and secures target URLs for competitive analysis:
 *   - Normalizes protocol, host, and path
 *   - Enforces SSRF and restricted IP protections via abuseProtection
 *   - Verifies primary and competitor URLs are distinct entities
 *   - Cleans display names and domain labels
 */

'use strict';

const { URL } = require('url');
const { validateTargetUrl, isRestrictedHost } = require('../middleware/abuseProtection');

/**
 * Normalizes and validates a target URL string.
 *
 * @param {string} rawInput
 * @param {string} label - 'Primary' or 'Competitor'
 * @returns {Object} { isValid, url, hostname, domain, error }
 */
function validateAndNormalizeTarget(rawInput, label = 'Target') {
  if (!rawInput || typeof rawInput !== 'string' || !rawInput.trim()) {
    return {
      isValid: false,
      error: `${label} website URL or domain is required.`,
    };
  }

  let cleaned = rawInput.trim();
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = `https://${cleaned}`;
  }

  // Enforce WebVitals SSRF & abuse filter
  const ssrfCheck = validateTargetUrl(cleaned);
  if (!ssrfCheck.valid) {
    return {
      isValid: false,
      error: `${label} website rejected: ${ssrfCheck.reason}`,
    };
  }

  try {
    const parsed = new URL(ssrfCheck.normalizedUrl || cleaned);
    const hostname = parsed.hostname.toLowerCase();

    if (isRestrictedHost(hostname)) {
      return {
        isValid: false,
        error: `${label} hostname (${hostname}) is restricted or non-public.`,
      };
    }

    const domain = hostname.replace(/^www\./i, '');
    const cleanUrl = `${parsed.protocol}//${hostname}${parsed.pathname === '/' ? '' : parsed.pathname}`;

    return {
      isValid: true,
      url: cleanUrl,
      rawUrl: rawInput,
      hostname,
      domain,
      label,
    };
  } catch (err) {
    return {
      isValid: false,
      error: `Malformed ${label} URL: ${err.message}`,
    };
  }
}

/**
 * Validates both Primary and Competitor inputs together.
 *
 * @param {string} primaryInput
 * @param {string} competitorInput
 * @param {Object} [options]
 * @returns {Object} { isValid, primary, competitor, options, error }
 */
function validateCompetitivePair(primaryInput, competitorInput, options = {}) {
  const primary = validateAndNormalizeTarget(primaryInput, 'Primary');
  if (!primary.isValid) {
    return { isValid: false, error: primary.error };
  }

  const competitor = validateAndNormalizeTarget(competitorInput, 'Competitor');
  if (!competitor.isValid) {
    return { isValid: false, error: competitor.error };
  }

  if (primary.domain === competitor.domain) {
    return {
      isValid: false,
      error: `Primary and Competitor cannot be the same domain (${primary.domain}). Please provide a distinct competitor website.`,
    };
  }

  return {
    isValid: true,
    primary,
    competitor,
    options: {
      businessName: (options.businessName || primary.domain.split('.')[0] || '').trim(),
      targetLocation: (options.targetLocation || options.location || 'Global').trim(),
      targetCountry: (options.targetCountry || options.country || 'Global').trim(),
      targetLanguage: (options.targetLanguage || options.language || 'English').trim(),
      industry: (options.industry || options.category || 'General Web Asset').trim(),
      businessObjectives: Array.isArray(options.businessObjectives) ? options.businessObjectives : [],
    },
  };
}

module.exports = {
  validateAndNormalizeTarget,
  validateCompetitivePair,
};
