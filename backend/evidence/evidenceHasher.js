/**
 * Evidence Hasher & Secret Redactor — Phase 3
 * WebVitals
 *
 * Provides cryptographic response hashing for baseline comparison
 * and strict secret redaction to prevent token disclosure.
 */

'use strict';

const crypto = require('crypto');

/**
 * Computes a SHA-256 hex hash of a string or Buffer.
 *
 * @param {string|Buffer} data
 * @returns {string} SHA-256 64-char hex string
 */
function hashData(data) {
  if (!data) return '';
  return crypto
    .createHash('sha256')
    .update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
    .digest('hex');
}

/**
 * Computes a normalized structural hash of text/HTML content
 * by stripping variable timestamps, session IDs, and excessive whitespace.
 *
 * @param {string} text
 * @returns {string} Normalized hash
 */
function structuralHash(text) {
  if (!text || typeof text !== 'string') return '';
  const normalized = text
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/csrf[-_]?token\s*=\s*['"][a-f0-9]+['"]/gi, '')
    .replace(/nonce\s*=\s*['"][a-z0-9+/=]+['"]/gi, '')
    .replace(/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}/g, '')
    .trim();
  return hashData(normalized);
}

// Patterns of sensitive values to redact in evidence
const SENSITIVE_PATTERNS = [
  // Key=Value assignments
  /((?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|DATABASE_URL|AUTH|JWT|KEY)\s*[:=]\s*)([^\s\r\n"';]+)/gi,
  // Bearer tokens
  /(Bearer\s+)([a-zA-Z0-9_\-\.]{15,})/gi,
  // AWS Keys (AKIA...)
  /(AKIA[0-9A-Z]{16})/g,
  // Generic Private Key headers
  /(-----BEGIN [A-Z ]+ PRIVATE KEY-----)[\s\S]+?(-----END [A-Z ]+ PRIVATE KEY-----)/g,
];

/**
 * Redacts passwords, API keys, private keys, and tokens from sensitive findings.
 *
 * @param {string} text
 * @returns {string} Sanitized string safe for reporting
 */
function redactSecrets(text) {
  if (!text || typeof text !== 'string') return text;
  let result = text;

  // Mask Key=Value secrets
  result = result.replace(
    /((?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|DATABASE_URL|AUTH|JWT|KEY)\s*[:=]\s*)([^\s\r\n"';]+)/gi,
    (match, prefix, value) => {
      if (value.length <= 4) return `${prefix}••••••••`;
      return `${prefix}${value.slice(0, 2)}••••••••${value.slice(-2)}`;
    }
  );

  // Mask Bearer tokens
  result = result.replace(/(Bearer\s+)([a-zA-Z0-9_\-\.]{15,})/gi, '$1••••••••');

  // Mask AWS Keys
  result = result.replace(/(AKIA[0-9A-Z]{16})/g, (match) => `${match.slice(0, 4)}••••••••••••`);

  // Mask PEM private keys
  result = result.replace(
    /(-----BEGIN [A-Z ]+ PRIVATE KEY-----)[\s\S]+?(-----END [A-Z ]+ PRIVATE KEY-----)/g,
    '$1\n[REDACTED PRIVATE KEY MATERIAL]\n$2'
  );

  return result;
}

module.exports = {
  hashData,
  structuralHash,
  redactSecrets,
};
