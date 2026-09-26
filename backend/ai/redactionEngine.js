/**
 * AI Redaction Engine — Phase 4
 * WebVitals
 *
 * Strict sanitization firewall that strips secrets, authentication tokens,
 * passwords, internal IP addresses, database URLs, and private keys from any data
 * before it can be processed by LLMs or logged.
 */

'use strict';

const SENSITIVE_KEY_REGEX = /^(?:authorization|cookie|set-cookie|x-api-key|secret|token|password|passwd|api_key|apikey|jwt|bearer|private_key)$/i;

// Regex patterns to redact in raw text strings
const TEXT_REDACTION_PATTERNS = [
  // 1. Key=Value or Key: Value assignments
  {
    regex: /((?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|DATABASE_URL|AUTH|JWT|KEY)\s*[:=]\s*)([^\s\r\n"';]+)/gi,
    replace: '$1<REDACTED_SECRET>',
  },
  // 2. Authorization / Bearer headers
  {
    regex: /(Bearer\s+)([a-zA-Z0-9_\-\.]{15,})/gi,
    replace: '$1<REDACTED_BEARER_TOKEN>',
  },
  // 3. JWT Tokens (header.payload.signature)
  {
    regex: /(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})/g,
    replace: '<REDACTED_JWT_TOKEN>',
  },
  // 4. AWS Access Keys
  {
    regex: /(AKIA[0-9A-Z]{16})/g,
    replace: '<REDACTED_AWS_KEY>',
  },
  // 5. Private Keys
  {
    regex: /(-----BEGIN [A-Z ]+ PRIVATE KEY-----)[\s\S]+?(-----END [A-Z ]+ PRIVATE KEY-----)/g,
    replace: '$1\n<REDACTED_PRIVATE_KEY_MATERIAL>\n$2',
  },
  // 6. DB Connection Strings (postgres://, mysql://, mongodb://)
  {
    regex: /((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s]+:)([^@\s]+)(@[^\s]+)/gi,
    replace: '$1<REDACTED_PASSWORD>$3',
  },
  // 7. Internal / RFC-1918 IP addresses
  {
    regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/g,
    replace: '<REDACTED_INTERNAL_IP>',
  },
];

/**
 * Redacts sensitive patterns from a raw text string.
 *
 * @param {string} text
 * @returns {string} Sanitized string
 */
function redactText(text) {
  if (!text || typeof text !== 'string') return text;
  let result = text;
  for (const { regex, replace } of TEXT_REDACTION_PATTERNS) {
    result = result.replace(regex, replace);
  }
  return result;
}

/**
 * Deeply sanitizes and redacts an arbitrary object or array.
 *
 * @param {*} value
 * @param {number} [depth=0]
 * @returns {*} Sanitized copy
 */
function redactObject(value, depth = 0) {
  if (depth > 8) return '<DEPTH_LIMIT_EXCEEDED>';
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') {
    return redactText(value);
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactObject(item, depth + 1));
  }

  if (typeof value === 'object') {
    const sanitized = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_KEY_REGEX.test(k)) {
        sanitized[k] = '<REDACTED_SENSITIVE_FIELD>';
      } else {
        sanitized[k] = redactObject(v, depth + 1);
      }
    }
    return sanitized;
  }

  return String(value);
}

module.exports = {
  redactText,
  redactObject,
};
