/**
 * Sensitive File Signatures & Content Matcher — Phase 3
 * WebVitals
 *
 * Defines probe paths, byte/text signatures, MIME filters, and risk levels
 * to strictly prevent false positives on soft-404 and SPA catch-all servers.
 */

'use strict';

const { redactSecrets } = require('../evidence/evidenceHasher');

/**
 * Validates ZIP magic header (0x50 0x4B / PK)
 * @param {string|Buffer} body
 */
function isZipArchive(body) {
  if (!body) return false;
  const str = typeof body === 'string' ? body : body.toString('binary');
  // 'PK' header (0x50 0x4B 0x03 0x04 or 0x50 0x4B 0x05 0x06)
  return str.startsWith('PK\x03\x04') || str.startsWith('PK\x05\x06') || str.startsWith('PK');
}

/**
 * Signature rules for sensitive file probes
 */
const SENSITIVE_PROBES = [
  {
    path: '/.env',
    name: 'Environment Configuration File (.env)',
    risk: 'CRITICAL',
    disallowHtml: true,
    signatureCheck: (body) => {
      if (!body) return { matched: false };
      // Check common .env assignment patterns
      const envPattern = /^(?:[A-Z0-9_-]+=(?:[^\r\n]*))$/m;
      const keyHits = body.match(/(?:DB_PASSWORD|DATABASE_URL|APP_KEY|SECRET|AWS_ACCESS_KEY|API_KEY|REDIS_URL|JWT_SECRET)=/i);
      const isMatch = envPattern.test(body) || keyHits !== null;
      return {
        matched: Boolean(isMatch),
        signature: 'ENV_KEY_ASSIGNMENTS',
        snippet: redactSecrets(body.slice(0, 300)),
      };
    },
  },
  {
    path: '/.git/config',
    name: 'Git Repository Config (.git/config)',
    risk: 'CRITICAL',
    disallowHtml: true,
    signatureCheck: (body) => {
      if (!body) return { matched: false };
      const hasCore = body.includes('[core]');
      const hasRemote = body.includes('[remote "') || body.includes('repositoryformatversion');
      const isMatch = hasCore && (hasRemote || body.includes('filemode'));
      return {
        matched: isMatch,
        signature: 'GIT_INI_CONFIG',
        snippet: redactSecrets(body.slice(0, 300)),
      };
    },
  },
  {
    path: '/.git/HEAD',
    name: 'Git HEAD Pointer (.git/HEAD)',
    risk: 'HIGH',
    disallowHtml: true,
    signatureCheck: (body) => {
      if (!body) return { matched: false };
      const clean = body.trim();
      const isRef = clean.startsWith('ref: refs/heads/') || clean.startsWith('ref: refs/tags/');
      const isSha = /^[0-9a-f]{40}$/i.test(clean);
      const isMatch = isRef || isSha;
      return {
        matched: isMatch,
        signature: 'GIT_HEAD_REF',
        snippet: clean.slice(0, 100),
      };
    },
  },
  {
    path: '/.htaccess',
    name: 'Apache Configuration (.htaccess)',
    risk: 'HIGH',
    disallowHtml: true,
    signatureCheck: (body) => {
      if (!body) return { matched: false };
      const isMatch = /RewriteEngine|RewriteRule|AuthType|Order\s+allow,deny|Deny\s+from|AllowOverride/i.test(body);
      return {
        matched: isMatch,
        signature: 'APACHE_HTACCESS_DIRECTIVES',
        snippet: body.slice(0, 300),
      };
    },
  },
  {
    path: '/config.php.bak',
    name: 'PHP/Database Configuration Backup (config.php.bak)',
    risk: 'CRITICAL',
    disallowHtml: true,
    signatureCheck: (body) => {
      if (!body) return { matched: false };
      const hasPhp = body.includes('<?php');
      const hasSecrets = /\$db|\$password|\$user|DB_NAME|DB_PASSWORD/i.test(body);
      const isMatch = hasPhp && hasSecrets;
      return {
        matched: isMatch,
        signature: 'PHP_CONFIG_BACKUP',
        snippet: redactSecrets(body.slice(0, 300)),
      };
    },
  },
  {
    path: '/backup.zip',
    name: 'Source Archive File (backup.zip)',
    risk: 'CRITICAL',
    disallowHtml: true,
    signatureCheck: (body, headers) => {
      const cType = (headers['content-type'] || '').toLowerCase();
      const isZip = isZipArchive(body) || cType.includes('application/zip') || cType.includes('application/x-zip-compressed');
      return {
        matched: isZip,
        signature: 'ZIP_MAGIC_ARCHIVE',
        snippet: '[Binary ZIP Archive Header PK\x03\x04]',
      };
    },
  },
  {
    path: '/robots.txt',
    name: 'Robots Directive File (robots.txt)',
    risk: 'INFO',
    disallowHtml: false,
    signatureCheck: (body) => {
      if (!body) return { matched: false };
      const isMatch = /User-agent:\s*[*a-zA-Z0-9_-]+/i.test(body) || /Disallow:\s*\/[^\r\n]*/i.test(body);
      return {
        matched: isMatch,
        signature: 'ROBOTS_TXT_DIRECTIVES',
        snippet: body.slice(0, 300),
      };
    },
  },
];

module.exports = {
  SENSITIVE_PROBES,
  isZipArchive,
};
