/**
 * Baseline Engine & Sensitive File Signatures Tests — Phase 3
 * WebVitals
 *
 * Tests soft-404 false positive suppression, SPA router detection,
 * signature checks (.env, .git, zip), and secret redaction.
 * Run: node --test backend/tests/phase3/baselineAndSignatures.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { isSoft404 } = require('../../baselines/baselineEngine');
const { SENSITIVE_PROBES, isZipArchive } = require('../../signatures/sensitiveFileSignatures');
const { redactSecrets, hashData, structuralHash } = require('../../evidence/evidenceHasher');

describe('Secret Redaction & Hashing', () => {
  test('redactSecrets masks DB_PASSWORD, API keys and tokens', () => {
    const rawEnv = 'DB_PASSWORD=SuperSecretPass123\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nAPI_KEY=sk_test_1234567890abcdef\n';
    const redacted = redactSecrets(rawEnv);

    assert.ok(!redacted.includes('SuperSecretPass123'));
    assert.ok(!redacted.includes('AKIAIOSFODNN7EXAMPLE'));
    assert.ok(!redacted.includes('sk_test_1234567890abcdef'));
    assert.match(redacted, /DB_PASSWORD=••••••••|DB_PASSWORD=Su••••••••23/);
    assert.match(redacted, /AKIA••••••••••••|AK••••••••LE/);
  });

  test('hashData generates 64-character SHA-256 string', () => {
    const hash = hashData('WebVitals');
    assert.strictEqual(hash.length, 64);
    assert.strictEqual(hash, 'dd49b9ed52b6d2a6de6ffbe917c570c13a07c6b6640b8d27ea13dcac276d89ec');
  });

  test('structuralHash normalizes whitespace and timestamps', () => {
    const html1 = '<html> <body> <div>Error 404</div> </body> </html>';
    const html2 = '<html>\n  <body>\n    <div>Error 404</div>\n  </body>\n</html>';
    assert.strictEqual(structuralHash(html1), structuralHash(html2));
  });
});

describe('Soft 404 & SPA Catch-All Detection', () => {
  test('detects soft 404 when probe matches baseline body hash', () => {
    const baseline = {
      status: 200,
      contentType: 'text/html; charset=utf-8',
      bodyHash: hashData('<html><body>Page Not Found</body></html>'),
      structuralHash: structuralHash('<html><body>Page Not Found</body></html>'),
      isSpaCatchAll: false,
    };

    const probe = {
      status: 200,
      contentType: 'text/html; charset=utf-8',
      bodySnippet: '<html><body>Page Not Found</body></html>',
      bodyHash: hashData('<html><body>Page Not Found</body></html>'),
    };

    const result = isSoft404(probe, baseline);
    assert.strictEqual(result.isSoft404, true);
    assert.match(result.reason, /hash match/i);
  });

  test('detects SPA catch-all shell returning index.html for .env probe', () => {
    const spaShell = '<!DOCTYPE html><html><head><title>App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>';
    const baseline = {
      status: 200,
      contentType: 'text/html; charset=utf-8',
      bodyHash: hashData(spaShell),
      structuralHash: structuralHash(spaShell),
      isSpaCatchAll: true,
    };

    const probeEnv = {
      status: 200,
      contentType: 'text/html',
      bodySnippet: spaShell,
      bodyHash: hashData(spaShell),
    };

    const result = isSoft404(probeEnv, baseline);
    assert.strictEqual(result.isSoft404, true);
  });

  test('does NOT flag genuine .env file as soft 404', () => {
    const baseline = {
      status: 404,
      contentType: 'text/html',
      bodyHash: hashData('<html>404 Not Found</html>'),
      structuralHash: structuralHash('<html>404 Not Found</html>'),
      isSpaCatchAll: false,
    };

    const genuineEnv = {
      status: 200,
      contentType: 'text/plain',
      bodySnippet: 'PORT=8080\nDB_HOST=127.0.0.1\nDB_PASSWORD=secret\n',
      bodyHash: hashData('PORT=8080\nDB_HOST=127.0.0.1\nDB_PASSWORD=secret\n'),
    };

    const result = isSoft404(genuineEnv, baseline);
    assert.strictEqual(result.isSoft404, false);
  });
});

describe('Sensitive File Signatures', () => {
  const envProbe = SENSITIVE_PROBES.find((p) => p.path === '/.env');
  const gitConfigProbe = SENSITIVE_PROBES.find((p) => p.path === '/.git/config');
  const gitHeadProbe = SENSITIVE_PROBES.find((p) => p.path === '/.git/HEAD');
  const zipProbe = SENSITIVE_PROBES.find((p) => p.path === '/backup.zip');

  test('.env signature matches assignment patterns', () => {
    const validEnv = 'DB_PASSWORD=secret\nAPI_KEY=12345';
    assert.strictEqual(envProbe.signatureCheck(validEnv).matched, true);
  });

  test('.env signature rejects empty or invalid body', () => {
    assert.strictEqual(envProbe.signatureCheck('').matched, false);
  });

  test('.git/config signature matches INI structure', () => {
    const gitConfig = '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://github.com/repo.git';
    assert.strictEqual(gitConfigProbe.signatureCheck(gitConfig).matched, true);
  });

  test('.git/HEAD signature matches ref pointer and raw commits', () => {
    assert.strictEqual(gitHeadProbe.signatureCheck('ref: refs/heads/main\n').matched, true);
    assert.strictEqual(gitHeadProbe.signatureCheck('e02422db7db99f2285b6ffeb612538f2a6b9405d').matched, true);
  });

  test('ZIP signature matches PK magic bytes', () => {
    const zipBuffer = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]);
    assert.strictEqual(isZipArchive(zipBuffer.toString('binary')), true);
    assert.strictEqual(zipProbe.signatureCheck(zipBuffer.toString('binary'), {}).matched, true);
  });
});
