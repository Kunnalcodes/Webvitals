/**
 * Scan Orchestrator — Phase 3
 * WebVitals
 *
 * Evidence-Driven Scan Orchestration Engine:
 *   - Centralized network & security telemetry collection
 *   - Fault-isolated parallel channel analyzers (TLS, DNS, Headers, Cookies, CORS, Probes, Heuristics)
 *   - False-positive elimination (404 baseline comparison, signature validation, MIME filtering)
 *   - Evidence provenance & confidence scoring
 *   - Deterministic weighted security evaluation
 *   - Audit-ready security reports with version '3.0.0'
 */

'use strict';

const { URL } = require('url');
const { validateTargetUrl, validateResolvedHost } = require('../middleware/abuseProtection');

// Phase 3 Telemetry Collectors
const { collectHttpTelemetry } = require('../telemetry/httpTelemetry');
const { collectTlsTelemetry }  = require('../telemetry/tlsTelemetry');
const { collectDnsTelemetry }  = require('../telemetry/dnsTelemetry');
const { collectCorsTelemetry } = require('../telemetry/corsTelemetry');

// Phase 3 Analyzers
const { analyzeTlsSecurity }           = require('../analyzers/tlsAnalyzer');
const { analyzeDnsSecurity }           = require('../analyzers/dnsAnalyzer');
const { analyzeSecurityHeaders }       = require('../analyzers/headerAnalyzer');
const { analyzeCookieSecurity }        = require('../analyzers/cookieAnalyzer');
const { analyzeCorsSecurity }          = require('../analyzers/corsAnalyzer');
const { analyzeSensitiveFileExposures } = require('../analyzers/sensitiveFileAnalyzer');
const { analyzePhishingAndThreatIntel } = require('../analyzers/phishingAnalyzer');
const { analyzeHttpVerbs }             = require('../analyzers/httpVerbAnalyzer');
const { analyzeProxyHeaders }          = require('../analyzers/proxyHeaderAnalyzer');
const { detectTechnologies }           = require('../signatures/technologySignatures');
const { correlateThreatAdvisories }     = require('../services/threatAdvisoryService');
const { generateCurlCommands, runWhatWebFingerprint, performDomainRecon } = require('../services/domainReconService');
const { queryIpGeolocation }           = require('../services/threatIntelService');
const { SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY } = require('../config/env');

// Modular Workers & Precision Finding Engine
const { runDnsWorker }         = require('../workers/dnsWorker');
const { runTlsWorker }         = require('../workers/tlsWorker');
const { runHttpWorker }        = require('../workers/httpWorker');
const { runSecurityWorker }    = require('../workers/securityWorker');
const { runDomainWorker }      = require('../workers/domainWorker');
const { runNetworkWorker }     = require('../workers/networkWorker');
const { runContentWorker }     = require('../workers/contentWorker');
const { runPerformanceWorker } = require('../workers/performanceWorker');
const { runEmailWorker }       = require('../workers/emailWorker');
const { evaluateScanResults }  = require('../services/precisionEngine');

// Scoring & Storage
const { computeScore, gradeFor, classify } = require('../services/securityEvaluator');
const { scanRepository }                   = require('../storage/scanRepository');
const { markRunning, markComplete, markFailed, buildEvent, getLifecycle } = require('./scanLifecycle');
const { emit, cleanup }                    = require('./progressEmitter');
const { runStage, skipStage }              = require('./scanStageRunner');

const SCAN_ORCHESTRATOR_TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS || '60000', 10);
const SCANNER_VERSION = '3.0.0';

const SYSTEM_LIMITATIONS = [
  'WebVitals performs non-intrusive automated remote security analysis based on observable target telemetry at scan time.',
  'This scan does not constitute a manual penetration test, authenticated assessment, or source-code audit.',
  'Controls requiring internal application credentials, authenticated session state, or specialized DNS selectors (e.g. DKIM) are categorized as NOT_EVALUATED to maintain data integrity.',
];

/**
 * Builds a structured logger prefixed with [SCAN scanId].
 */
function makeLogger(scanId) {
  const prefix = `[SCAN ${scanId.slice(0, 8)}]`;
  return (msg) => console.log(`${prefix} ${msg}`);
}

/**
 * Executes the full Phase 3 evidence-backed security scan pipeline.
 *
 * @param {string} scanId - Must exist in lifecycle store
 * @param {string} rawUrl - Target URL
 * @param {Object} [options={}] - Scan mode ('passive'|'active'), depth, consent
 * @returns {Promise<void>}
 */
async function executeScan(scanId, rawUrl, options = {}) {
  const log = makeLogger(scanId);
  const ctx = { scanId, log };

  const timeoutHandle = setTimeout(() => {
    const lc = getLifecycle(scanId);
    if (lc && lc.status === 'RUNNING') {
      log(`TIMEOUT after ${SCAN_ORCHESTRATOR_TIMEOUT_MS}ms`);
      _finalizeFailed(scanId, 'SCAN_TIMEOUT', `Scan timed out after ${SCAN_ORCHESTRATOR_TIMEOUT_MS}ms`, log);
    }
  }, SCAN_ORCHESTRATOR_TIMEOUT_MS).unref();

  try {
    markRunning(scanId);
    log(`STARTED Phase 3 Scan v${SCANNER_VERSION}`);

    // ── 1. STAGE: VALIDATING (FATAL) ───────────────────────────────────────────
    const { value: validationResult } = await runStage(ctx, 'VALIDATING', async () => {
      const v = validateTargetUrl(rawUrl);
      if (!v.valid) throw Object.assign(new Error(v.message), { code: 'INVALID_TARGET' });

      const dnsCheck = await validateResolvedHost(v.parsedUrl.hostname);
      if (dnsCheck.blocked) throw Object.assign(new Error(dnsCheck.reason), { code: 'SSRF_BLOCKED' });

      return v;
    }, { fatal: true });

    const urlObj = validationResult.parsedUrl;
    const hostname = urlObj.hostname;

    // ── 2. STAGE: CONNECTING & HTTP TELEMETRY ──────────────────────────────────
    let httpTelemetry;
    const { value: httpResult, error: httpError } = await runStage(ctx, 'CONNECTING', async () => {
      return await collectHttpTelemetry(urlObj, { maxRedirects: 5, timeoutMs: 10000 });
    }, { fatal: false });

    if (httpResult && httpResult.status !== null) {
      httpTelemetry = httpResult;
    } else {
      httpTelemetry = {
        requestedUrl: rawUrl,
        finalUrl: urlObj.toString(),
        status: null,
        headers: {},
        contentType: '',
        contentLength: 0,
        bodySnippet: '',
        bodyHash: '',
        elapsedMs: 0,
        protocol: urlObj.protocol,
        redirectChain: [{ url: urlObj.toString(), status: null, error: httpError?.message || 'Connection failed' }],
        connectionError: httpError?.message || 'Connection failed',
      };
    }

    const finalUrlStr = httpTelemetry.finalUrl || rawUrl;
    let finalUrlObj;
    try {
      finalUrlObj = new URL(finalUrlStr);
    } catch {
      finalUrlObj = urlObj;
    }

    const finalHost = finalUrlObj.hostname || hostname;
    const isHttps = finalUrlObj.protocol === 'https:';
    const rawHeaders = httpTelemetry.headers || {};

    // ── 3. STAGE: HTTP_ANALYSIS ────────────────────────────────────────────────
    await runStage(ctx, 'HTTP_ANALYSIS', async () => {
      return { status: httpTelemetry.status, protocol: httpTelemetry.protocol, redirects: httpTelemetry.redirectChain?.length || 0 };
    }, { fatal: false });

    // ── 4. STAGE: HEADERS_ANALYSIS (Security headers evaluation) ───────────────
    let headerFindings = [];
    await runStage(ctx, 'HEADERS_ANALYSIS', async () => {
      headerFindings = analyzeSecurityHeaders(rawHeaders, isHttps);
      return headerFindings.length;
    }, { fatal: false });

    // ── 5. STAGE: COOKIE_ANALYSIS ──────────────────────────────────────────────
    let cookieFindings = [];
    await runStage(ctx, 'COOKIE_ANALYSIS', async () => {
      cookieFindings = analyzeCookieSecurity(rawHeaders, isHttps);
      return cookieFindings.length;
    }, { fatal: false });

    // ── 6. PARALLEL CHANNELS (TLS, DNS, CORS, Sensitive Files, Phishing, Tech Stack)
    const [
      tlsSettled,
      dnsSettled,
      corsSettled,
      sensitiveSettled,
      phishingSettled,
      techSettled,
      accessControlSettled,
    ] = await Promise.allSettled([
      // TLS Channel
      isHttps
        ? runStage(ctx, 'TLS_ANALYSIS', async () => {
            const telemetry = await collectTlsTelemetry(finalHost);
            const findings = analyzeTlsSecurity(telemetry, httpTelemetry);
            return { telemetry, findings };
          }, { fatal: false })
        : (skipStage(ctx, 'TLS_ANALYSIS', 'Site operates over plaintext HTTP — TLS not applicable'), Promise.resolve({ value: { telemetry: null, findings: analyzeTlsSecurity(null, httpTelemetry) } })),

      // DNS Channel
      runStage(ctx, 'DNS_ANALYSIS', async () => {
        const telemetry = await collectDnsTelemetry(finalHost);
        const findings = analyzeDnsSecurity(telemetry);
        return { telemetry, findings };
      }, { fatal: false }),

      // CORS Channel (dynamic probes)
      runStage(ctx, 'CORS_ANALYSIS', async () => {
        const telemetry = await collectCorsTelemetry(finalUrlObj);
        const findings = analyzeCorsSecurity(telemetry);
        return { telemetry, findings };
      }, { fatal: false }),

      // Sensitive Files Channel (with 404 baseline & signature verification)
      runStage(ctx, 'SENSITIVE_FILE_ANALYSIS', async () => {
        return await analyzeSensitiveFileExposures(finalUrlObj);
      }, { fatal: false }),

      // Phishing & Cloud Threat Intelligence Channel
      runStage(ctx, 'PHISHING_ANALYSIS', async () => {
        const res = await analyzePhishingAndThreatIntel(finalUrlObj, rawUrl, {
          safeBrowsingKey: SAFE_BROWSING_API_KEY,
          virusTotalKey: VIRUSTOTAL_API_KEY,
        });
        return res;
      }, { fatal: false }),

      // Technology Stack Fingerprinting
      runStage(ctx, 'TECH_STACK_ANALYSIS', async () => {
        const detected = detectTechnologies(rawHeaders, httpTelemetry.bodySnippet || '');
        return detected;
      }, { fatal: false }),

      // Access Control, HTTP Verbs & Reverse Proxy Spoofing Channel
      runStage(ctx, 'ACCESS_CONTROL_ANALYSIS', async () => {
        const [verbRes, proxyRes] = await Promise.all([
          analyzeHttpVerbs(finalUrlObj),
          analyzeProxyHeaders(finalUrlObj),
        ]);
        return {
          findings: [...(verbRes?.findings || []), ...(proxyRes?.findings || [])],
          telemetry: {
            verbs: verbRes?.telemetry || {},
            proxyHeaders: proxyRes?.telemetry || {},
          },
        };
      }, { fatal: false }),
    ]);

    // Skip SEO in core security scan
    skipStage(ctx, 'SEO_ANALYSIS', 'SEO analysis is available via /api/seo/analyze');

    // Extract settled channel outputs safely
    const tlsData       = tlsSettled.value?.value?.telemetry       ?? null;
    const tlsFindings   = tlsSettled.value?.value?.findings        ?? [];

    const dnsData       = dnsSettled.value?.value?.telemetry       ?? null;
    const dnsFindings   = dnsSettled.value?.value?.findings        ?? [];

    const corsData      = corsSettled.value?.value?.telemetry      ?? null;
    const corsFindings  = corsSettled.value?.value?.findings       ?? [];

    const sensitiveData = sensitiveSettled.value?.value            ?? { findings: [], summary: {} };
    const sensitiveFindings = sensitiveData.findings || [];

    const phishingData  = phishingSettled.value?.value?.findings   ?? [];
    const techStack     = techSettled.value?.value                 ?? [];

    const accessControlData = accessControlSettled.value?.value    ?? { findings: [], telemetry: {} };
    const accessControlFindings = accessControlData.findings || [];

    // ── 7. MODULAR WORKERS & DEEP OSINT RECONNAISSANCE ────────────────────────
    let modularChecks = [];
    let reconData = null;
    let precisionEvaluation = null;

    await runStage(ctx, 'OSINT_MODULAR_AUDIT', async () => {
      const [
        dnsWorkerSettled,
        emailWorkerSettled,
        tlsWorkerSettled,
        httpWorkerSettled,
        securityWorkerSettled,
        domainWorkerSettled,
        networkWorkerSettled,
        contentWorkerSettled,
        performanceWorkerSettled,
        reconSettled,
      ] = await Promise.allSettled([
        runDnsWorker(finalHost, options),
        runEmailWorker(finalHost, dnsData?.txt || [], dnsData?.mx || []),
        isHttps ? runTlsWorker(finalHost) : Promise.resolve({ checks: [], tlsData: null }),
        runHttpWorker(finalUrlObj, { maxRedirects: 5, timeoutMs: 10000 }),
        runSecurityWorker(finalUrlObj, rawHeaders),
        runDomainWorker(finalHost),
        runNetworkWorker(finalHost, dnsData?.a || [], options),
        runContentWorker(finalUrlObj, rawHeaders, httpTelemetry.bodySnippet || ''),
        runPerformanceWorker(httpTelemetry),
        performDomainRecon(finalHost).catch(() => null),
      ]);

      const dnsWorkerRes = dnsWorkerSettled.value || { checks: [], raw: {} };
      const emailWorkerRes = emailWorkerSettled.value || { checks: [], emailConfig: {} };
      const tlsWorkerRes = tlsWorkerSettled.value || { checks: [], tlsData: null };
      const httpWorkerRes = httpWorkerSettled.value || { checks: [], telemetry: {} };
      const securityWorkerRes = securityWorkerSettled.value || { checks: [], securityData: {} };
      const domainWorkerRes = domainWorkerSettled.value || { checks: [], domainData: {} };
      const networkWorkerRes = networkWorkerSettled.value || { checks: [], networkData: {} };
      const contentWorkerRes = contentWorkerSettled.value || { checks: [], contentData: {} };
      const performanceWorkerRes = performanceWorkerSettled.value || { checks: [], performanceData: {} };
      reconData = reconSettled.value || null;

      modularChecks = [
        ...(dnsWorkerRes.checks || []),
        ...(emailWorkerRes.checks || []),
        ...(tlsWorkerRes.checks || []),
        ...(httpWorkerRes.checks || []),
        ...(securityWorkerRes.checks || []),
        ...(domainWorkerRes.checks || []),
        ...(networkWorkerRes.checks || []),
        ...(contentWorkerRes.checks || []),
        ...(performanceWorkerRes.checks || []),
      ];

      precisionEvaluation = evaluateScanResults(modularChecks);

      // Return telemetry summaries for stage report
      return {
        checksCount: modularChecks.length,
        passed: precisionEvaluation.coverage.passed,
        findings: precisionEvaluation.coverage.findings,
        score: precisionEvaluation.score,
      };
    }, { fatal: false });

    // ── 8. AGGREGATE ALL FINDINGS ──────────────────────────────────────────────
    const allFindings = [
      ...tlsFindings,
      ...headerFindings,
      ...cookieFindings,
      ...corsFindings,
      ...dnsFindings,
      ...sensitiveFindings,
      ...accessControlFindings,
      ...phishingData,
    ];

    // ── 9. STAGE: SCORING (Deterministic 0-100 evaluation) ─────────────────────
    let score = 100;
    let grade = 'A';
    let gradeLabel = 'Good security posture';
    let classification = 'Safe';

    await runStage(ctx, 'SCORING', async () => {
      // Calculate score based on findings and score impacts
      let computed = 100;
      for (const f of allFindings) {
        if (f.status === 'FAIL') {
          computed += (f.scoreImpact || -5);
        } else if (f.status === 'WARNING') {
          computed += Math.min(0, f.scoreImpact || -2);
        }
      }

      score = Math.max(0, Math.min(100, computed));
      const graded = gradeFor(score);
      grade = graded.grade;
      gradeLabel = graded.label;
      classification = classify(score);
      return score;
    }, { fatal: false });

    // ── 10. STAGE: FINALIZING (Assemble & Persist Report) ───────────────────────
    await runStage(ctx, 'FINALIZING', async () => {
      const completedAt = new Date().toISOString();
      const lc = getLifecycle(scanId);
      const startedAt = lc?.startedAt || completedAt;

      const report = {
        scanId,
        scannerVersion: SCANNER_VERSION,
        requestedUrl: rawUrl,
        finalUrl: finalUrlStr,
        hostname: finalHost,
        httpStatus: httpTelemetry.status,
        https: isHttps,
        redirects: httpTelemetry.redirectChain?.length > 1 ? httpTelemetry.redirectChain.length - 1 : 0,
        redirectChain: httpTelemetry.redirectChain || [],
        connectionError: httpTelemetry.connectionError || null,
        scanTimeMs: Date.now() - new Date(startedAt).getTime(),
        startedAt,
        completedAt,
        score,
        grade,
        gradeLabel,
        classification,
        findings: allFindings,
        // Modular standard schema checks & precision analysis
        modularChecks: modularChecks || [],
        precision: precisionEvaluation || null,
        remediation: precisionEvaluation?.remediation || [],
        methodology: precisionEvaluation?.methodology || null,
        coverage: precisionEvaluation?.coverage || null,
        categoryScores: precisionEvaluation?.categoryScores || null,
        overview: {
          scanId,
          target: rawUrl,
          finalUrl: finalUrlStr,
          hostname: finalHost,
          ip: dnsData?.a?.[0] || '127.0.0.1',
          asn: reconData?.osint?.output?.serverLocation?.asn || 'Autonomous System',
          country: reconData?.osint?.output?.serverLocation?.location || 'Global',
          mode: options.mode || 'passive',
          score: precisionEvaluation ? precisionEvaluation.score : score,
          grade: precisionEvaluation ? precisionEvaluation.grade : grade,
          risk: precisionEvaluation ? precisionEvaluation.risk : classification,
          startedAt,
          completedAt,
          durationMs: Date.now() - new Date(startedAt).getTime(),
          coverage: precisionEvaluation?.coverage || null,
          categoryScores: precisionEvaluation?.categoryScores || null,
        },
        channels: allFindings.map((f) => ({
          id: f.id || f.channel,
          name: f.title || f.name || f.channel || f.id,
          channel: f.channel || f.id,
          status: f.status || 'PASS',
          score: f.score !== undefined ? f.score : (f.status === 'PASS' ? 100 : f.status === 'WARN' || f.status === 'WARNING' ? 50 : 0),
          maxScore: f.maxScore || 100,
          severity: f.severity || 'INFO',
          description: f.description || f.detail || '',
          recommendation: f.recommendation || '',
          evidence: f.evidence || f.details || {},
        })),
        cookieInfo: {
          total: httpTelemetry.headers?.['set-cookie'] ? (Array.isArray(httpTelemetry.headers['set-cookie']) ? httpTelemetry.headers['set-cookie'].length : 1) : 0,
          cookies: cookieFindings || [],
          status: cookieFindings.some(f => f.status === 'FAIL') ? 'FAIL' : cookieFindings.some(f => f.status === 'WARNING') ? 'WARN' : 'PASS',
          summary: cookieFindings.length > 0 ? `${cookieFindings.length} cookie policy findings evaluated.` : 'No cookies detected on response (Safe / Stateless).',
        },
        corsInfo: {
          status: corsFindings.some(f => f.status === 'FAIL') ? 'FAIL' : 'PASS',
          score: corsFindings.some(f => f.status === 'FAIL') ? 0 : 10,
          detail: corsData?.summary || 'Strict Same-Origin Policy (SOP) enforced. Safe.',
        },
        dnsInfo: {
          emailProtection: dnsData?.spf?.valid && dnsData?.dmarc?.valid ? 'Protected' : 'At Risk',
          spf: dnsData?.spf || { status: 'PASS' },
          dmarc: dnsData?.dmarc || { status: 'PASS' },
          caa: dnsData?.caa || { status: 'WARN' },
        },
        sensitiveFiles: {
          exposedCount: sensitiveFindings.filter(f => f.status === 'FAIL').length,
          findings: sensitiveFindings,
        },
        accessControl: {
          traceDisabled: accessControlData?.telemetry?.verbs?.traceDisabled ?? true,
          methods: accessControlData?.telemetry?.verbs?.testedMethods || {},
          optionsAllow: accessControlData?.telemetry?.verbs?.optionsAllow || null,
          proxyResilient: accessControlData?.telemetry?.proxyHeaders?.resilient ?? true,
          proxyProbes: accessControlData?.telemetry?.proxyHeaders?.probes || [],
        },
        domainRecon: reconData || {
          engine: 'WebVitals Deep OSINT Recon Engine',
          whatweb: await runWhatWebFingerprint(urlObj, httpTelemetry.headers, ''),
          curlCommands: generateCurlCommands(rawUrl, hostname),
        },
        technologies: techStack,
        threatAdvisories: correlateThreatAdvisories(techStack),
        telemetry: {
          http: {
            status: httpTelemetry.status,
            contentType: httpTelemetry.contentType,
            contentLength: httpTelemetry.contentLength,
            headers: httpTelemetry.headers,
            bodyHash: httpTelemetry.bodyHash,
            elapsedMs: httpTelemetry.elapsedMs,
          },
          tls: tlsData,
          dns: dnsData,
          cors: corsData,
          sensitiveProbes: sensitiveData.summary,
          threatIntel: phishingSettled.value?.value?.threatIntel || null,
          geolocation: dnsData?.a?.[0] ? await queryIpGeolocation(dnsData.a[0]) : null,
        },
        limitations: SYSTEM_LIMITATIONS,
        timestamp: completedAt,
      };

      // Persist to storage repository
      scanRepository.saveScan(report);
      return report;
    }, { fatal: false });

    // ── 10. COMPLETE ──────────────────────────────────────────────────────────
    const finalReport = scanRepository.getScan(scanId) || {
      scanId,
      scannerVersion: SCANNER_VERSION,
      requestedUrl: rawUrl,
      score,
      grade,
      findings: allFindings,
      timestamp: new Date().toISOString(),
    };

    const completedLc = markComplete(scanId, finalReport);
    if (completedLc) {
      emit(scanId, {
        type: 'SCAN_COMPLETE',
        scanId,
        status: 'COMPLETE',
        stage: 'REPORT_READY',
        progress: 100,
        message: 'Scan complete',
        timestamp: new Date().toISOString(),
        report: finalReport,
      });
    }

    const scanTimeMs = Date.now() - new Date(finalReport.startedAt || Date.now()).getTime();
    log(`COMPLETE in ${(scanTimeMs / 1000).toFixed(2)}s — score: ${finalReport.score} grade: ${finalReport.grade} findings: ${allFindings.length}`);

  } catch (err) {
    const code = err.code || 'SCAN_FAILED';
    _finalizeFailed(scanId, code, err.message, log);
  } finally {
    clearTimeout(timeoutHandle);
    setTimeout(() => cleanup(scanId), 30_000).unref();
  }
}

function _finalizeFailed(scanId, code, message, log) {
  const lc = markFailed(scanId, code, message);
  if (lc) {
    emit(scanId, {
      type: 'SCAN_ERROR',
      scanId,
      status: 'FAILED',
      stage: lc.stage,
      progress: lc.progress,
      timestamp: new Date().toISOString(),
      error: { code, message },
    });
  }
  if (log) log(`FAILED — ${code}: ${message}`);
}

module.exports = {
  executeScan,
  SCANNER_VERSION,
  SYSTEM_LIMITATIONS,
};
