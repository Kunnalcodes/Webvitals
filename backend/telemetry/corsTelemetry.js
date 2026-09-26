/**
 * Dynamic CORS Telemetry Collector — Phase 3
 * WebVitals
 *
 * Performs controlled, non-destructive dynamic CORS probing with test origins
 * to evaluate arbitrary origin reflection and credential exposure.
 */

'use strict';

const { collectHttpTelemetry } = require('./httpTelemetry');

const TEST_ORIGIN_EXTERNAL = 'https://webvitals-origin-audit.invalid';
const TEST_ORIGIN_NULL     = 'null';

/**
 * Performs dynamic CORS probing against a target URL.
 *
 * @param {URL|string} targetUrl
 * @returns {Promise<object>}
 */
async function collectCorsTelemetry(targetUrl) {
  const cleanUrl = typeof targetUrl === 'string' ? targetUrl : targetUrl.toString();

  // Probe 1: Send external test origin
  const probe1 = await collectHttpTelemetry(cleanUrl, {
    method: 'GET',
    headers: {
      'Origin': TEST_ORIGIN_EXTERNAL,
      'Sec-Fetch-Mode': 'cors',
    },
    maxBodyBytes: 10 * 1024, // only need small slice
  });

  // Probe 2: Send null origin
  const probe2 = await collectHttpTelemetry(cleanUrl, {
    method: 'GET',
    headers: {
      'Origin': TEST_ORIGIN_NULL,
      'Sec-Fetch-Mode': 'cors',
    },
    maxBodyBytes: 10 * 1024,
  });

  const headers1 = probe1.headers || {};
  const headers2 = probe2.headers || {};

  const acao1 = headers1['access-control-allow-origin'] || null;
  const acac1 = headers1['access-control-allow-credentials'] === 'true';
  const vary1 = (headers1['vary'] || '').toLowerCase();

  const acao2 = headers2['access-control-allow-origin'] || null;
  const acac2 = headers2['access-control-allow-credentials'] === 'true';

  const reflectsExternalOrigin = acao1 === TEST_ORIGIN_EXTERNAL;
  const reflectsNullOrigin     = acao2 === 'null';
  const hasWildcardOrigin      = acao1 === '*' || acao2 === '*';

  let riskType = 'NONE';
  if (reflectsExternalOrigin && acac1) {
    riskType = 'ARBITRARY_ORIGIN_REFLECTION_WITH_CREDENTIALS'; // CRITICAL
  } else if (reflectsExternalOrigin && !acac1) {
    riskType = 'ARBITRARY_ORIGIN_REFLECTION_NO_CREDENTIALS'; // MEDIUM / WARNING
  } else if (reflectsNullOrigin && acac2) {
    riskType = 'NULL_ORIGIN_REFLECTION_WITH_CREDENTIALS'; // HIGH
  } else if (hasWildcardOrigin && acac1) {
    riskType = 'WILDCARD_WITH_CREDENTIALS'; // INVALID / HIGH
  } else if (hasWildcardOrigin && !acac1) {
    riskType = 'PUBLIC_WILDCARD_NO_CREDENTIALS'; // INFO / NORMAL FOR PUBLIC APIS
  }

  return {
    targetUrl: cleanUrl,
    acao: acao1,
    acac: acac1,
    varyOrigin: vary1.includes('origin'),
    reflectsExternalOrigin,
    reflectsNullOrigin,
    hasWildcardOrigin,
    riskType,
    probeResponses: {
      externalOrigin: {
        sentOrigin: TEST_ORIGIN_EXTERNAL,
        status: probe1.status,
        acao: acao1,
        acac: acac1,
      },
      nullOrigin: {
        sentOrigin: TEST_ORIGIN_NULL,
        status: probe2.status,
        acao: acao2,
        acac: acac2,
      },
    },
  };
}

module.exports = {
  collectCorsTelemetry,
  TEST_ORIGIN_EXTERNAL,
  TEST_ORIGIN_NULL,
};
