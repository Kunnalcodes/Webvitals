const { sendSuccess } = require('../utils/helpers');
const {
  GEMINI_API_KEY,
  AI_ENABLED,
  GEMINI_MODEL,
  SAFE_BROWSING_API_KEY,
  GOOGLE_PAGESPEED_API_KEY,
  VIRUSTOTAL_API_KEY,
} = require('../config/env');

function handleHealth(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.writeHead(200);
  res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
}

function handleIntegrationsStatus(req, res) {
  const integrations = {
    googleCloud: {
      geminiAi: {
        configured: Boolean(GEMINI_API_KEY),
        enabled: AI_ENABLED,
        model: GEMINI_MODEL,
        status: Boolean(GEMINI_API_KEY) ? 'CONNECTED' : 'DISABLED',
        features: ['Grounded AI Explanations', 'Executive Summaries', 'Scan-Scoped Security Chat'],
      },
      safeBrowsing: {
        configured: Boolean(SAFE_BROWSING_API_KEY),
        status: Boolean(SAFE_BROWSING_API_KEY) ? 'CONNECTED' : 'DISABLED',
        service: 'Google Safe Browsing API v4',
        features: ['Malware Detection', 'Social Engineering / Phishing List Lookups'],
      },
      pageSpeedInsights: {
        configured: Boolean(GOOGLE_PAGESPEED_API_KEY),
        status: Boolean(GOOGLE_PAGESPEED_API_KEY) ? 'CONNECTED' : 'STANDALONE_FALLBACK',
        service: 'Google PageSpeed Insights & CrUX API',
        features: ['Real-time Lighthouse Auditing', 'Real-User Core Web Vitals (FCP, LCP, CLS, TBT)'],
      },
    },
    threatIntelligence: {
      virusTotal: {
        configured: Boolean(VIRUSTOTAL_API_KEY),
        status: Boolean(VIRUSTOTAL_API_KEY) ? 'CONNECTED' : 'DISABLED',
        service: 'VirusTotal API v3',
        features: ['Global Antivirus Engine Consensus', 'Domain Reputation Trajectory'],
      },
    },
    systemSummary: {
      cloudConnected: Boolean(GEMINI_API_KEY && SAFE_BROWSING_API_KEY && GOOGLE_PAGESPEED_API_KEY),
      activeEnginesCount: [GEMINI_API_KEY, SAFE_BROWSING_API_KEY, GOOGLE_PAGESPEED_API_KEY, VIRUSTOTAL_API_KEY].filter(Boolean).length,
      timestamp: new Date().toISOString(),
    },
  };

  sendSuccess(res, integrations);
}

module.exports = {
  handleHealth,
  handleIntegrationsStatus,
};
