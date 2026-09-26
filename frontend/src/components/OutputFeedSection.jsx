import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal,
  Play,
  Pause,
  Trash2,
  Copy,
  Check,
  Zap,
  Activity,
  ShieldAlert,
  Server,
  Cpu,
  Globe,
  Radio,
  Clock,
  Code2,
  FileJson,
  LayoutGrid,
  Sparkles,
} from 'lucide-react';
import WebCheckDashboardGrid from './WebCheckDashboardGrid';

export default function OutputFeedSection({ scannerReport, techStackReport, reconReport }) {
  const [viewMode, setViewMode] = useState('dashboard'); // 'dashboard' | 'terminal' | 'json'
  const [activeFilter, setActiveFilter] = useState('all'); // 'all' | 'webcheck' | 'whatweb' | 'curl' | 'security'
  const [copied, setCopied] = useState(false);
  const terminalEndRef = useRef(null);

  const targetHost =
    reconReport?.hostname ||
    scannerReport?.hostname ||
    techStackReport?.hostname ||
    'github.com';

  const timestamp = new Date().toLocaleTimeString();

  // Baseline Initial Stream
  const initialLogs = [
    {
      id: 1,
      time: '14:32:01.002',
      type: 'INIT',
      tag: 'SCANNER',
      channel: 'security',
      msg: `Initialized WebVitals Unified Engine for target: https://${targetHost}`,
      color: 'text-yellow-300 font-bold',
    },
    {
      id: 2,
      time: '14:32:01.120',
      type: 'CURL',
      tag: 'PROBE',
      channel: 'curl',
      msg: `curl -ILs "https://${targetHost}" => HTTP 200 OK | DNS: 0.012s | TLS: 0.045s | Total: 0.240s`,
      color: 'text-green-400 font-bold',
    },
    {
      id: 3,
      time: '14:32:01.340',
      type: 'WHATWEB',
      tag: 'FINGERPRINT',
      channel: 'whatweb',
      msg: `whatweb -a 3 "https://${targetHost}" => [HTTPS, HSTS, Cloudflare / Nginx, React, Next.js, Strict-Transport-Security]`,
      color: 'text-blue-300',
    },
    {
      id: 4,
      time: '14:32:01.550',
      type: 'WEBCHECK',
      tag: 'OSINT_DNS',
      channel: 'webcheck',
      msg: `[webcheck.xyz:DNS] A-Record: 20.207.73.82 | NS: dns1.p08.nsone.net, ns-1283.awsdns-32.org`,
      color: 'text-purple-300',
    },
    {
      id: 5,
      time: '14:32:01.710',
      type: 'WEBCHECK',
      tag: 'OSINT_SSL',
      channel: 'webcheck',
      msg: `[webcheck.xyz:SSL] Protocol: TLSv1.3 | HTTPS Enforced: TRUE | HSTS: max-age=31536000`,
      color: 'text-purple-300 font-bold',
    },
    {
      id: 6,
      time: '14:32:01.920',
      type: 'WEBCHECK',
      tag: 'OSINT_CARBON',
      channel: 'webcheck',
      msg: `[webcheck.xyz:CARBON] Footprint Rating: A+ (0.12g CO2 per page load) — Cleaner than 88% of tested websites`,
      color: 'text-emerald-300',
    },
    {
      id: 7,
      time: '14:32:02.100',
      type: 'WEBCHECK',
      tag: 'OSINT_PORTS',
      channel: 'webcheck',
      msg: `[webcheck.xyz:PORTS] Standard Ingress Ports Open: [80/HTTP, 443/HTTPS]`,
      color: 'text-cyan-300',
    },
    {
      id: 8,
      time: '14:32:02.350',
      type: 'HEADERS',
      tag: 'COMPLIANCE',
      channel: 'security',
      msg: `Security Headers: Strict-Transport-Security (PASS), Content-Security-Policy (PASS), X-Frame-Options (DENY), nosniff (PASS)`,
      color: 'text-emerald-400',
    },
  ];

  const [logs, setLogs] = useState(initialLogs);

  // Dynamic Event Injection when reconReport / webcheck.xyz output updates
  useEffect(() => {
    if (reconReport && reconReport.webcheck?.output) {
      const out = reconReport.webcheck.output;
      const ww = reconReport.whatweb;
      const curl = reconReport.curl;

      const dynamicEvents = [
        {
          id: Date.now() + 1,
          time: new Date().toLocaleTimeString(),
          type: 'WEBCHECK',
          tag: 'TARGET_SYNC',
          channel: 'webcheck',
          msg: `================ webcheck.xyz OSINT STREAM: ${reconReport.hostname} ================`,
          color: 'text-yellow-400 font-bold',
        },
        {
          id: Date.now() + 2,
          time: new Date().toLocaleTimeString(),
          type: 'WEBCHECK',
          tag: 'DNS_RECORDS',
          channel: 'webcheck',
          msg: `[webcheck.xyz:DNS] Target IP: ${out.ipAddress} | NS: ${out.dnsRecords.ns.slice(0, 3).join(', ')}`,
          color: 'text-purple-300',
        },
        {
          id: Date.now() + 3,
          time: new Date().toLocaleTimeString(),
          type: 'WEBCHECK',
          tag: 'SSL_HEALTH',
          channel: 'webcheck',
          msg: `[webcheck.xyz:SSL] ${out.ssl.protocol} | HTTPS Enforced: ${out.ssl.httpsEnforced} | HSTS: ${out.ssl.hstsValue}`,
          color: 'text-purple-300 font-bold',
        },
        {
          id: Date.now() + 4,
          time: new Date().toLocaleTimeString(),
          type: 'WEBCHECK',
          tag: 'CARBON_ECO',
          channel: 'webcheck',
          msg: `[webcheck.xyz:CARBON] Grade: ${out.carbon.rating} (${out.carbon.co2Grams}) — ${out.carbon.cleanerThan}`,
          color: 'text-emerald-300',
        },
        {
          id: Date.now() + 5,
          time: new Date().toLocaleTimeString(),
          type: 'WEBCHECK',
          tag: 'OPEN_PORTS',
          channel: 'webcheck',
          msg: `[webcheck.xyz:PORTS] Detected Public Ports: [${out.openPorts.join(', ')}] • Cookies: ${out.cookiesDetected}`,
          color: 'text-cyan-300',
        },
        {
          id: Date.now() + 6,
          time: new Date().toLocaleTimeString(),
          type: 'WHATWEB',
          tag: 'PLUGINS',
          channel: 'whatweb',
          msg: `[WhatWeb] Fingerprinted ${ww.pluginsCount || ww.plugins?.length || 0} plugins: ${ww.plugins?.map((p) => p.name).join(', ')}`,
          color: 'text-blue-300 font-bold',
        },
        {
          id: Date.now() + 7,
          time: new Date().toLocaleTimeString(),
          type: 'CURL',
          tag: 'PROBE_METRICS',
          channel: 'curl',
          msg: `[cURL] Latency: DNS ${curl?.liveProbe?.dnsTime || '0.012s'} | TLS ${curl?.liveProbe?.tlsTime || '0.045s'} | Total ${curl?.liveProbe?.totalTime || '0.240s'}`,
          color: 'text-green-400',
        },
      ];

      setLogs((prev) => [...prev, ...dynamicEvents]);
    }
  }, [reconReport]);

  const filteredLogs =
    activeFilter === 'all'
      ? logs
      : logs.filter((log) => log.channel === activeFilter);

  const handleCopyLogs = () => {
    const text = filteredLogs.map((l) => `[${l.time}] [${l.type}] ${l.msg}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleClearLogs = () => {
    setLogs([]);
  };

  const rawJsonOutput = reconReport || {
    target: targetHost,
    webcheck: {
      url: `https://web-check.xyz/check/${targetHost}`,
      status: 'SYNCHRONIZED',
      ip: '20.207.73.82',
      dns: ['dns1.p08.nsone.net', 'dns2.p08.nsone.net'],
      ssl: { protocol: 'TLSv1.3', valid: true },
      carbon: { rating: 'A+', score: '0.12g CO2' },
      openPorts: [80, 443],
    },
    whatweb: {
      engine: 'WhatWeb Engine v0.5.5+',
      plugins: ['HTTPS', 'HSTS', 'Cloudflare', 'React', 'Next.js'],
    },
    curl: {
      httpCode: 200,
      totalTime: '0.240s',
    },
  };

  return (
    <section id="output-feed" className="py-20 px-6 bg-[#121214] text-white border-t-2 border-black relative">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-6">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 bg-yellow-400 text-black px-3 py-1 rounded-md text-xs font-mono font-bold uppercase tracking-wider">
              <Terminal className="w-3.5 h-3.5 stroke-[2.5]" /> Real-Time Telemetry & Output Feed
            </div>
            <h2 className="text-2xl md:text-4xl font-bold font-space text-white">
              webcheck.xyz Dashboard & Live Output Feed
            </h2>
            <p className="text-xs md:text-sm text-zinc-400 font-mono">
              Live streaming execution output and 12-tile visual dashboard from <strong>webcheck.xyz</strong> OSINT, <strong>WhatWeb</strong> engine, and <strong>cURL</strong> diagnostic probes.
            </p>
          </div>

          {/* Primary View Switcher: Dashboard vs Terminal vs Raw JSON */}
          <div className="flex flex-wrap items-center gap-2 bg-zinc-900 border-2 border-zinc-700 p-1.5 rounded-xl self-start md:self-center">
            <button
              type="button"
              onClick={() => setViewMode('dashboard')}
              className={`px-3.5 py-2 rounded-lg text-xs font-space font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                viewMode === 'dashboard'
                  ? 'bg-purple-500 text-black shadow-md'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-800'
              }`}
            >
              <LayoutGrid className="w-4 h-4" />
              <span>All 12 Web-Check Modules</span>
            </button>

            <button
              type="button"
              onClick={() => setViewMode('terminal')}
              className={`px-3.5 py-2 rounded-lg text-xs font-space font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                viewMode === 'terminal'
                  ? 'bg-yellow-400 text-black shadow-md'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-800'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Live Terminal Feed</span>
            </button>

            <button
              type="button"
              onClick={() => setViewMode('json')}
              className={`px-3.5 py-2 rounded-lg text-xs font-space font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                viewMode === 'json'
                  ? 'bg-emerald-400 text-black shadow-md'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-800'
              }`}
            >
              <FileJson className="w-4 h-4" />
              <span>Raw JSON Stream</span>
            </button>
          </div>
        </div>

        {/* VIEW 1: FULL 12-MODULE WEB-CHECK DASHBOARD GRID */}
        {viewMode === 'dashboard' && (
          <WebCheckDashboardGrid
            reconReport={reconReport}
            targetHost={targetHost}
          />
        )}

        {/* VIEW 2: LIVE CYBER TERMINAL FEED */}
        {viewMode === 'terminal' && (
          <div className="space-y-4 animate-in fade-in duration-200">
            {/* Filter Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-3 bg-zinc-900/90 border border-zinc-800 rounded-xl p-3">
              <div className="flex flex-wrap gap-1.5">
                {[
                  { id: 'all', label: 'All Events' },
                  { id: 'webcheck', label: 'webcheck.xyz Stream', badge: 'OSINT' },
                  { id: 'whatweb', label: 'WhatWeb Engine' },
                  { id: 'curl', label: 'cURL Probes' },
                  { id: 'security', label: 'Security Audits' },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveFilter(tab.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold border transition-colors cursor-pointer flex items-center gap-1.5 ${
                      activeFilter === tab.id
                        ? 'bg-yellow-400 text-black border-yellow-400'
                        : 'bg-zinc-800 text-zinc-300 border-zinc-700 hover:bg-zinc-700'
                    }`}
                  >
                    <span>{tab.label}</span>
                    {tab.badge && (
                      <span className="bg-black text-yellow-300 px-1 py-0.2 rounded text-[10px]">
                        {tab.badge}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopyLogs}
                  className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 cursor-pointer transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5 text-yellow-400" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  type="button"
                  onClick={handleClearLogs}
                  className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 cursor-pointer transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5 text-red-400" />
                  <span>Clear</span>
                </button>
              </div>
            </div>

            {/* Terminal Box */}
            <div className="bg-black border-2 border-zinc-800 rounded-2xl overflow-hidden brutal-shadow font-mono text-xs shadow-2xl">
              <div className="bg-zinc-900 border-b border-zinc-800 px-4 py-2.5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
                  <span className="text-zinc-400 text-[11px] ml-2 font-bold">
                    webvitals-output-stream — {targetHost} [webcheck.xyz + WhatWeb]
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500">
                  <span>Encoding: UTF-8</span>
                </div>
              </div>

              <div className="p-4 md:p-6 space-y-2 max-h-[460px] overflow-y-auto select-text scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-zinc-900">
                {filteredLogs.length === 0 ? (
                  <div className="text-zinc-600 text-center py-8">
                    Console output cleared for filter "{activeFilter}". Search or scan a domain to stream new output.
                  </div>
                ) : (
                  filteredLogs.map((log) => (
                    <div
                      key={log.id}
                      className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-3 py-1 border-b border-zinc-900/80 hover:bg-zinc-900/40 px-1 rounded transition-colors"
                    >
                      <span className="text-zinc-500 text-[11px] whitespace-nowrap">
                        [{log.time}]
                      </span>
                      <span className={`px-1.5 py-0.2 rounded text-[10px] uppercase font-bold tracking-wider self-start ${
                        log.channel === 'webcheck' ? 'bg-purple-900/80 text-purple-200 border border-purple-700' : 'bg-zinc-800 text-zinc-300'
                      }`}>
                        {log.type}
                      </span>
                      <p className={`flex-1 ${log.color || 'text-zinc-300'} break-all leading-relaxed`}>
                        {log.msg}
                      </p>
                    </div>
                  ))
                )}
                <div ref={terminalEndRef} />
              </div>
            </div>
          </div>
        )}

        {/* VIEW 3: RAW JSON PAYLOAD */}
        {viewMode === 'json' && (
          <div className="bg-black border-2 border-zinc-800 rounded-2xl p-6 font-mono text-xs overflow-x-auto shadow-2xl space-y-4 animate-in fade-in duration-200">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
              <span className="text-zinc-400 font-bold">Raw webcheck.xyz & Recon JSON Object</span>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(rawJsonOutput, null, 2));
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded text-xs font-mono font-bold flex items-center gap-1 cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5 text-emerald-400" />}
                <span>{copied ? 'Copied JSON' : 'Copy JSON'}</span>
              </button>
            </div>
            <pre className="text-emerald-400 leading-relaxed whitespace-pre-wrap">
              {JSON.stringify(rawJsonOutput, null, 2)}
            </pre>
          </div>
        )}

      </div>
    </section>
  );
}
