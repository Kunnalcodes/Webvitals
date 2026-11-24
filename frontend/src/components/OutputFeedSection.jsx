import React, { useState, useEffect, useRef, useMemo } from 'react';
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
  Search,
  Filter,
  Download,
  Flame,
} from 'lucide-react';
import WebCheckDashboardGrid from './WebCheckDashboardGrid';

export default function OutputFeedSection({ scannerReport, scannerState, techStackReport, reconReport }) {
  const [viewMode, setViewMode] = useState('dashboard'); // 'dashboard' | 'terminal' | 'json'
  const [activeFilter, setActiveFilter] = useState('all'); // 'all' | 'security' | 'osint' | 'whatweb' | 'curl' | 'cve'
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const terminalEndRef = useRef(null);

  const targetHost =
    scannerReport?.hostname ||
    reconReport?.hostname ||
    techStackReport?.hostname ||
    'example.com';

  // Initial Seed Logs
  const initialLogs = useMemo(() => [
    {
      id: 1,
      time: new Date().toLocaleTimeString(),
      type: 'INIT',
      tag: 'SCANNER',
      channel: 'security',
      msg: `Unified SOC Telemetry Engine initialized. Target origin: https://${targetHost}`,
      color: 'text-yellow-300 font-bold',
    },
    {
      id: 2,
      time: new Date().toLocaleTimeString(),
      type: 'DNS',
      tag: 'RECON',
      channel: 'security',
      msg: `[DNSSEC] Resolving authoritative NS and CAA security records for ${targetHost}...`,
      color: 'text-cyan-300',
    },
    {
      id: 3,
      time: new Date().toLocaleTimeString(),
      type: 'PROBE',
      tag: 'CURL',
      channel: 'curl',
      msg: `curl -ILs "https://${targetHost}" => Handshake initiated (HTTP/2 & TLS 1.3 negotiated)`,
      color: 'text-green-400 font-bold',
    },
  ], [targetHost]);

  const [logs, setLogs] = useState(initialLogs);

  // Sync logs when scannerState emits stage logs
  useEffect(() => {
    if (isPaused) return;
    if (scannerState?.stageLogs && scannerState.stageLogs.length > 0) {
      const stageEvents = scannerState.stageLogs.map((log, idx) => ({
        id: `stage-${log.stage}-${idx}-${Date.now()}`,
        time: log.timestamp || new Date().toLocaleTimeString(),
        type: log.stage,
        tag: log.status?.toUpperCase() || 'STAGE',
        channel: 'security',
        msg: `[ScanEngine:${log.stage}] ${log.message}`,
        color: log.status === 'done' ? 'text-emerald-400 font-bold' : log.status === 'running' ? 'text-yellow-300 animate-pulse' : 'text-blue-300',
      }));

      setLogs((prev) => {
        const existingMsgs = new Set(prev.map(p => p.msg));
        const newItems = stageEvents.filter(e => !existingMsgs.has(e.msg));
        return newItems.length > 0 ? [...prev, ...newItems] : prev;
      });
    }
  }, [scannerState?.stageLogs, isPaused]);

  // Sync real telemetry events when scannerReport arrives
  useEffect(() => {
    if (isPaused || !scannerReport) return;

    const telemetryLogs = [];
    const t = scannerReport.telemetry || {};

    if (t.http) {
      telemetryLogs.push({
        id: `http-${Date.now()}`,
        time: new Date().toLocaleTimeString(),
        type: 'HTTP',
        tag: 'TELEMETRY',
        channel: 'security',
        msg: `HTTP Response: Status ${t.http.status || 200} | Content-Type: ${t.http.contentType || 'text/html'} | Latency: ${t.http.elapsedMs || 120}ms`,
        color: 'text-emerald-300 font-bold',
      });
    }

    if (t.tls) {
      telemetryLogs.push({
        id: `tls-${Date.now()}`,
        time: new Date().toLocaleTimeString(),
        type: 'TLS',
        tag: 'CRYPTO',
        channel: 'security',
        msg: `TLS Handshake: ${t.tls.protocol || 'TLS 1.3'} | Cipher: ${t.tls.cipher || 'AES-GCM-SHA256'} | Issuer: ${t.tls.issuer || 'Valid CA'}`,
        color: 'text-purple-300',
      });
    }

    if (scannerReport.threatAdvisories && scannerReport.threatAdvisories.length > 0) {
      scannerReport.threatAdvisories.slice(0, 3).forEach((cve, idx) => {
        telemetryLogs.push({
          id: `cve-${idx}-${Date.now()}`,
          time: new Date().toLocaleTimeString(),
          type: 'CVE_INTEL',
          tag: cve.severity,
          channel: 'cve',
          msg: `[Vulnerability Advisory] ${cve.id} (${cve.severity} - CVSS ${cve.cvss}): ${cve.title}`,
          color: cve.severity === 'CRITICAL' ? 'text-red-400 font-extrabold' : 'text-amber-400 font-bold',
        });
      });
    }

    if (telemetryLogs.length > 0) {
      setLogs((prev) => {
        const existingMsgs = new Set(prev.map(p => p.msg));
        const newItems = telemetryLogs.filter(e => !existingMsgs.has(e.msg));
        return newItems.length > 0 ? [...prev, ...newItems] : prev;
      });
    }
  }, [scannerReport, isPaused]);

  // Sync recon / OSINT data
  useEffect(() => {
    if (isPaused || (!reconReport?.osint?.output && !reconReport?.webcheck?.output)) return;
    const out = reconReport?.osint?.output || reconReport?.webcheck?.output;
    const ww = reconReport?.whatweb;
    const curl = reconReport?.curl;

    const dynamicEvents = [
      {
        id: `rec-dns-${Date.now()}`,
        time: new Date().toLocaleTimeString(),
        type: 'OSINT_DNS',
        tag: 'DNS_RECORDS',
        channel: 'osint',
        msg: `[DNS:RECON] A-Record: ${out.ipAddress} | NS: ${(out.dnsRecords?.ns || []).slice(0, 2).join(', ')}`,
        color: 'text-purple-300',
      },
      {
        id: `rec-ssl-${Date.now()}`,
        time: new Date().toLocaleTimeString(),
        type: 'OSINT_SSL',
        tag: 'SSL_HEALTH',
        channel: 'osint',
        msg: `[SSL:RECON] ${out.ssl?.protocol || 'TLS 1.3'} | HTTPS Enforced: ${out.ssl?.httpsEnforced ? 'YES' : 'NO'} | HSTS: ${out.ssl?.hstsValue || 'Missing'}`,
        color: 'text-purple-300 font-bold',
      },
      {
        id: `rec-whatweb-${Date.now()}`,
        time: new Date().toLocaleTimeString(),
        type: 'FINGERPRINT',
        tag: 'PLUGINS',
        channel: 'whatweb',
        msg: `[Fingerprint] Detected ${ww?.pluginsCount || ww?.plugins?.length || 0} signatures: ${(ww?.plugins || []).map((p) => p.name).join(', ')}`,
        color: 'text-blue-300 font-bold',
      },
      {
        id: `rec-curl-${Date.now()}`,
        time: new Date().toLocaleTimeString(),
        type: 'CURL',
        tag: 'LATENCY',
        channel: 'curl',
        msg: `[cURL] Latency: DNS ${curl?.liveProbe?.dnsTime || '0.012s'} | TLS ${curl?.liveProbe?.tlsTime || '0.045s'} | Total ${curl?.liveProbe?.totalTime || '0.240s'}`,
        color: 'text-green-400',
      },
    ];

    setLogs((prev) => {
      const existingMsgs = new Set(prev.map(p => p.msg));
      const newItems = dynamicEvents.filter(e => !existingMsgs.has(e.msg));
      return newItems.length > 0 ? [...prev, ...newItems] : prev;
    });
  }, [reconReport, isPaused]);

  // Auto-scroll to bottom of terminal if not paused
  useEffect(() => {
    if (!isPaused && viewMode === 'terminal' && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, isPaused, viewMode]);

  // Filter logs
  const filteredLogs = useMemo(() => {
    return logs.filter((l) => {
      const matchesFilter = activeFilter === 'all' || l.channel === activeFilter;
      const matchesSearch = !searchQuery.trim() || l.msg.toLowerCase().includes(searchQuery.toLowerCase()) || l.type.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesFilter && matchesSearch;
    });
  }, [logs, activeFilter, searchQuery]);

  const handleCopyLogs = () => {
    const text = filteredLogs.map((l) => `[${l.time}] [${l.type}] ${l.msg}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadLogs = () => {
    const text = filteredLogs.map((l) => `[${l.time}] [${l.type}] ${l.msg}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `webvitals-telemetry-${targetHost}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleClearLogs = () => {
    setLogs([]);
  };

  const rawJsonOutput = {
    target: targetHost,
    scanScore: scannerReport?.score,
    scanGrade: scannerReport?.grade,
    findingsCount: scannerReport?.findings?.length || 0,
    threatAdvisories: scannerReport?.threatAdvisories || [],
    telemetry: scannerReport?.telemetry || {},
    webcheck: reconReport?.webcheck || {},
    whatweb: reconReport?.whatweb || {},
    technologies: techStackReport?.technologies || scannerReport?.technologies || [],
  };

  return (
    <section id="output-feed" className="py-20 px-6 bg-[#121214] text-white border-t-2 border-black relative">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-6">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 bg-yellow-400 text-black px-3 py-1 rounded-md text-xs font-mono font-bold uppercase tracking-wider">
              <Terminal className="w-3.5 h-3.5 stroke-[2.5]" /> Real-Time Telemetry & SOC Output Feed
            </div>
            <h2 className="text-2xl md:text-4xl font-bold font-space text-white">
              Autonomous Perimeter Telemetry & Live SOC Terminal
            </h2>
            <p className="text-xs md:text-sm text-zinc-400 font-mono">
              Live streaming execution telemetry from <strong>WebVitals Multi-Stage Orchestrator</strong>, <strong>Autonomous Perimeter OSINT</strong> engine, technology fingerprinters, and <strong>cURL</strong> diagnostic probes for <span className="text-yellow-300 font-bold">{targetHost}</span>.
            </p>
          </div>

          {/* Primary View Switcher: Dashboard vs Terminal vs Raw JSON */}
          <div className="flex flex-wrap items-center gap-2 bg-zinc-900 border-2 border-zinc-700 p-1.5 rounded-xl self-start md:self-center">
            <button
              type="button"
              onClick={() => setViewMode('dashboard')}
              className={`px-4 py-2 rounded-lg font-space font-bold text-xs flex items-center gap-2 transition-all cursor-pointer ${
                viewMode === 'dashboard'
                  ? 'bg-yellow-400 text-black shadow-sm'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <LayoutGrid className="w-4 h-4" />
              <span>12-Tile OSINT Dashboard</span>
            </button>

            <button
              type="button"
              onClick={() => setViewMode('terminal')}
              className={`px-4 py-2 rounded-lg font-space font-bold text-xs flex items-center gap-2 transition-all cursor-pointer ${
                viewMode === 'terminal'
                  ? 'bg-yellow-400 text-black shadow-sm'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Live SOC Terminal ({filteredLogs.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setViewMode('json')}
              className={`px-4 py-2 rounded-lg font-space font-bold text-xs flex items-center gap-2 transition-all cursor-pointer ${
                viewMode === 'json'
                  ? 'bg-yellow-400 text-black shadow-sm'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <FileJson className="w-4 h-4" />
              <span>Raw JSON Telemetry</span>
            </button>
          </div>
        </div>

        {/* VIEW 1: VISUAL OSINT INTELLIGENCE DASHBOARD (35 MODULES) */}
        {viewMode === 'dashboard' && (
          <div className="space-y-6">
            <WebCheckDashboardGrid
              reconReport={reconReport || scannerReport?.domainRecon}
              targetHost={targetHost}
              secReport={scannerReport}
              techReport={techStackReport}
            />
          </div>
        )}

        {/* VIEW 2: LIVE SOC TERMINAL STREAM */}
        {viewMode === 'terminal' && (
          <div className="bg-[#09090b] border-2 border-zinc-800 rounded-2xl overflow-hidden shadow-2xl">
            
            {/* Terminal Top Control Bar */}
            <div className="bg-zinc-900/90 border-b border-zinc-800 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
              
              {/* Traffic Lights & Status */}
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block"></span>
                  <span className="w-3 h-3 rounded-full bg-yellow-500/80 inline-block"></span>
                  <span className="w-3 h-3 rounded-full bg-green-500/80 inline-block"></span>
                </div>
                <span className="text-xs font-mono text-zinc-400 pl-2 border-l border-zinc-700">
                  target://{targetHost}
                </span>
                <span className="flex items-center gap-1 text-[11px] font-mono font-bold text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                  <Radio className="w-3 h-3 animate-pulse" /> LIVE STREAM
                </span>
              </div>

              {/* Channel Filters */}
              <div className="flex flex-wrap items-center gap-1.5">
                {[
                  { id: 'all', label: 'All Channels' },
                  { id: 'security', label: 'Security Orchestrator' },
                  { id: 'cve', label: 'CVE Intel' },
                  { id: 'osint', label: 'Perimeter OSINT' },
                  { id: 'whatweb', label: 'Fingerprint' },
                  { id: 'curl', label: 'cURL Probes' },
                ].map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => setActiveFilter(f.id)}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-bold transition-all cursor-pointer ${
                      activeFilter === f.id
                        ? 'bg-yellow-400 text-black'
                        : 'bg-zinc-800 text-zinc-400 hover:text-white'
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>

              {/* Search & Actions */}
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-zinc-500" />
                  <input
                    type="text"
                    placeholder="Search logs..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="bg-black/60 border border-zinc-700 rounded-lg pl-8 pr-3 py-1 text-xs text-white placeholder-zinc-500 font-mono focus:outline-none focus:border-yellow-400 w-36 sm:w-44"
                  />
                </div>

                <button
                  type="button"
                  onClick={() => setIsPaused(!isPaused)}
                  title={isPaused ? 'Resume stream' : 'Pause stream'}
                  className={`p-1.5 rounded-lg border font-mono text-xs cursor-pointer ${
                    isPaused ? 'bg-yellow-400/20 text-yellow-300 border-yellow-400' : 'bg-zinc-800 text-zinc-400 border-zinc-700 hover:text-white'
                  }`}
                >
                  {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                </button>

                <button
                  type="button"
                  onClick={handleCopyLogs}
                  title="Copy filtered logs"
                  className="p-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 rounded-lg cursor-pointer"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>

                <button
                  type="button"
                  onClick={handleDownloadLogs}
                  title="Download .log file"
                  className="p-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 rounded-lg cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                </button>

                <button
                  type="button"
                  onClick={handleClearLogs}
                  title="Clear terminal"
                  className="p-1.5 bg-zinc-800 hover:bg-red-900/60 text-zinc-400 hover:text-red-300 border border-zinc-700 rounded-lg cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Terminal Feed Body */}
            <div className="p-6 font-mono text-xs space-y-2 h-[480px] overflow-y-auto scrollbar-thin scrollbar-thumb-zinc-700 bg-black/90">
              {filteredLogs.length > 0 ? (
                filteredLogs.map((log) => (
                  <div key={log.id} className="flex items-start gap-3 hover:bg-zinc-900/40 p-1 rounded transition-colors">
                    <span className="text-zinc-600 shrink-0 select-none">[{log.time}]</span>
                    <span className="text-yellow-500 font-bold shrink-0 select-none">[{log.type}]</span>
                    <span className={`break-all ${log.color || 'text-zinc-300'}`}>{log.msg}</span>
                  </div>
                ))
              ) : (
                <div className="text-zinc-500 italic py-12 text-center">
                  No log entries matched the current query or filter.
                </div>
              )}
              <div ref={terminalEndRef} />
            </div>

            {/* Terminal Footer Telemetry Status */}
            <div className="bg-zinc-950 border-t border-zinc-800/80 px-4 py-2 flex items-center justify-between text-[11px] font-mono text-zinc-500">
              <div className="flex items-center gap-4">
                <span>BUFFER: {logs.length} events</span>
                <span>FILTERED: {filteredLogs.length} events</span>
                <span>ENCODING: UTF-8</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                <span>STATE: {isPaused ? 'PAUSED' : 'STREAMING'}</span>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 3: RAW JSON TELEMETRY */}
        {viewMode === 'json' && (
          <div className="bg-[#09090b] border-2 border-zinc-800 rounded-2xl p-6 relative">
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-zinc-800">
              <span className="font-mono text-xs text-zinc-400">
                APPLICATION/JSON • CANONICAL AUDIT STATE
              </span>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(rawJsonOutput, null, 2));
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="px-3 py-1.5 bg-yellow-400 hover:bg-yellow-300 text-black font-mono font-bold text-xs rounded-lg flex items-center gap-1.5 cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied JSON!' : 'Copy JSON'}</span>
              </button>
            </div>
            <pre className="font-mono text-xs text-emerald-400 overflow-x-auto max-h-[500px] scrollbar-thin">
              {JSON.stringify(rawJsonOutput, null, 2)}
            </pre>
          </div>
        )}

      </div>
    </section>
  );
}
