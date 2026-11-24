import React, { useState } from 'react';
import {
  Terminal,
  Copy,
  Check,
  Server,
  Lock,
  Globe,
  Activity,
  FileCode,
  ChevronDown,
  ChevronUp,
  Download,
  Shield,
  Layers,
} from 'lucide-react';

export default function RawEvidenceInspector({ report, reconReport }) {
  const [activeTab, setActiveTab] = useState('all');
  const [copiedKey, setCopiedKey] = useState(null);
  const [expandedSection, setExpandedSection] = useState({
    headers: true,
    dns: true,
    tls: true,
    redirects: true,
    modular: true,
  });

  const handleCopy = (data, key) => {
    navigator.clipboard.writeText(typeof data === 'object' ? JSON.stringify(data, null, 2) : String(data));
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleSection = (sec) => {
    setExpandedSection((prev) => ({ ...prev, [sec]: !prev[sec] }));
  };

  // Safe extractions
  const rawHeaders = report?.telemetry?.http?.headers || report?.rawEvidence?.headers || {};
  const httpTelemetry = report?.telemetry?.http || {};
  const tlsData = report?.telemetry?.tls || report?.rawEvidence?.tls || {};
  const dnsData = report?.telemetry?.dns || report?.rawEvidence?.dns || {};
  const redirectChain = report?.redirectChain || report?.rawEvidence?.redirectChain || [];
  const modularChecks = report?.modularChecks || [];
  const overview = report?.overview || {};

  return (
    <div className="bg-white border-2 border-black rounded-2xl p-6 md:p-8 brutal-shadow space-y-6 font-space">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b-2 border-black/10">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 bg-zinc-900 text-white border-2 border-black rounded-xl flex items-center justify-center brutal-shadow-sm">
            <Terminal className="w-6 h-6 stroke-[2.5]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xl font-bold text-zinc-900">
                Raw Telemetry & Evidence Inspector
              </h3>
              <span className="bg-[#86efac] text-black border border-black px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase">
                AUDIT PROVENANCE
              </span>
            </div>
            <p className="text-xs md:text-sm text-zinc-600 font-medium">
              Inspect unadulterated wire responses, cryptographic fingerprints, and authoritative DNS payloads.
            </p>
          </div>
        </div>

        {/* Global Copy Raw JSON Action */}
        <button
          type="button"
          onClick={() => handleCopy({ report, telemetry: report?.telemetry, rawEvidence: report?.rawEvidence }, 'all-raw')}
          className="px-4 py-2 bg-zinc-100 hover:bg-zinc-200 text-black border-2 border-black rounded-xl font-bold text-xs brutal-shadow-sm flex items-center gap-2 cursor-pointer transition-all"
        >
          {copiedKey === 'all-raw' ? (
            <Check className="w-4 h-4 text-emerald-700 stroke-[2.5]" />
          ) : (
            <Copy className="w-4 h-4 stroke-[2]" />
          )}
          <span>{copiedKey === 'all-raw' ? 'Copied Full Telemetry' : 'Copy All Telemetry JSON'}</span>
        </button>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b-2 border-black/10 pb-3 text-xs font-bold">
        {[
          { id: 'all', label: 'All Raw Evidence' },
          { id: 'headers', label: `HTTP Headers (${Object.keys(rawHeaders).length})` },
          { id: 'dns', label: 'DNS Telemetry' },
          { id: 'tls', label: 'TLS Cryptography' },
          { id: 'redirects', label: `Redirects (${redirectChain.length})` },
          { id: 'checks', label: `Schema Checks (${modularChecks.length})` },
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-3.5 py-1.5 rounded-lg border-2 transition-all cursor-pointer ${
              activeTab === tab.id
                ? 'bg-black text-white border-black brutal-shadow-sm'
                : 'bg-white text-zinc-700 border-zinc-300 hover:border-black'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 1. HTTP Response Headers Section */}
      {(activeTab === 'all' || activeTab === 'headers') && (
        <div className="border-2 border-black rounded-xl overflow-hidden brutal-shadow-sm">
          <div className="bg-zinc-100 p-3.5 flex items-center justify-between border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-zinc-700" />
              <span className="font-bold text-sm text-zinc-900">
                HTTP Response Headers ({Object.keys(rawHeaders).length} Headers Received)
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleCopy(rawHeaders, 'headers')}
                className="text-xs font-mono text-zinc-600 hover:text-black flex items-center gap-1 cursor-pointer bg-white px-2 py-0.5 rounded border border-zinc-300"
              >
                {copiedKey === 'headers' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'headers' ? 'Copied' : 'Copy Headers'}</span>
              </button>
              <button
                type="button"
                onClick={() => toggleSection('headers')}
                className="p-1 hover:bg-zinc-200 rounded cursor-pointer"
              >
                {expandedSection.headers ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {expandedSection.headers && (
            <div className="p-4 bg-zinc-950 text-emerald-400 font-mono text-xs overflow-x-auto max-h-80 space-y-1">
              <div className="text-zinc-500 pb-1 border-b border-zinc-800 text-[11px]">
                HTTP/{httpTelemetry.protocol || '1.1'} {httpTelemetry.status || '200'} OK • Elapsed: {httpTelemetry.elapsedMs || 0}ms
              </div>
              {Object.keys(rawHeaders).length > 0 ? (
                Object.entries(rawHeaders).map(([key, val]) => (
                  <div key={key} className="flex items-start gap-2 py-0.5">
                    <span className="text-cyan-300 font-bold flex-shrink-0">{key}:</span>
                    <span className="text-zinc-300 break-all">{Array.isArray(val) ? val.join('; ') : String(val)}</span>
                  </div>
                ))
              ) : (
                <div className="text-zinc-500 italic">No raw headers captured on this probe.</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 2. DNS Telemetry Section */}
      {(activeTab === 'all' || activeTab === 'dns') && (
        <div className="border-2 border-black rounded-xl overflow-hidden brutal-shadow-sm">
          <div className="bg-zinc-100 p-3.5 flex items-center justify-between border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-zinc-700" />
              <span className="font-bold text-sm text-zinc-900">
                Authoritative DNS Telemetry & Resource Records
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleCopy(dnsData, 'dns')}
                className="text-xs font-mono text-zinc-600 hover:text-black flex items-center gap-1 cursor-pointer bg-white px-2 py-0.5 rounded border border-zinc-300"
              >
                {copiedKey === 'dns' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'dns' ? 'Copied' : 'Copy DNS JSON'}</span>
              </button>
              <button
                type="button"
                onClick={() => toggleSection('dns')}
                className="p-1 hover:bg-zinc-200 rounded cursor-pointer"
              >
                {expandedSection.dns ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {expandedSection.dns && (
            <div className="p-4 bg-zinc-950 text-cyan-300 font-mono text-xs overflow-x-auto max-h-80">
              <pre className="whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(dnsData, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* 3. TLS Handshake & Certificate Section */}
      {(activeTab === 'all' || activeTab === 'tls') && (
        <div className="border-2 border-black rounded-xl overflow-hidden brutal-shadow-sm">
          <div className="bg-zinc-100 p-3.5 flex items-center justify-between border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-zinc-700" />
              <span className="font-bold text-sm text-zinc-900">
                TLS 1.2 / 1.3 Cryptographic Handshake & Certificate Payload
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleCopy(tlsData, 'tls')}
                className="text-xs font-mono text-zinc-600 hover:text-black flex items-center gap-1 cursor-pointer bg-white px-2 py-0.5 rounded border border-zinc-300"
              >
                {copiedKey === 'tls' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'tls' ? 'Copied' : 'Copy TLS JSON'}</span>
              </button>
              <button
                type="button"
                onClick={() => toggleSection('tls')}
                className="p-1 hover:bg-zinc-200 rounded cursor-pointer"
              >
                {expandedSection.tls ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {expandedSection.tls && (
            <div className="p-4 bg-zinc-950 text-amber-300 font-mono text-xs overflow-x-auto max-h-80">
              <pre className="whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(tlsData, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* 4. Redirect Chain Waterfall Section */}
      {(activeTab === 'all' || activeTab === 'redirects') && (
        <div className="border-2 border-black rounded-xl overflow-hidden brutal-shadow-sm">
          <div className="bg-zinc-100 p-3.5 flex items-center justify-between border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-zinc-700" />
              <span className="font-bold text-sm text-zinc-900">
                HTTP Redirect Chain & Timing Waterfall ({redirectChain.length} Hops)
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleCopy(redirectChain, 'redirects')}
                className="text-xs font-mono text-zinc-600 hover:text-black flex items-center gap-1 cursor-pointer bg-white px-2 py-0.5 rounded border border-zinc-300"
              >
                {copiedKey === 'redirects' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'redirects' ? 'Copied' : 'Copy Waterfall'}</span>
              </button>
              <button
                type="button"
                onClick={() => toggleSection('redirects')}
                className="p-1 hover:bg-zinc-200 rounded cursor-pointer"
              >
                {expandedSection.redirects ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {expandedSection.redirects && (
            <div className="p-4 bg-zinc-950 font-mono text-xs space-y-2 max-h-80 overflow-y-auto">
              {redirectChain.length > 0 ? (
                redirectChain.map((hop, idx) => (
                  <div key={idx} className="flex items-center gap-3 p-2 rounded bg-zinc-900 border border-zinc-800 text-zinc-200">
                    <span className="w-5 h-5 rounded-full bg-zinc-700 flex items-center justify-center text-[10px] font-bold text-white">
                      {idx + 1}
                    </span>
                    <span className="text-cyan-400 font-bold">{hop.status ? `HTTP ${hop.status}` : 'INIT'}</span>
                    <span className="text-zinc-300 flex-1 truncate">{hop.url}</span>
                    {hop.elapsedMs !== undefined && (
                      <span className="text-zinc-500 text-[11px] font-mono">{hop.elapsedMs}ms</span>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-zinc-500 italic">No redirect hops observed (Direct single HTTP request).</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 5. Standardized Checks Schema Findings Table */}
      {(activeTab === 'all' || activeTab === 'checks') && modularChecks.length > 0 && (
        <div className="border-2 border-black rounded-xl overflow-hidden brutal-shadow-sm">
          <div className="bg-zinc-100 p-3.5 flex items-center justify-between border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-zinc-700" />
              <span className="font-bold text-sm text-zinc-900">
                Standard Result Schema Checks ({modularChecks.length} Evaluated Checks)
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleCopy(modularChecks, 'checks')}
                className="text-xs font-mono text-zinc-600 hover:text-black flex items-center gap-1 cursor-pointer bg-white px-2 py-0.5 rounded border border-zinc-300"
              >
                {copiedKey === 'checks' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'checks' ? 'Copied' : 'Copy All Checks'}</span>
              </button>
              <button
                type="button"
                onClick={() => toggleSection('modular')}
                className="p-1 hover:bg-zinc-200 rounded cursor-pointer"
              >
                {expandedSection.modular ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {expandedSection.modular && (
            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-zinc-200 border-b border-black/20 text-zinc-700 font-mono text-[11px] uppercase">
                    <th className="p-3">Check ID</th>
                    <th className="p-3">Category</th>
                    <th className="p-3">Title</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Severity</th>
                    <th className="p-3">Conf.</th>
                    <th className="p-3">Duration</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 font-mono">
                  {modularChecks.map((chk, idx) => (
                    <tr key={idx} className="hover:bg-zinc-50 transition-colors">
                      <td className="p-3 font-bold text-zinc-800">{chk.checkId}</td>
                      <td className="p-3 text-zinc-500 uppercase">{chk.category}</td>
                      <td className="p-3 text-zinc-900 font-space font-medium">{chk.title}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          chk.status === 'pass'
                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                            : chk.status === 'finding'
                            ? 'bg-red-100 text-red-800 border border-red-300'
                            : chk.status === 'info'
                            ? 'bg-sky-100 text-sky-800 border border-sky-300'
                            : 'bg-zinc-200 text-zinc-700'
                        }`}>
                          {chk.status}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className={`text-[10px] font-bold uppercase ${
                          chk.severity === 'critical' ? 'text-red-700' : chk.severity === 'high' ? 'text-orange-600' : 'text-zinc-600'
                        }`}>
                          {chk.severity}
                        </span>
                      </td>
                      <td className="p-3 text-zinc-600">{(chk.confidence * 100).toFixed(0)}%</td>
                      <td className="p-3 text-zinc-500">{chk.durationMs}ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

    </div>
  );
}
