import React, { useState } from 'react';
import {
  Terminal,
  Globe,
  ExternalLink,
  Copy,
  Check,
  Cpu,
  Layers,
  ShieldCheck,
  Zap,
  Activity,
  Server,
  Code2,
  Lock,
  Search,
} from 'lucide-react';

export default function DomainReconPanel({ domainRecon, targetUrl, hostname }) {
  const [copiedId, setCopiedId] = useState(null);
  const [selectedCmdCategory, setSelectedCmdCategory] = useState('all');

  const targetDomain = hostname || (targetUrl ? targetUrl.replace(/^https?:\/\//, '').replace(/\/.*$/, '') : 'target.com');
  const webcheckUrl = domainRecon?.webcheckUrl || `https://web-check.xyz/check/${encodeURIComponent(targetDomain)}`;
  const whatweb = domainRecon?.whatweb || {
    engine: 'WhatWeb Engine (Heuristic + Plugin Signatures)',
    pluginsCount: 4,
    plugins: [
      { name: 'HTTPS', version: 'TLS 1.2/1.3', category: 'Transport', confidence: 100 },
      { name: 'Nginx / Cloudflare', category: 'Reverse Proxy / Web Server', confidence: 95 },
      { name: 'React / Next.js', category: 'Frontend Framework', confidence: 95 },
      { name: 'Strict-Transport-Security (HSTS)', category: 'Security Header', confidence: 100 },
    ],
  };

  const curlCommands = domainRecon?.curlCommands || [
    {
      id: 'headers',
      name: 'Dump Headers & Timing Metrics',
      category: 'Inspection',
      description: 'Fetches HTTP headers, follow redirects, and measures DNS, TLS, and total latency.',
      command: `curl -ILs -o /dev/null -w "HTTP_CODE: %{http_code}\\nEFFECTIVE_URL: %{url_effective}\\nREMOTE_IP: %{remote_ip}\\nDNS_TIME: %{time_namelookup}s\\nTLS_TIME: %{time_appconnect}s\\nTOTAL_TIME: %{time_total}s\\n" "https://${targetDomain}"`,
    },
    {
      id: 'ssl-verbose',
      name: 'TLS Handshake & Cipher Suite',
      category: 'TLS / SSL',
      description: 'Verbose TLS 1.2/1.3 handshake dump showing negotiated cipher, issuer, and certificate validity.',
      command: `curl -Iv --tlsv1.2 --tls-max 1.3 "https://${targetDomain}" 2>&1 | grep -E "(\\bSSL\\b|\\bTLS\\b|expire date|subject|issuer|cipher|ALPN)"`,
    },
    {
      id: 'security-headers',
      name: 'Audit Security Headers (CSP, HSTS, XFO)',
      category: 'Security Compliance',
      description: 'Filters and verifies critical defense headers on the remote origin.',
      command: `curl -sI "https://${targetDomain}" | grep -Ei "(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|permissions-policy|referrer-policy)"`,
    },
    {
      id: 'bypass-403',
      name: 'Proxy & Header Bypass Simulation',
      category: '403 / 401 Bypass',
      description: 'Simulates client spoofing headers (X-Forwarded-For, X-Originating-IP) to test gateway bypass resilience.',
      command: `curl -ks -o /dev/null -i -w "Status: %{http_code} | Size: %{size_download}B\\n" -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" "https://${targetDomain}"`,
    },
    {
      id: 'http-methods',
      name: 'HTTP Method Probing (OPTIONS, TRACE, PUT)',
      category: 'Access Control',
      description: 'Tests Allowed HTTP verbs to uncover insecure TRACE (XST) or arbitrary PUT capabilities.',
      command: `curl -s -X OPTIONS -i "https://${targetDomain}" | grep -i "Allow:"`,
    },
    {
      id: 'whatweb-cli',
      name: 'WhatWeb Full Plugin Fingerprint',
      category: 'Tech Stack Recon',
      description: 'Runs aggressive WhatWeb plugin signatures against the target URL.',
      command: `whatweb -a 3 -v "https://${targetDomain}"`,
    },
  ];

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredCommands =
    selectedCmdCategory === 'all'
      ? curlCommands
      : curlCommands.filter((cmd) => cmd.category.toLowerCase().includes(selectedCmdCategory.toLowerCase()));

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Top Banner: WebCheck.xyz & WhatWeb Live Integration */}
      <div className="bg-gradient-to-r from-amber-100 via-yellow-100 to-emerald-100 border-2 border-black rounded-xl p-5 brutal-shadow flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 bg-black text-white px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase">
            <Globe className="w-3.5 h-3.5 text-yellow-300" /> webcheck.xyz + WhatWeb Live Engine
          </div>
          <h4 className="text-xl font-bold font-space text-black">
            Domain Reconnaissance & OSINT Hub for <span className="underline decoration-black">{targetDomain}</span>
          </h4>
          <p className="text-xs md:text-sm text-zinc-700 font-medium">
            Cross-referenced with <strong>webcheck.xyz</strong> deep OSINT scanner, <strong>WhatWeb</strong> fingerprint signatures, and automated <strong>cURL</strong> diagnostic commands.
          </p>
        </div>

        <a
          href={webcheckUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 bg-[#86efac] hover:bg-[#4ade80] text-black font-bold font-space text-sm px-4 py-2.5 rounded-xl border-2 border-black brutal-shadow brutal-hover whitespace-nowrap transition-transform cursor-pointer"
        >
          <span>Open in webcheck.xyz</span>
          <ExternalLink className="w-4 h-4 stroke-[2.5]" />
        </a>
      </div>

      {/* Grid: 2 Columns for WhatWeb Signatures & WebCheck Insights */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Column 1: WhatWeb Technology & Plugin Signatures */}
        <div className="bg-white border-2 border-black rounded-xl p-5 brutal-shadow space-y-4">
          <div className="flex items-center justify-between border-b-2 border-black/10 pb-3">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-[#bfdbfe] border-2 border-black rounded-lg flex items-center justify-center">
                <Cpu className="w-4 h-4 text-black stroke-[2.5]" />
              </div>
              <div>
                <h5 className="font-bold font-space text-base text-black">WhatWeb Signature Detector</h5>
                <span className="text-[11px] font-mono text-zinc-500 font-semibold">{whatweb.engine || 'WhatWeb Heuristic Engine'}</span>
              </div>
            </div>
            <span className="bg-blue-100 text-blue-900 border border-black px-2 py-0.5 rounded text-xs font-bold font-mono">
              {whatweb.plugins?.length || whatweb.pluginsCount || 0} Signatures
            </span>
          </div>

          <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
            {whatweb.plugins && whatweb.plugins.length > 0 ? (
              whatweb.plugins.map((plugin, idx) => (
                <div
                  key={idx}
                  className="bg-zinc-50 hover:bg-yellow-50/60 border-2 border-black/80 rounded-lg p-2.5 flex items-center justify-between transition-colors"
                >
                  <div className="flex items-center gap-2.5">
                    <div className="w-2 h-2 rounded-full bg-emerald-500 border border-black"></div>
                    <div>
                      <div className="font-bold font-space text-xs md:text-sm text-black">{plugin.name}</div>
                      <div className="text-[11px] text-zinc-600 font-medium">
                        {plugin.category || 'Technology'} {plugin.version ? `• v${plugin.version}` : ''} {plugin.string ? `(${plugin.string})` : ''}
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono font-bold bg-zinc-200 px-2 py-0.5 rounded border border-zinc-400 text-zinc-800">
                    {plugin.confidence || 100}% Conf.
                  </span>
                </div>
              ))
            ) : (
              <div className="text-center py-6 text-zinc-500 text-xs font-mono">
                No custom WhatWeb plugins discovered for this domain.
              </div>
            )}
          </div>
        </div>

        {/* Column 2: webcheck.xyz OSINT Telemetry */}
        <div className="bg-white border-2 border-black rounded-xl p-5 brutal-shadow space-y-4">
          <div className="flex items-center justify-between border-b-2 border-black/10 pb-3">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-[#fed7aa] border-2 border-black rounded-lg flex items-center justify-center">
                <Globe className="w-4 h-4 text-black stroke-[2.5]" />
              </div>
              <div>
                <h5 className="font-bold font-space text-base text-black">webcheck.xyz OSINT Modules</h5>
                <span className="text-[11px] font-mono text-zinc-500 font-semibold">Active Reconnaissance Endpoints</span>
              </div>
            </div>
            <a
              href={webcheckUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-bold font-space text-blue-700 hover:underline flex items-center gap-1"
            >
              Full Report <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <div className="bg-zinc-50 border border-black rounded-lg p-3">
              <div className="text-[11px] font-mono font-bold text-zinc-500 uppercase">DNS Records</div>
              <div className="text-xs font-bold font-space text-black mt-0.5">A, AAAA, MX, TXT, NS</div>
              <a
                href={`https://web-check.xyz/check/${encodeURIComponent(targetDomain)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] text-blue-600 font-mono font-bold mt-1 inline-block hover:underline"
              >
                Inspect on webcheck.xyz →
              </a>
            </div>

            <div className="bg-zinc-50 border border-black rounded-lg p-3">
              <div className="text-[11px] font-mono font-bold text-zinc-500 uppercase">SSL / TLS Cipher</div>
              <div className="text-xs font-bold font-space text-black mt-0.5">Cert Authority & Validity</div>
              <a
                href={`https://web-check.xyz/check/${encodeURIComponent(targetDomain)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] text-blue-600 font-mono font-bold mt-1 inline-block hover:underline"
              >
                Inspect on webcheck.xyz →
              </a>
            </div>

            <div className="bg-zinc-50 border border-black rounded-lg p-3">
              <div className="text-[11px] font-mono font-bold text-zinc-500 uppercase">Server Location</div>
              <div className="text-xs font-bold font-space text-black mt-0.5">GeoIP & Autonomous System</div>
              <a
                href={`https://web-check.xyz/check/${encodeURIComponent(targetDomain)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] text-blue-600 font-mono font-bold mt-1 inline-block hover:underline"
              >
                Inspect on webcheck.xyz →
              </a>
            </div>

            <div className="bg-zinc-50 border border-black rounded-lg p-3">
              <div className="text-[11px] font-mono font-bold text-zinc-500 uppercase">Carbon & Cookies</div>
              <div className="text-xs font-bold font-space text-black mt-0.5">CO2 Rating & Tracking</div>
              <a
                href={`https://web-check.xyz/check/${encodeURIComponent(targetDomain)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] text-blue-600 font-mono font-bold mt-1 inline-block hover:underline"
              >
                Inspect on webcheck.xyz →
              </a>
            </div>
          </div>

          <div className="p-3 bg-yellow-50 rounded-lg border border-yellow-300 text-xs font-medium text-amber-900 flex items-center justify-between">
            <span>Query live webcheck.xyz OSINT for full perimeter visualization</span>
            <a
              href={webcheckUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="px-2.5 py-1 bg-black text-yellow-300 font-bold font-mono text-[11px] rounded border border-black hover:bg-zinc-800"
            >
              Launch webcheck
            </a>
          </div>
        </div>
      </div>

      {/* cURL Command Suite & Terminal */}
      <div className="bg-[#18181b] text-white border-2 border-black rounded-xl p-5 md:p-6 brutal-shadow space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-zinc-700 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 bg-yellow-400 text-black border border-black rounded-lg flex items-center justify-center font-mono font-bold text-sm">
              <Terminal className="w-4 h-4 stroke-[2.5]" />
            </div>
            <div>
              <h5 className="font-bold font-space text-lg text-white">cURL Command Diagnostic Center</h5>
              <p className="text-xs text-zinc-400 font-mono">
                Execute ready-to-run terminal commands for {targetDomain}
              </p>
            </div>
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap gap-1.5">
            {['all', 'inspection', 'tls', 'security', 'bypass'].map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setSelectedCmdCategory(cat)}
                className={`px-2.5 py-1 rounded text-xs font-mono font-bold border transition-colors cursor-pointer capitalize ${
                  selectedCmdCategory === cat
                    ? 'bg-yellow-400 text-black border-yellow-400'
                    : 'bg-zinc-800 text-zinc-300 border-zinc-700 hover:bg-zinc-700'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Command List */}
        <div className="space-y-3">
          {filteredCommands.map((cmd) => (
            <div key={cmd.id} className="bg-zinc-900 border border-zinc-800 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-bold font-space text-xs md:text-sm text-yellow-300">{cmd.name}</span>
                  <span className="text-[11px] text-zinc-400 ml-2 font-mono">({cmd.category})</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopy(cmd.command, cmd.id)}
                  className="inline-flex items-center gap-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-600 px-2.5 py-1 rounded text-xs font-mono font-bold cursor-pointer transition-colors"
                >
                  {copiedId === cmd.id ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-green-400" />
                      <span className="text-green-400">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-yellow-400" />
                      <span>Copy cURL</span>
                    </>
                  )}
                </button>
              </div>

              <p className="text-[11px] text-zinc-400 font-sans">{cmd.description}</p>

              <div className="bg-black border border-zinc-800 rounded p-2.5 font-mono text-xs text-emerald-400 overflow-x-auto whitespace-pre-wrap select-all">
                {cmd.command}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
