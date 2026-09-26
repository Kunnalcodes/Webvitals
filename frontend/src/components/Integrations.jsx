import React, { useEffect, useState } from 'react';
import { Lock, Shield, Eye, FileCode2, Globe2, Sparkles, Cloud, Activity, CheckCircle2, ShieldAlert } from 'lucide-react';

export default function Integrations() {
  const [integrations, setIntegrations] = useState(null);

  useEffect(() => {
    fetch('/api/integrations/status')
      .then((r) => r.json())
      .then((json) => {
        if (json.success) setIntegrations(json.data);
      })
      .catch(() => {});
  }, []);

  return (
    <section className="py-24 bg-white border-b-2 border-black">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 bg-[#dbeafe] text-[#1e40af] text-xs font-bold uppercase tracking-wider px-3.5 py-1.5 rounded-full border border-black mb-4 font-space">
            <Cloud className="w-3.5 h-3.5" />
            Live Cloud & Threat Intel Infrastructure
          </div>
          <h2 className="text-4xl md:text-5xl font-medium font-space">
            Connected Cloud Intelligence & Standards
          </h2>
          <p className="mt-3 text-zinc-600 max-w-2xl mx-auto text-sm font-space">
            WebVitals pairs zero-dependency local telemetry with official Google Cloud and threat intelligence APIs for real-time security consensus.
          </p>
        </div>

        {/* Cloud Services Live Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {/* Google Gemini AI */}
          <div className="bg-[#fffdf7] border-2 border-black rounded-xl p-5 brutal-shadow hover:-translate-y-1 transition-all">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-lg bg-[#fef08a] border-2 border-black flex items-center justify-center">
                <Sparkles className="w-5 h-5 text-black" />
              </div>
              <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase font-space px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                Connected
              </span>
            </div>
            <h3 className="font-bold text-base font-space text-black">Google Gemini AI</h3>
            <p className="text-xs text-zinc-500 font-mono mt-0.5 mb-2">gemini-3.5-flash-lite</p>
            <p className="text-xs text-zinc-600 leading-relaxed font-space">
              Grounded vulnerability reasoning, executive briefs & stack-specific playbooks.
            </p>
          </div>

          {/* Google Safe Browsing */}
          <div className="bg-[#fffdf7] border-2 border-black rounded-xl p-5 brutal-shadow hover:-translate-y-1 transition-all">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-lg bg-[#bfdbfe] border-2 border-black flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-blue-900" />
              </div>
              <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase font-space px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                Connected
              </span>
            </div>
            <h3 className="font-bold text-base font-space text-black">Google Safe Browsing</h3>
            <p className="text-xs text-zinc-500 font-mono mt-0.5 mb-2">Safe Browsing API v4</p>
            <p className="text-xs text-zinc-600 leading-relaxed font-space">
              Real-time Google threat registry lookups for malware, deceptive phishing & social engineering.
            </p>
          </div>

          {/* Google PageSpeed & CrUX */}
          <div className="bg-[#fffdf7] border-2 border-black rounded-xl p-5 brutal-shadow hover:-translate-y-1 transition-all">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-lg bg-[#bbf7d0] border-2 border-black flex items-center justify-center">
                <Activity className="w-5 h-5 text-emerald-900" />
              </div>
              <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase font-space px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                Connected
              </span>
            </div>
            <h3 className="font-bold text-base font-space text-black">Google PageSpeed & CrUX</h3>
            <p className="text-xs text-zinc-500 font-mono mt-0.5 mb-2">PageSpeed Insights v5</p>
            <p className="text-xs text-zinc-600 leading-relaxed font-space">
              Real-user field data & Core Web Vitals (FCP, LCP, CLS, TBT) diagnostics.
            </p>
          </div>

          {/* VirusTotal Threat Intel */}
          <div className="bg-[#fffdf7] border-2 border-black rounded-xl p-5 brutal-shadow hover:-translate-y-1 transition-all">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-lg bg-[#e9d5ff] border-2 border-black flex items-center justify-center">
                <Shield className="w-5 h-5 text-purple-900" />
              </div>
              <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase font-space px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                Connected
              </span>
            </div>
            <h3 className="font-bold text-base font-space text-black">VirusTotal Intel</h3>
            <p className="text-xs text-zinc-500 font-mono mt-0.5 mb-2">VirusTotal API v3</p>
            <p className="text-xs text-zinc-600 leading-relaxed font-space">
              Consensus analysis across 70+ global antivirus and domain reputation engines.
            </p>
          </div>
        </div>

        {/* Protocol & Header Standard Badges */}
        <h3 className="text-xl font-bold font-space text-center mb-6">
          Supported Protocols & Evaluated Header Standards
        </h3>
        <div className="flex flex-wrap justify-center gap-4">
          <div className="bg-white border-2 border-black rounded-xl px-6 py-3 flex items-center gap-3 brutal-shadow-sm hover:-translate-y-0.5 transition-all cursor-default">
            <Lock className="w-5 h-5 text-green-600 stroke-[2]" />
            <span className="font-bold text-sm font-space">TLS 1.3 / SSL SANs</span>
          </div>
          <div className="bg-white border-2 border-black rounded-xl px-6 py-3 flex items-center gap-3 brutal-shadow-sm hover:-translate-y-0.5 transition-all cursor-default">
            <FileCode2 className="w-5 h-5 text-blue-600 stroke-[2]" />
            <span className="font-bold text-sm font-space">CSP Directives (Level 3)</span>
          </div>
          <div className="bg-white border-2 border-black rounded-xl px-6 py-3 flex items-center gap-3 brutal-shadow-sm hover:-translate-y-0.5 transition-all cursor-default">
            <Shield className="w-5 h-5 text-purple-600 stroke-[2]" />
            <span className="font-bold text-sm font-space">HSTS & Preload List</span>
          </div>
          <div className="bg-white border-2 border-black rounded-xl px-6 py-3 flex items-center gap-3 brutal-shadow-sm hover:-translate-y-0.5 transition-all cursor-default">
            <Eye className="w-5 h-5 text-orange-500 stroke-[2]" />
            <span className="font-bold text-sm font-space">Frame-Ancestors & XFO</span>
          </div>
          <div className="bg-white border-2 border-black rounded-xl px-6 py-3 flex items-center gap-3 brutal-shadow-sm hover:-translate-y-0.5 transition-all cursor-default">
            <Globe2 className="w-5 h-5 text-indigo-600 stroke-[2]" />
            <span className="font-bold text-sm font-space">SPF & DMARC Enforcer</span>
          </div>
        </div>
      </div>
    </section>
  );
}
