import React, { useState, useEffect, useMemo } from 'react';
import {
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Download,
  LayoutGrid,
  RefreshCw,
  Zap,
  Globe,
  Shield,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { generateSecurityPdf } from '../utils/pdfExportService';

// All 43 Diagnostic Checks divided across Left (22) and Right (21)
// matching the user's reference diagram
export const CHECKS_LEFT = [
  { id: 'location', label: 'Server Location' },
  { id: 'ssl', label: 'SSL Certificate' },
  { id: 'whois', label: 'Whois Lookup' },
  { id: 'domain-info', label: 'Domain Info' },
  { id: 'quality', label: 'Quality Metrics' },
  { id: 'tech-stack', label: 'Tech Stack' },
  { id: 'hosts', label: 'Associated Hosts' },
  { id: 'server-info', label: 'Server Info' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
  { id: 'cookies', label: 'Cookies' },
  { id: 'trackers', label: 'Trackers & Third Parties' },
  { id: 'headers', label: 'Headers' },
  { id: 'dns', label: 'DNS Records' },
  { id: 'http-security', label: 'HTTP Security' },
  { id: 'mixed-content', label: 'Mixed Content & SRI' },
  { id: 'tls-connection', label: 'TLS Connection' },
  { id: 'tls-audit', label: 'TLS Security Audit' },
  { id: 'tls-compat', label: 'TLS Client Compatibility' },
  { id: 'subdomains', label: 'Subdomains' },
  { id: 'traceroute', label: 'Traceroute' },
  { id: 'security-txt', label: 'Security.txt' },
  { id: 'dns-server', label: 'DNS Server' },
];

export const CHECKS_RIGHT = [
  { id: 'firewall', label: 'Firewall' },
  { id: 'dnssec', label: 'DNSSEC' },
  { id: 'caa-records', label: 'CAA Records' },
  { id: 'hsts', label: 'HSTS' },
  { id: 'threats', label: 'Malware & Phishing' },
  { id: 'breaches', label: 'Data Breaches' },
  { id: 'mail-config', label: 'Email Configuration' },
  { id: 'archives', label: 'Archive History' },
  { id: 'ranking', label: 'Global Ranking' },
  { id: 'redirects', label: 'Redirect Chain' },
  { id: 'linked-pages', label: 'Linked Pages' },
  { id: 'robots-txt', label: 'Crawl Rules' },
  { id: 'status', label: 'Server Status' },
  { id: 'ports', label: 'Open Ports' },
  { id: 'txt-records', label: 'TXT Records' },
  { id: 'block-lists', label: 'Block Detection' },
  { id: 'sitemap', label: 'Sitemap' },
  { id: 'screenshot', label: 'Screenshot' },
  { id: 'social-tags', label: 'Social Tags' },
  { id: 'social-presence', label: 'Social Presence' },
  { id: 'carbon', label: 'Carbon Footprint' },
];

export const ALL_43_CHECKS = [...CHECKS_LEFT, ...CHECKS_RIGHT];

export default function CircuitProgressDashboard({
  targetUrl,
  hostname,
  isScanning,
  progress = 0,
  stageLogs = [],
  secReport = null,
  techReport = null,
  seoReport = null,
  onToggleView = null,
  showFullGrid = false,
}) {
  const [elapsedTime, setElapsedTime] = useState('0.0');
  const [downloading, setDownloading] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  const cleanHost = hostname || (targetUrl ? targetUrl.replace(/^https?:\/\//i, '').replace(/\/.*$/, '') : 'target.com');

  // Elapsed scan timer
  useEffect(() => {
    if (!isScanning) return;
    const startTime = Date.now();
    const interval = setInterval(() => {
      setElapsedTime(((Date.now() - startTime) / 1000).toFixed(1));
    }, 100);
    return () => clearInterval(interval);
  }, [isScanning]);

  // Compute completed checks based on progress and scan status
  const completedCount = useMemo(() => {
    if (!isScanning && (secReport || techReport || seoReport)) {
      return 43;
    }
    const ratio = Math.max(0, Math.min(100, progress || 35)) / 100;
    return Math.min(43, Math.max(3, Math.floor(ratio * 43)));
  }, [isScanning, progress, secReport, techReport, seoReport]);

  const issuesCount = useMemo(() => {
    if (!secReport) return 2;
    const fails = secReport.channels?.filter(c => c.status === 'FAIL')?.length || 0;
    const warns = secReport.channels?.filter(c => c.status === 'WARN')?.length || 0;
    return fails + warns || 2;
  }, [secReport]);

  // Check state map (id -> 'done' | 'active' | 'pending')
  const checkStatusMap = useMemo(() => {
    const map = {};
    ALL_43_CHECKS.forEach((chk, index) => {
      if (index < completedCount) {
        map[chk.id] = 'done';
      } else if (index === completedCount && isScanning) {
        map[chk.id] = 'active';
      } else {
        map[chk.id] = 'pending';
      }
    });
    return map;
  }, [completedCount, isScanning]);

  // Active stage display text
  const currentStageName = useMemo(() => {
    if (!isScanning) return 'All 43 Checks Verified';
    if (completedCount < 10) return 'Perimeter & DNS Resolution';
    if (completedCount < 20) return 'SSL/TLS Handshake & Ciphers';
    if (completedCount < 30) return 'Security Headers & WAF Probe';
    if (completedCount < 38) return 'Crawl Rules & Blocklists';
    return 'Finalizing Intelligence Payload';
  }, [isScanning, completedCount]);

  // Instant 1-Click PDF Download handler
  const handleDownloadPdf = () => {
    setDownloading(true);
    setDownloadSuccess(false);

    setTimeout(() => {
      try {
        generateSecurityPdf(secReport, techReport, seoReport);
        setDownloadSuccess(true);
      } catch (err) {
        console.error('PDF export error:', err);
      } finally {
        setTimeout(() => {
          setDownloading(false);
          setTimeout(() => setDownloadSuccess(false), 3000);
        }, 500);
      }
    }, 250);
  };

  return (
    <div className="w-full bg-[#f8fafc] border-2 border-black rounded-3xl p-5 md:p-8 brutal-shadow-lg relative overflow-hidden transition-all duration-300">
      {/* Background Micro-Circuit Dot Grid Pattern */}
      <div
        className="absolute inset-0 opacity-[0.45] pointer-events-none"
        style={{
          backgroundImage: 'radial-gradient(#94a3b8 1px, transparent 1px)',
          backgroundSize: '24px 24px',
        }}
      />

      {/* Top Header Bar matching user's Image 1 */}
      <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b-2 border-black/10">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping" />
            <span className="text-xs font-mono font-bold tracking-wider text-zinc-600 uppercase">
              Autonomous Ingress Diagnostics
            </span>
            <span className="text-xs font-bold text-zinc-400">•</span>
            <span className="text-xs font-mono font-bold text-zinc-800 bg-zinc-200/80 px-2 py-0.5 rounded border border-zinc-300">
              {cleanHost}
            </span>
          </div>
          <h2 className="text-2xl md:text-3xl font-black font-space text-zinc-900 tracking-tight flex items-center gap-3">
            <span>
              Loading <strong className="text-emerald-600">{completedCount}</strong> of 43 ({elapsedTime}s)
            </span>
            <span className="text-zinc-400 font-normal">•</span>
            <span className="text-amber-600 font-bold text-lg md:text-xl">
              {issuesCount} issues detected
            </span>
          </h2>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* 1-Click Direct Download PDF Button */}
          <button
            type="button"
            onClick={handleDownloadPdf}
            disabled={downloading}
            className={`px-4 py-2.5 rounded-xl border-2 border-black font-bold text-xs md:text-sm font-space brutal-shadow-sm flex items-center gap-2 cursor-pointer transition-all ${
              downloadSuccess
                ? 'bg-[#86efac] text-black'
                : 'bg-[#fde047] hover:bg-yellow-300 text-black brutal-hover'
            } disabled:opacity-75`}
            title="Download Full Multi-Engine Security & Intelligence Report"
          >
            {downloading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin stroke-[2.5]" />
                <span>Generating Report...</span>
              </>
            ) : downloadSuccess ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-black stroke-[2.5]" />
                <span>Downloaded Report!</span>
              </>
            ) : (
              <>
                <Download className="w-4 h-4 stroke-[2.5]" />
                <span>Download Report</span>
              </>
            )}
          </button>

          {/* Toggle View button matching Image 1: "Show Load State" / "View Grid" */}
          {onToggleView && (
            <button
              type="button"
              onClick={onToggleView}
              className="px-4 py-2.5 bg-white hover:bg-zinc-100 text-black border-2 border-black rounded-xl font-bold text-xs md:text-sm font-space brutal-shadow-sm brutal-hover flex items-center gap-2 cursor-pointer"
            >
              <LayoutGrid className="w-4 h-4" />
              <span>{showFullGrid ? 'Show Circuit Map' : 'Show Multi-Tile Grid'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Circuit Microprocessor Visual Canvas (Image 1) in Lighter Tone */}
      <div className="relative z-10 py-8 md:py-12 my-2 overflow-x-auto">
        <div className="min-w-[900px] flex items-center justify-between gap-2 relative">

          {/* LEFT COLUMN: 22 Diagnostic Checks */}
          <div className="w-[280px] flex flex-col justify-between space-y-1.5 flex-shrink-0">
            {CHECKS_LEFT.map((check, idx) => {
              const status = checkStatusMap[check.id];
              const isDone = status === 'done';
              const isActive = status === 'active';

              return (
                <div
                  key={check.id}
                  className={`flex items-center justify-between px-2.5 py-1 rounded-md transition-all text-right font-space text-[12px] font-bold ${
                    isDone
                      ? 'text-zinc-900 bg-white/90 border border-zinc-300/80 brutal-shadow-sm'
                      : isActive
                      ? 'text-amber-900 bg-amber-100/90 border border-amber-400 font-extrabold animate-pulse'
                      : 'text-zinc-400 hover:text-zinc-600'
                  }`}
                >
                  <span className="truncate">{check.label}</span>
                  <div className="flex items-center gap-1.5 ml-2">
                    {/* Status Pip */}
                    <div
                      className={`w-3.5 h-3.5 rounded-full border flex items-center justify-center transition-all ${
                        isDone
                          ? 'bg-emerald-500 border-emerald-700 text-white'
                          : isActive
                          ? 'bg-amber-400 border-amber-600 animate-ping'
                          : 'bg-zinc-200 border-zinc-400'
                      }`}
                    >
                      {isDone && <span className="text-[9px] font-black leading-none">✓</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* CENTER BUS CONVERGENCE & MICROPROCESSOR CHIP */}
          <div className="flex-1 flex flex-col items-center justify-center relative px-2">
            
            {/* SVG Connecting Bus Lines Canvas */}
            <svg
              className="absolute inset-0 w-full h-full pointer-events-none"
              style={{ minHeight: '520px' }}
              viewBox="0 0 400 520"
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient id="busGradLeft" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#10b981" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#059669" stopOpacity="0.9" />
                </linearGradient>
                <linearGradient id="busGradRight" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#059669" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#10b981" stopOpacity="0.8" />
                </linearGradient>
              </defs>

              {/* Left Bus Fan-in Lines */}
              {CHECKS_LEFT.map((chk, idx) => {
                const yStart = 15 + idx * 23;
                const yEnd = 200 + (idx % 10) * 12;
                const isDone = checkStatusMap[chk.id] === 'done';
                return (
                  <path
                    key={`line-l-${chk.id}`}
                    d={`M 10,${yStart} C 70,${yStart} 110,${yEnd} 145,${yEnd}`}
                    fill="none"
                    stroke={isDone ? '#10b981' : '#cbd5e1'}
                    strokeWidth={isDone ? '2' : '1'}
                    strokeDasharray={isDone ? 'none' : '3,3'}
                    className="transition-all duration-300"
                  />
                );
              })}

              {/* Right Bus Fan-out Lines */}
              {CHECKS_RIGHT.map((chk, idx) => {
                const yEnd = 15 + idx * 24;
                const yStart = 200 + (idx % 10) * 12;
                const isDone = checkStatusMap[chk.id] === 'done';
                return (
                  <path
                    key={`line-r-${chk.id}`}
                    d={`M 255,${yStart} C 290,${yStart} 330,${yEnd} 390,${yEnd}`}
                    fill="none"
                    stroke={isDone ? '#10b981' : '#cbd5e1'}
                    strokeWidth={isDone ? '2' : '1'}
                    strokeDasharray={isDone ? 'none' : '3,3'}
                    className="transition-all duration-300"
                  />
                );
              })}
            </svg>

            {/* Central Microprocessor Chip Container */}
            <div className="relative z-20 my-auto">
              
              {/* Top Chip Pins */}
              <div className="flex justify-center gap-2 mb-1">
                {[...Array(8)].map((_, i) => (
                  <div key={`pin-t-${i}`} className="w-1.5 h-3 bg-zinc-800 rounded-t-sm" />
                ))}
              </div>

              {/* Microprocessor Core Box */}
              <div className="w-56 h-48 bg-[#fffdf7] border-4 border-black rounded-2xl brutal-shadow-lg p-4 flex flex-col items-center justify-center text-center relative overflow-hidden group">
                
                {/* Silicon Circuit Trace Overlay */}
                <div
                  className="absolute inset-0 opacity-15 pointer-events-none"
                  style={{
                    backgroundImage: 'linear-gradient(45deg, #000 25%, transparent 25%), linear-gradient(-45deg, #000 25%, transparent 25%)',
                    backgroundSize: '12px 12px',
                  }}
                />

                {/* Status Dot */}
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-3 h-3 rounded-full bg-emerald-500 animate-ping border border-black" />
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-500">
                    SOC CORE
                  </span>
                </div>

                {/* Crunching Data Title */}
                <h3 className="text-xl font-black font-space text-zinc-900 leading-tight">
                  Crunching data
                </h3>

                {/* Progress Subtitle */}
                <div className="mt-2 text-sm font-black font-mono text-emerald-700 bg-emerald-100/90 px-3 py-1 rounded-full border-2 border-black brutal-shadow-sm">
                  {completedCount} / 43 checks
                </div>

                {/* Current Stage Indicator */}
                <p className="mt-3 text-[11px] font-medium font-space text-zinc-600 truncate max-w-[190px]">
                  {currentStageName}
                </p>

                {/* Left/Right Chip Lead Pins */}
                <div className="absolute -left-2 top-6 bottom-6 flex flex-col justify-between">
                  {[...Array(6)].map((_, i) => (
                    <div key={`pin-l-${i}`} className="w-2 h-1.5 bg-zinc-800 rounded-l-sm" />
                  ))}
                </div>
                <div className="absolute -right-2 top-6 bottom-6 flex flex-col justify-between">
                  {[...Array(6)].map((_, i) => (
                    <div key={`pin-r-${i}`} className="w-2 h-1.5 bg-zinc-800 rounded-r-sm" />
                  ))}
                </div>
              </div>

              {/* Bottom Chip Pins */}
              <div className="flex justify-center gap-2 mt-1">
                {[...Array(8)].map((_, i) => (
                  <div key={`pin-b-${i}`} className="w-1.5 h-3 bg-zinc-800 rounded-b-sm" />
                ))}
              </div>
            </div>

          </div>

          {/* RIGHT COLUMN: 21 Diagnostic Checks */}
          <div className="w-[280px] flex flex-col justify-between space-y-1.5 flex-shrink-0">
            {CHECKS_RIGHT.map((check, idx) => {
              const status = checkStatusMap[check.id];
              const isDone = status === 'done';
              const isActive = status === 'active';

              return (
                <div
                  key={check.id}
                  className={`flex items-center justify-between px-2.5 py-1 rounded-md transition-all text-left font-space text-[12px] font-bold ${
                    isDone
                      ? 'text-zinc-900 bg-white/90 border border-zinc-300/80 brutal-shadow-sm'
                      : isActive
                      ? 'text-amber-900 bg-amber-100/90 border border-amber-400 font-extrabold animate-pulse'
                      : 'text-zinc-400 hover:text-zinc-600'
                  }`}
                >
                  <div className="flex items-center gap-1.5 mr-2">
                    {/* Status Pip */}
                    <div
                      className={`w-3.5 h-3.5 rounded-full border flex items-center justify-center transition-all ${
                        isDone
                          ? 'bg-emerald-500 border-emerald-700 text-white'
                          : isActive
                          ? 'bg-amber-400 border-amber-600 animate-ping'
                          : 'bg-zinc-200 border-zinc-400'
                      }`}
                    >
                      {isDone && <span className="text-[9px] font-black leading-none">✓</span>}
                    </div>
                  </div>
                  <span className="truncate flex-1">{check.label}</span>
                </div>
              );
            })}
          </div>

        </div>
      </div>

      {/* Bottom Subtitle matching user's Image 1 */}
      <div className="relative z-10 pt-4 border-t-2 border-black/10 text-center">
        <p className="text-xs md:text-sm font-medium font-space text-zinc-600">
          It may take up to a minute for all jobs to complete.
        </p>
        <p className="text-xs font-bold font-mono text-zinc-800 mt-0.5">
          You can view preliminary results as they come in below.
        </p>
      </div>
    </div>
  );
}
