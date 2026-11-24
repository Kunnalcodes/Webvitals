import React, { useState, useMemo } from 'react';
import {
  Sparkles,
  Sliders,
  CheckCircle2,
  TrendingUp,
  ShieldAlert,
  ShieldCheck,
  Zap,
  ArrowRight,
  RotateCcw,
  Copy,
  Check,
  Flame,
  Award,
} from 'lucide-react';

const REMEDIATION_OPTIONS = [
  {
    id: 'csp',
    channel: 'CSP',
    title: 'Deploy Strict Content-Security-Policy',
    impactPoints: 15,
    description: "Eliminates 'unsafe-inline' and enforces strict default-src 'self' script and object isolation.",
    snippet: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
    compliance: ['OWASP A03:2021', 'PCI-DSS 6.4.3'],
  },
  {
    id: 'hsts',
    channel: 'HSTS',
    title: 'Enforce Strict-Transport-Security (1 Year + Preload)',
    impactPoints: 10,
    description: 'Forces browser to use encrypted HTTPS exclusively and protects subdomains from SSL stripping.',
    snippet: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    compliance: ['NIST SP 800-52', 'PCI-DSS 4.1'],
  },
  {
    id: 'cookies',
    channel: 'COOKIES',
    title: 'Harden Session Cookies (Secure, HttpOnly, SameSite=Strict)',
    impactPoints: 10,
    description: 'Prevents XSS cookie theft and mitigates Cross-Site Request Forgery (CSRF) vectors.',
    snippet: 'Set-Cookie: session_id=...; Secure; HttpOnly; SameSite=Strict; Path=/',
    compliance: ['OWASP A01:2021', 'OWASP A07:2021'],
  },
  {
    id: 'clickjacking',
    channel: 'CLICKJACKING',
    title: 'Block Unauthorized Framing (frame-ancestors / XFO)',
    impactPoints: 10,
    description: 'Guarantees the application cannot be framed inside transparent malicious iframes.',
    snippet: "X-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors 'none';",
    compliance: ['OWASP A04:2021'],
  },
  {
    id: 'mime',
    channel: 'MIME',
    title: 'Disable MIME-Type Sniffing (X-Content-Type-Options: nosniff)',
    impactPoints: 5,
    description: 'Stops browser execution of non-executable MIME formats uploaded by users.',
    snippet: 'X-Content-Type-Options: nosniff',
    compliance: ['OWASP A05:2021'],
  },
  {
    id: 'isolation',
    channel: 'ISOLATION',
    title: 'Enable Cross-Origin Isolation (COOP & COEP)',
    impactPoints: 5,
    description: 'Isolates application process memory to mitigate Spectre and cross-window state manipulation.',
    snippet: 'Cross-Origin-Opener-Policy: same-origin\nCross-Origin-Embedder-Policy: require-corp',
    compliance: ['Defense in Depth', 'W3C WebAppSec'],
  },
  {
    id: 'info_disclosure',
    channel: 'RECON',
    title: 'Mask Server & Framework Disclosures (Server & X-Powered-By)',
    impactPoints: 5,
    description: 'Hides internal software versions from automated reconnaissance scanners.',
    snippet: '# Nginx: server_tokens off;\n# Express: app.disable("x-powered-by");',
    compliance: ['CIS Benchmark 2.1'],
  },
  {
    id: 'sensitive_files',
    channel: 'ENDPOINTS',
    title: 'Block Exposed DevOps Files (.env, .git, config.php.bak)',
    impactPoints: 15,
    description: 'Returns explicit 403/404 on sensitive repository and environment assets at the edge.',
    snippet: 'location ~ /\\.(env|git|htaccess) { deny all; return 404; }',
    compliance: ['OWASP A05:2021', 'ISO 27001 A.12.1.2'],
  },
];

export default function WhatIfSimulator({ baselineReport }) {
  const baseScore = baselineReport?.score !== undefined ? baselineReport.score : 65;
  const baseGrade = baselineReport?.grade || 'C';

  // Initially activate options corresponding to failed channels or common gaps
  const [selectedFixes, setSelectedFixes] = useState(() => {
    const initial = new Set();
    const findings = baselineReport?.findings || [];
    const failedChannels = findings.filter(f => f.status === 'FAIL' || f.status === 'WARNING').map(f => f.channel);

    for (const opt of REMEDIATION_OPTIONS) {
      if (failedChannels.includes(opt.channel) || baseScore < 90) {
        initial.add(opt.id);
      }
    }
    // Default at least 2 fixes if empty
    if (initial.size === 0) {
      initial.add('csp');
      initial.add('hsts');
    }
    return initial;
  });

  const [copied, setCopied] = useState(false);

  const toggleFix = (id) => {
    setSelectedFixes(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    setSelectedFixes(new Set(REMEDIATION_OPTIONS.map(o => o.id)));
  };

  const resetAll = () => {
    setSelectedFixes(new Set());
  };

  // Compute Simulated Score
  const simulation = useMemo(() => {
    let addedPoints = 0;
    const activeSnippets = [];
    const complianceMet = new Set();

    for (const opt of REMEDIATION_OPTIONS) {
      if (selectedFixes.has(opt.id)) {
        addedPoints += opt.impactPoints;
        activeSnippets.push(`# --- Fix: ${opt.title} ---\n${opt.snippet}`);
        opt.compliance.forEach(c => complianceMet.add(c));
      }
    }

    const projectedScore = Math.min(100, Math.max(0, baseScore + addedPoints));
    let projectedGrade = 'A+';
    let gradeColor = 'bg-[#86efac] text-black border-black';

    if (projectedScore >= 95) {
      projectedGrade = 'A+';
      gradeColor = 'bg-[#86efac] text-black border-black';
    } else if (projectedScore >= 85) {
      projectedGrade = 'A';
      gradeColor = 'bg-[#bbf7d0] text-black border-black';
    } else if (projectedScore >= 75) {
      projectedGrade = 'B';
      gradeColor = 'bg-[#fef08a] text-black border-black';
    } else if (projectedScore >= 65) {
      projectedGrade = 'C';
      gradeColor = 'bg-[#fed7aa] text-black border-black';
    } else if (projectedScore >= 50) {
      projectedGrade = 'D';
      gradeColor = 'bg-[#fecaca] text-black border-black';
    } else {
      projectedGrade = 'F';
      gradeColor = 'bg-[#fda4af] text-black border-black';
    }

    const delta = projectedScore - baseScore;
    const riskReductionPct = Math.min(100, Math.round(((projectedScore - baseScore) / Math.max(1, (100 - baseScore))) * 100));

    return {
      projectedScore,
      projectedGrade,
      gradeColor,
      delta,
      riskReductionPct: Math.max(0, riskReductionPct),
      bundleSnippet: activeSnippets.join('\n\n'),
      complianceMet: Array.from(complianceMet),
    };
  }, [baseScore, selectedFixes]);

  const handleCopyBundle = () => {
    navigator.clipboard.writeText(simulation.bundleSnippet || '# No fixes selected');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-white border-2 border-black rounded-2xl p-6 md:p-8 brutal-shadow-lg space-y-6">
      
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b-2 border-black/10 pb-6">
        <div>
          <div className="inline-flex items-center gap-1.5 px-3 py-1 bg-purple-100 border border-black rounded-md text-xs font-bold font-space uppercase mb-2">
            <Sliders className="w-3.5 h-3.5 text-purple-700" /> Interactive Security Health Simulator
          </div>
          <h3 className="text-2xl font-bold font-space text-zinc-900">
            "What-If" Remediation & Score Predictor
          </h3>
          <p className="text-sm font-medium text-zinc-600 mt-1">
            Toggle planned security fixes below to preview how your defensive posture, letter grade, and compliance benchmarks jump before deploying to production.
          </p>
        </div>

        {/* Global actions */}
        <div className="flex items-center gap-2 self-start md:self-center">
          <button
            type="button"
            onClick={selectAll}
            className="px-3 py-1.5 bg-yellow-200 hover:bg-yellow-300 text-black border border-black rounded-lg text-xs font-bold font-space cursor-pointer"
          >
            Select All Fixes
          </button>
          <button
            type="button"
            onClick={resetAll}
            className="px-3 py-1.5 bg-zinc-100 hover:bg-zinc-200 text-zinc-700 border border-black rounded-lg text-xs font-bold font-space cursor-pointer flex items-center gap-1"
          >
            <RotateCcw className="w-3 h-3" /> Reset
          </button>
        </div>
      </div>

      {/* Score Comparison Display Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Baseline Score */}
        <div className="bg-zinc-50 border-2 border-black rounded-xl p-4 brutal-shadow-sm flex flex-col justify-between">
          <span className="text-xs font-bold font-space text-zinc-500 uppercase tracking-wider">Current Score</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-4xl font-extrabold font-space text-zinc-800">{baseScore}</span>
            <span className="text-xs font-bold text-zinc-500">/ 100</span>
          </div>
          <span className="inline-block mt-2 text-xs font-bold font-space px-2 py-0.5 rounded bg-zinc-200 text-zinc-800 border border-black/30 self-start">
            Grade {baseGrade}
          </span>
        </div>

        {/* Projected Score */}
        <div className="bg-[#fffdf0] border-2 border-black rounded-xl p-4 brutal-shadow flex flex-col justify-between">
          <span className="text-xs font-bold font-space text-purple-900 uppercase tracking-wider flex items-center gap-1">
            <Sparkles className="w-3.5 h-3.5 text-purple-600" /> Projected Score
          </span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-4xl font-extrabold font-space text-black">{simulation.projectedScore}</span>
            <span className="text-xs font-bold text-zinc-500">/ 100</span>
            {simulation.delta > 0 && (
              <span className="text-sm font-bold text-emerald-600 ml-1">+{simulation.delta} pts</span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-2">
            <span className={`text-xs font-bold font-space px-2.5 py-0.5 rounded border ${simulation.gradeColor}`}>
              Projected Grade {simulation.projectedGrade}
            </span>
          </div>
        </div>

        {/* Risk Reduction */}
        <div className="bg-emerald-50 border-2 border-black rounded-xl p-4 brutal-shadow-sm flex flex-col justify-between">
          <span className="text-xs font-bold font-space text-emerald-900 uppercase tracking-wider flex items-center gap-1">
            <TrendingUp className="w-3.5 h-3.5 text-emerald-600" /> Risk Reduction
          </span>
          <div className="flex items-baseline gap-1 mt-2">
            <span className="text-4xl font-extrabold font-space text-emerald-700">{simulation.riskReductionPct}%</span>
          </div>
          <span className="text-xs font-medium text-emerald-800 mt-2">
            {selectedFixes.size} / {REMEDIATION_OPTIONS.length} critical controls remediated
          </span>
        </div>

        {/* Compliance Benchmarks */}
        <div className="bg-blue-50 border-2 border-black rounded-xl p-4 brutal-shadow-sm flex flex-col justify-between">
          <span className="text-xs font-bold font-space text-blue-900 uppercase tracking-wider flex items-center gap-1">
            <Award className="w-3.5 h-3.5 text-blue-600" /> Standards Met
          </span>
          <div className="flex items-baseline gap-1 mt-2">
            <span className="text-3xl font-extrabold font-space text-blue-900">{simulation.complianceMet.length}</span>
            <span className="text-xs font-bold text-blue-700">Framework Requirements</span>
          </div>
          <span className="text-xs font-medium text-blue-800 mt-2 truncate">
            {simulation.complianceMet.slice(0, 3).join(', ')}...
          </span>
        </div>
      </div>

      {/* Interactive Toggles List */}
      <div className="space-y-3">
        <h4 className="text-sm font-bold font-space uppercase tracking-wider text-zinc-700">
          Select Defensive Controls to Simulate:
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {REMEDIATION_OPTIONS.map((opt) => {
            const isChecked = selectedFixes.has(opt.id);
            return (
              <label
                key={opt.id}
                onClick={() => toggleFix(opt.id)}
                className={`flex items-start gap-3.5 p-3.5 rounded-xl border-2 border-black cursor-pointer transition-all ${
                  isChecked
                    ? 'bg-[#f0fdf4] brutal-shadow-sm translate-y-[-1px]'
                    : 'bg-zinc-50 opacity-75 hover:opacity-100 hover:bg-zinc-100'
                }`}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={() => {}} // handled by label onClick
                  className="mt-1 h-4 w-4 rounded border-2 border-black text-black accent-black cursor-pointer"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold font-space text-sm text-zinc-900">{opt.title}</span>
                    <span className="text-xs font-extrabold font-space text-emerald-600 bg-emerald-100 px-2 py-0.5 rounded border border-emerald-300 shrink-0">
                      +{opt.impactPoints} pts
                    </span>
                  </div>
                  <p className="text-xs text-zinc-600 mt-1 leading-relaxed">{opt.description}</p>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {opt.compliance.map(c => (
                      <span key={c} className="text-[10px] font-mono font-bold bg-white border border-black/20 px-1.5 py-0.5 rounded text-zinc-600">
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              </label>
            );
          })}
        </div>
      </div>

      {/* Unified 1-Click Config Exporter */}
      <div className="bg-[#18181b] text-white border-2 border-black rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-yellow-300" />
            <h4 className="text-sm font-bold font-space text-yellow-300 uppercase tracking-wider">
              Unified 1-Click Hardening Configuration ({selectedFixes.size} Active Fixes)
            </h4>
          </div>
          <button
            type="button"
            onClick={handleCopyBundle}
            className="px-3.5 py-1.5 bg-yellow-400 hover:bg-yellow-300 text-black border border-black rounded-lg text-xs font-bold font-space flex items-center gap-1.5 cursor-pointer brutal-shadow-sm"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-black" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied Bundle!' : 'Copy Config'}</span>
          </button>
        </div>
        <pre className="text-xs font-mono bg-black/60 p-3.5 rounded-lg border border-zinc-800 text-emerald-400 overflow-x-auto max-h-48 scrollbar-thin">
          {simulation.bundleSnippet || '# No fixes selected'}
        </pre>
      </div>

    </div>
  );
}
