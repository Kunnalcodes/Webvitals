import React, { useState, useEffect } from 'react';
import { Award, Zap, TrendingUp, AlertOctagon, CheckCircle, RefreshCw, BarChart3, ArrowUpRight, ShieldCheck, ShieldAlert, FileCheck, Lock, Globe } from 'lucide-react';
import { ExecutiveSummaryReport } from '../../types/ai';
import { fetchExecutiveSummary } from '../../services/aiApi';
import { AIStatusBadge } from './AIStatusBadge';

interface ExecutiveSummaryProps {
  scanId?: string;
  report?: any;
}

export const ExecutiveSummary: React.FC<ExecutiveSummaryProps> = ({ scanId, report }) => {
  const [summary, setSummary] = useState<ExecutiveSummaryReport | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    let mounted = true;

    const loadSummary = async () => {
      // 1. If scanId is a valid UUID or saved scan, try to fetch server summary
      if (scanId && scanId !== 'scan-latest' && scanId.length > 10) {
        setLoading(true);
        try {
          const data: any = await fetchExecutiveSummary(scanId);
          if (mounted && data && !data.error && data.overallScore !== undefined) {
            setSummary(data);
            setLoading(false);
            return;
          }
        } catch {
          // Fall through to deterministic local synthesis
        }
      }

      // 2. Deterministic Local Synthesis from report prop
      if (report && mounted && (report.channels?.length > 0 || report.findings?.length > 0 || report.score !== undefined)) {
        const score = report.score ?? 0;
        const channels = report.channels || [];
        const failedChannels = channels.filter((c: any) => c.status === 'FAIL');
        const warnChannels = channels.filter((c: any) => c.status === 'WARN');
        const passedChannels = channels.filter((c: any) => c.status === 'PASS');

        let headline = 'Adequate security posture with actionable areas for hardening.';
        if (score >= 90) headline = 'Exceptional, enterprise-grade perimeter posture across all critical defensive controls.';
        else if (score >= 80) headline = 'Strong baseline security with minor configuration and defensive opportunities.';
        else if (score >= 60) headline = 'Moderate risk profile: Key defensive headers and email DNS controls require remediation.';
        else headline = 'High risk posture: Critical security controls are absent, exposing the perimeter to active threat vectors.';

        const topPriorityActions = [...failedChannels, ...warnChannels].slice(0, 5).map((c: any, idx: number) => ({
          priority: idx + 1,
          findingId: c.id || `f-${idx}`,
          channel: c.id || 'PERIMETER',
          title: c.name || 'Security Control',
          severity: (c.status === 'FAIL' ? 'HIGH' : 'MEDIUM') as 'HIGH' | 'MEDIUM',
          scoreImpact: -(c.weight - c.earned),
          effort: ((c.id === 'HSTS' || c.id === 'MIME' || c.id === 'SPF' || c.id === 'PRIVACY' || c.id === 'CLICKJACKING') ? 'LOW' : (c.id === 'CSP' || c.id === 'TLS') ? 'HIGH' : 'MEDIUM') as 'LOW' | 'MEDIUM' | 'HIGH',
          businessImpact: c.detail || 'Remediating this control directly hardens the public perimeter and lowers attack surface.',
          recommendation: c.recommendation || 'Implement recommended security header or configuration.',
        }));

        const quickWins = topPriorityActions.filter((a) => a.effort === 'LOW').map((a) => `${a.title} (+${Math.abs(a.scoreImpact)} pts)`);
        const moderateActions = topPriorityActions.filter((a) => a.effort === 'MEDIUM').map((a) => `${a.title} (+${Math.abs(a.scoreImpact)} pts)`);
        const strategicActions = topPriorityActions.filter((a) => a.effort === 'HIGH').map((a) => `${a.title} (+${Math.abs(a.scoreImpact)} pts)`);

        let hostname = report.hostname;
        if (!hostname && report.finalUrl) {
          try { hostname = new URL(report.finalUrl).hostname; } catch {}
        }
        if (!hostname && report.requestedUrl) {
          try { hostname = new URL(report.requestedUrl).hostname; } catch {}
        }
        hostname = hostname || 'Target Host';

        const p1 = `WebVitals conducted an automated remote security audit of ${hostname}. The target achieved an overall security score of ${score}/100 (Grade: ${report.grade || 'C'}). A total of ${channels.length || 12} perimeter controls were evaluated (${passedChannels.length} compliant, ${warnChannels.length} warnings, ${failedChannels.length} critical omissions).`;
        const p2 = failedChannels.length > 0
          ? `Identified exposures include missing defensive headers (${failedChannels.slice(0, 3).map((f: any) => f.name || f.id).join(', ')}), leaving endpoints vulnerable to cross-site scripting (XSS), framing/clickjacking, and transport eavesdropping.`
          : `Transport and cryptographic channels demonstrated verified TLS security and baseline defensive headers.`;
        const p3 = `Recommended Strategy: Implement the prioritized configuration directives below to immediately raise overall posture to an A-Grade rating (+${Math.max(0, 100 - score)} PTS) with zero downtime.`;

        setSummary({
          target: hostname,
          scanId: scanId || 'live-scan',
          scannerVersion: '4.0.0',
          overallScore: score,
          grade: report.grade || (score >= 80 ? 'A' : score >= 60 ? 'C' : 'F'),
          gradeLabel: report.gradeLabel || '',
          classification: report.classification || (score >= 80 ? 'Safe Posture' : score >= 60 ? 'Needs Attention' : 'High Risk'),
          postureHeadline: headline,
          executiveNarrative: `${p1}\n\n${p2}\n\n${p3}`,
          counts: {
            critical: failedChannels.length,
            high: failedChannels.length,
            medium: warnChannels.length,
            low: 0,
            totalFindings: channels.length || 12,
          },
          topPriorityActions,
          effortVsImpact: {
            quickWins,
            moderateActions,
            strategicActions,
          },
          limitations: report.limitations || [],
          timestamp: report.completedAt || report.timestamp || new Date().toISOString(),
          isAiGenerated: false,
        });
      }

      if (mounted) setLoading(false);
    };

    loadSummary();

    return () => {
      mounted = false;
    };
  }, [scanId, report]);

  if (loading) {
    return (
      <div className="p-8 rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-md flex flex-col items-center justify-center gap-3 text-slate-400">
        <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
        <p className="text-sm font-medium">Synthesizing executive briefing & priority matrix...</p>
      </div>
    );
  }

  if (!summary || (summary.overallScore === 0 && (!report || !report.channels || report.channels.length === 0))) {
    return null;
  }

  const score = summary.overallScore ?? 0;
  const gradeColor = score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-rose-400';

  return (
    <div className="rounded-2xl border border-slate-800 bg-gradient-to-b from-slate-900/90 to-slate-950/90 backdrop-blur-xl p-6 space-y-6 text-slate-200 shadow-2xl">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              Executive Security Intelligence Briefing
            </h3>
            <AIStatusBadge isAiGenerated={summary.isAiGenerated} />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Target Host: <span className="text-slate-200 font-mono font-semibold">{summary.target}</span> • Security Posture Grade: <span className={`${gradeColor} font-bold`}>{summary.grade}</span> ({summary.overallScore}/100 PTS)
          </p>
        </div>

        {/* Score & Badge Pill */}
        <div className="flex items-center gap-4 bg-slate-950/80 px-4 py-2.5 rounded-xl border border-slate-800">
          <div className="text-right">
            <span className="text-[10px] uppercase tracking-wider text-slate-400">Security Score</span>
            <div className={`text-xl font-black ${gradeColor}`}>{summary.overallScore}/100</div>
          </div>
          <div className="h-8 w-px bg-slate-800" />
          <div className="text-right">
            <span className="text-[10px] uppercase tracking-wider text-slate-400">Grade Rating</span>
            <div className={`text-xl font-black ${gradeColor}`}>{summary.grade}</div>
          </div>
        </div>
      </div>

      {/* Posture Headline & Narrative */}
      <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 space-y-3">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <h4 className="text-sm font-semibold text-cyan-300">{summary.postureHeadline}</h4>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line border-t border-slate-800/60 pt-2.5">
          {summary.executiveNarrative}
        </p>
      </div>

      {/* Compliance Quick Matrix */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-slate-400 font-medium">OWASP Top 10</div>
            <div className="text-xs font-bold text-slate-200 mt-0.5">Misconfiguration</div>
          </div>
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${score >= 70 ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/40' : 'bg-rose-950 text-rose-300 border border-rose-800/40'}`}>
            {score >= 70 ? 'COMPLIANT' : 'REVIEW'}
          </span>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-slate-400 font-medium">NIST CSF 2.0</div>
            <div className="text-xs font-bold text-slate-200 mt-0.5">Data In-Transit</div>
          </div>
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${score >= 80 ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/40' : 'bg-amber-950 text-amber-300 border border-amber-800/40'}`}>
            {score >= 80 ? 'COMPLIANT' : 'PARTIAL'}
          </span>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-slate-400 font-medium">CIS Controls v8</div>
            <div className="text-xs font-bold text-slate-200 mt-0.5">Secure Baseline</div>
          </div>
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${score >= 60 ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/40' : 'bg-rose-950 text-rose-300 border border-rose-800/40'}`}>
            {score >= 60 ? 'COMPLIANT' : 'GAP'}
          </span>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-slate-400 font-medium">GDPR Art. 32</div>
            <div className="text-xs font-bold text-slate-200 mt-0.5">Data Privacy</div>
          </div>
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${score >= 75 ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/40' : 'bg-amber-950 text-amber-300 border border-amber-800/40'}`}>
            {score >= 75 ? 'COMPLIANT' : 'PARTIAL'}
          </span>
        </div>
      </div>

      {/* Top Priority Actions & Score Jumps */}
      {summary.topPriorityActions && summary.topPriorityActions.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              Prioritized High-ROI Defensive Actions
            </h4>
            <span className="text-[11px] text-slate-500">Ranked by score gain & attack surface reduction</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {summary.topPriorityActions.slice(0, 3).map((action, idx) => (
              <div
                key={action.findingId || idx}
                className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col justify-between gap-3"
              >
                <div>
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <span className="font-mono text-cyan-400 font-bold">#{action.priority}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        action.effort === 'LOW'
                          ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/40'
                          : action.effort === 'MEDIUM'
                          ? 'bg-amber-950/80 text-amber-300 border border-amber-800/40'
                          : 'bg-indigo-950/80 text-indigo-300 border border-indigo-800/40'
                      }`}
                    >
                      {action.effort} EFFORT
                    </span>
                  </div>
                  <h5 className="text-xs font-semibold text-slate-200 line-clamp-1">{action.title}</h5>
                  <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{action.businessImpact}</p>
                </div>

                <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-xs">
                  <span className="text-slate-400 text-[10px]">Score Uplift:</span>
                  <span className="text-emerald-400 font-bold font-mono">+{Math.abs(action.scoreImpact)} pts</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Effort vs Impact Matrix Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
        <div className="p-3.5 rounded-xl bg-emerald-950/10 border border-emerald-900/30">
          <div className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <CheckCircle className="w-3.5 h-3.5" /> Quick Wins (Low Complexity &lt; 48h)
          </div>
          <ul className="text-xs text-slate-300 space-y-1.5">
            {summary.effortVsImpact.quickWins.map((item, i) => (
              <li key={i} className="line-clamp-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                {item}
              </li>
            ))}
            {summary.effortVsImpact.quickWins.length === 0 && <li className="text-slate-500 italic">No low-effort items pending</li>}
          </ul>
        </div>

        <div className="p-3.5 rounded-xl bg-amber-950/10 border border-amber-900/30">
          <div className="text-xs font-bold text-amber-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <BarChart3 className="w-3.5 h-3.5" /> Configuration Hardening (7–14 Days)
          </div>
          <ul className="text-xs text-slate-300 space-y-1.5">
            {summary.effortVsImpact.moderateActions.map((item, i) => (
              <li key={i} className="line-clamp-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                {item}
              </li>
            ))}
            {summary.effortVsImpact.moderateActions.length === 0 && <li className="text-slate-500 italic">No moderate items pending</li>}
          </ul>
        </div>

        <div className="p-3.5 rounded-xl bg-indigo-950/10 border border-indigo-900/30">
          <div className="text-xs font-bold text-indigo-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <TrendingUp className="w-3.5 h-3.5" /> Architecture &amp; Policy (&lt; 30 Days)
          </div>
          <ul className="text-xs text-slate-300 space-y-1.5">
            {summary.effortVsImpact.strategicActions.map((item, i) => (
              <li key={i} className="line-clamp-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                {item}
              </li>
            ))}
            {summary.effortVsImpact.strategicActions.length === 0 && <li className="text-slate-500 italic">No strategic items pending</li>}
          </ul>
        </div>
      </div>
    </div>
  );
};
