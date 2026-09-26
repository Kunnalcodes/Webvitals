import React, { useState, useEffect } from 'react';
import { Sparkles, Shield, AlertCircle, CheckCircle2, ChevronDown, ChevronUp, Terminal, BookOpen, Lock } from 'lucide-react';
import { SecurityFinding } from '../../types/findings';
import { FindingExplanation, AudienceType } from '../../types/ai';
import { fetchFindingExplanation } from '../../services/aiApi';
import { AIStatusBadge } from './AIStatusBadge';

interface AIExplanationPanelProps {
  scanId: string;
  finding: SecurityFinding;
}

export const AIExplanationPanel: React.FC<AIExplanationPanelProps> = ({ scanId, finding }) => {
  const [audience, setAudience] = useState<AudienceType>('developer');
  const [explanation, setExplanation] = useState<FindingExplanation | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<boolean>(true);

  useEffect(() => {
    let mounted = true;
    const loadExplanation = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchFindingExplanation(scanId, finding.id, audience);
        if (mounted) setExplanation(data);
      } catch (err: any) {
        if (mounted) setError(err.message || 'Failed to generate explanation');
      } finally {
        if (mounted) setLoading(false);
      }
    };

    if (scanId && finding?.id) {
      loadExplanation();
    }

    return () => {
      mounted = false;
    };
  }, [scanId, finding?.id, audience]);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 backdrop-blur-md overflow-hidden transition-all duration-300">
      {/* Panel Header */}
      <div className="px-5 py-3.5 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <BookOpen className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              Security Reasoning & Context
            </h4>
            <p className="text-xs text-slate-400">Contextual interpretation of verified Phase 3 evidence</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {explanation && (
            <AIStatusBadge
              isAiGenerated={explanation.isAiGenerated}
              evidenceCount={finding.evidence?.length || 0}
              fallbackReason={explanation.fallbackReason}
            />
          )}

          {/* Audience Toggle */}
          <div className="inline-flex rounded-lg bg-slate-800/90 p-0.5 border border-slate-700/60">
            <button
              onClick={() => setAudience('developer')}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all ${
                audience === 'developer'
                  ? 'bg-cyan-500/20 text-cyan-300 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Developer
            </button>
            <button
              onClick={() => setAudience('executive')}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all ${
                audience === 'executive'
                  ? 'bg-cyan-500/20 text-cyan-300 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Executive
            </button>
          </div>

          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 text-slate-400 hover:text-slate-200 rounded-md hover:bg-slate-800 transition"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Content */}
      {expanded && (
        <div className="p-5 space-y-4 text-sm">
          {loading && (
            <div className="py-8 flex flex-col items-center justify-center gap-2 text-slate-400">
              <div className="w-6 h-6 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
              <p className="text-xs font-mono">Analyzing verified scan telemetry...</p>
            </div>
          )}

          {error && !loading && (
            <div className="p-4 rounded-lg bg-rose-950/30 border border-rose-800/40 text-rose-300 text-xs flex items-start gap-3">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Explanation Unavailable</p>
                <p className="text-rose-400/80">{error}</p>
              </div>
            </div>
          )}

          {!loading && !error && explanation && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Why It Matters */}
              <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800/80 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-cyan-400">
                  <Shield className="w-3.5 h-3.5" />
                  <span>Why It Matters</span>
                </div>
                <p className="text-xs leading-relaxed text-slate-300">{explanation.whyItMatters}</p>
              </div>

              {/* Potential Attack Scenario */}
              <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800/80 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-amber-400">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>Attack Surface / Exposure</span>
                </div>
                <p className="text-xs leading-relaxed text-slate-300">{explanation.attackScenario}</p>
              </div>

              {/* What This Scan Proves */}
              <div className="p-4 rounded-lg bg-emerald-950/10 border border-emerald-900/30 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-emerald-400">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>What This Scan Proves</span>
                </div>
                <p className="text-xs leading-relaxed text-slate-300">{explanation.whatThisProves}</p>
              </div>

              {/* What This Scan Does NOT Prove */}
              <div className="p-4 rounded-lg bg-slate-950/30 border border-slate-800/60 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                  <Lock className="w-3.5 h-3.5" />
                  <span>Scope Limitations</span>
                </div>
                <p className="text-xs leading-relaxed text-slate-400">{explanation.whatThisDoesNotProve}</p>
              </div>

              {/* Validation Steps */}
              {explanation.validationSteps && (
                <div className="md:col-span-2 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>How to Validate Fix</span>
                  </div>
                  <pre className="p-2.5 rounded bg-slate-900 text-xs font-mono text-cyan-300/90 overflow-x-auto border border-slate-800">
                    {explanation.validationSteps}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
