import React from 'react';
import { Sparkles, ShieldCheck, AlertTriangle } from 'lucide-react';

interface AIStatusBadgeProps {
  isAiGenerated: boolean;
  evidenceCount?: number;
  fallbackReason?: string;
  className?: string;
}

export const AIStatusBadge: React.FC<AIStatusBadgeProps> = ({
  isAiGenerated,
  evidenceCount = 0,
  fallbackReason,
  className = '',
}) => {
  if (isAiGenerated) {
    return (
      <div
        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 shadow-sm ${className}`}
        title="Interpreted by WebVitals AI Advisor from verified Phase 3 scan evidence"
      >
        <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
        <span>Grounded AI Interpretation</span>
        {evidenceCount > 0 && (
          <span className="text-[10px] text-emerald-500/80 font-mono">({evidenceCount} verified signals)</span>
        )}
      </div>
    );
  }

  return (
    <div
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800/80 border border-slate-700 text-slate-300 ${className}`}
      title={fallbackReason || 'Deterministic security intelligence based directly on verified scan telemetry'}
    >
      <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
      <span>Deterministic Intelligence</span>
    </div>
  );
};
