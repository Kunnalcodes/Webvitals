import React, { useState } from 'react';
import { Database, ShieldCheck, Hash, Calendar, ChevronDown, ChevronUp, Terminal } from 'lucide-react';
import { SecurityFinding, SecurityEvidence } from '../../types/findings';

interface FindingEvidenceProps {
  finding: SecurityFinding;
}

export const FindingEvidence: React.FC<FindingEvidenceProps> = ({ finding }) => {
  const [showRawProof, setShowRawProof] = useState<boolean>(false);
  const evidenceList: SecurityEvidence[] = finding.evidence || [];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3 text-xs text-slate-300">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
        <div className="flex items-center gap-2 text-slate-200 font-semibold">
          <Database className="w-4 h-4 text-cyan-400" />
          <span>Verified Security Evidence</span>
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 font-mono text-cyan-300">
            {evidenceList.length} telemetry records
          </span>
        </div>

        <button
          onClick={() => setShowRawProof(!showRawProof)}
          className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition"
        >
          {showRawProof ? 'Hide Raw Proof' : 'View Raw Proof'}
          {showRawProof ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {evidenceList.length === 0 ? (
        <p className="text-slate-500 italic py-2">No raw telemetry attached for this control.</p>
      ) : (
        <div className="space-y-2">
          {evidenceList.map((item, idx) => (
            <div key={idx} className="p-3 rounded-lg bg-slate-900/90 border border-slate-800/80 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-cyan-300 font-bold">{item.source}</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-slate-400">{item.dataType}</span>
                </div>
                {item.hash && (
                  <div className="flex items-center gap-1 text-slate-500 font-mono text-[10px]" title="SHA-256 Evidence Provenance Hash">
                    <Hash className="w-3 h-3 text-slate-400" />
                    <span>{item.hash.slice(0, 12)}...</span>
                  </div>
                )}
              </div>

              {item.notes && <p className="text-slate-300">{item.notes}</p>}

              {showRawProof && item.rawProof !== undefined && (
                <div className="pt-2">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1 flex items-center gap-1">
                    <Terminal className="w-3 h-3 text-emerald-400" /> Raw Captured Proof:
                  </div>
                  <pre className="p-2.5 rounded bg-slate-950 text-[11px] font-mono text-emerald-300/90 overflow-x-auto border border-slate-800">
                    {typeof item.rawProof === 'object' ? JSON.stringify(item.rawProof, null, 2) : String(item.rawProof)}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
