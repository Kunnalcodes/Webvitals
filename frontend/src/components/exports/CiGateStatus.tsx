import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, Sliders } from 'lucide-react';
import { QualityGateResponse } from '../../types/reports';
import { checkCiQualityGate } from '../../services/exportApi';

interface CiGateStatusProps {
  scanId?: string;
  score: number;
}

export const CiGateStatus: React.FC<CiGateStatusProps> = ({ scanId, score }) => {
  const [threshold, setThreshold] = useState<number>(80);
  const [gateResult, setGateResult] = useState<QualityGateResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    const evaluate = async () => {
      // If scanId is a valid UUID or saved scan, try to fetch server evaluation
      if (scanId && scanId !== 'scan-latest' && scanId.length > 10) {
        try {
          const res: any = await checkCiQualityGate(scanId, threshold);
          if (mounted && res && !res.error) {
            setGateResult(res);
            return;
          }
        } catch {
          // Fall through to deterministic client calculation
        }
      }

      // Deterministic Client Fallback Calculation
      const passed = (score ?? 0) >= threshold;
      if (mounted) {
        setGateResult({
          passed,
          score: score ?? 0,
          minimumScore: threshold,
          grade: score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : 'F',
          scanId: scanId || 'live-scan',
          target: 'Active Target',
          failedControlsCount: 0,
          reason: passed
            ? `Security score ${score} meets or exceeds configured gate threshold of ${threshold}.`
            : `Security score ${score} is below configured gate threshold of ${threshold}.`,
          timestamp: new Date().toISOString(),
        });
      }
    };

    evaluate();

    return () => {
      mounted = false;
    };
  }, [scanId, score, threshold]);

  const passed = gateResult ? gateResult.passed : (score ?? 0) >= threshold;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/80 backdrop-blur-md p-4 text-slate-200">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          {passed ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          ) : (
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          )}
          <div>
            <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
              CI/CD Build Quality Gate
            </h4>
            <p className="text-[11px] text-slate-400">
              Deterministic threshold policy for GitHub Actions / GitLab CI
            </p>
          </div>
        </div>

        {/* Threshold Controller */}
        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400 text-[11px]">Threshold:</span>
          <select
            value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value={70}>Min 70 (Permissive)</option>
            <option value={80}>Min 80 (Standard)</option>
            <option value={90}>Min 90 (Strict)</option>
          </select>
        </div>
      </div>

      <div className="pt-3 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div
            className={`px-3 py-1.5 rounded-lg font-bold text-xs flex items-center gap-1.5 ${
              passed
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/50'
                : 'bg-rose-950/80 text-rose-300 border border-rose-800/50'
            }`}
          >
            {passed ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>BUILD PASSED (HTTP 200)</span>
              </>
            ) : (
              <>
                <XCircle className="w-3.5 h-3.5" />
                <span>BUILD BLOCKED (HTTP 422)</span>
              </>
            )}
          </div>
          <p className="text-xs text-slate-300">{gateResult?.reason}</p>
        </div>

        {/* CI curl example */}
        <div className="text-[10px] font-mono text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
          curl -f &quot;https://webvitals.local/api/scan/gate?scanId={(scanId || 'scan-id').slice(0, 8)}&amp;minScore={threshold}&quot;
        </div>
      </div>
    </div>
  );
};
