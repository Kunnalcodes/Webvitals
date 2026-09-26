import React, { useState, useEffect } from 'react';
import { Wrench, Copy, Check, AlertTriangle, RefreshCw, FileCode2, Layers, ShieldAlert } from 'lucide-react';
import { RemediationPlaybook as IRemediationPlaybook } from '../../types/ai';
import { fetchRemediationPlaybook } from '../../services/aiApi';

interface RemediationPlaybookProps {
  scanId: string;
  findingId: string;
  detectedStack?: string;
}

const SUPPORTED_STACKS = [
  { id: 'nginx', label: 'Nginx' },
  { id: 'apache', label: 'Apache' },
  { id: 'node', label: 'Node.js / Express' },
  { id: 'next', label: 'Next.js' },
  { id: 'caddy', label: 'Caddy' },
  { id: 'cloudflare', label: 'Cloudflare' },
  { id: 'dns', label: 'DNS Provider' },
];

export const RemediationPlaybook: React.FC<RemediationPlaybookProps> = ({
  scanId,
  findingId,
  detectedStack,
}) => {
  const [selectedStack, setSelectedStack] = useState<string>(detectedStack || 'nginx');
  const [playbook, setPlaybook] = useState<IRemediationPlaybook | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    let mounted = true;
    const loadPlaybook = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchRemediationPlaybook(scanId, findingId, selectedStack);
        if (mounted) setPlaybook(data);
      } catch (err: any) {
        if (mounted) setError(err.message || 'Failed to load remediation snippet');
      } finally {
        if (mounted) setLoading(false);
      }
    };

    if (scanId && findingId) {
      loadPlaybook();
    }

    return () => {
      mounted = false;
    };
  }, [scanId, findingId, selectedStack]);

  const handleCopy = () => {
    if (!playbook?.snippet) return;
    navigator.clipboard.writeText(playbook.snippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 backdrop-blur-md overflow-hidden text-slate-200">
      {/* Playbook Header */}
      <div className="px-5 py-3.5 bg-slate-950/70 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Wrench className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              Remediation Playbook
              {playbook && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-800/40 text-emerald-300">
                  {playbook.applicability} MATCH
                </span>
              )}
            </h4>
            <p className="text-xs text-slate-400">Stack-specific defensive configuration</p>
          </div>
        </div>

        {/* Stack Selector */}
        <div className="flex items-center gap-2">
          <Layers className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={selectedStack}
            onChange={(e) => setSelectedStack(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-cyan-500 transition"
          >
            {SUPPORTED_STACKS.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Content */}
      <div className="p-5 space-y-4">
        {loading && (
          <div className="py-8 flex flex-col items-center justify-center gap-2 text-slate-400">
            <RefreshCw className="w-5 h-5 animate-spin text-emerald-400" />
            <p className="text-xs font-mono">Generating configuration template...</p>
          </div>
        )}

        {error && !loading && (
          <div className="p-3.5 rounded-lg bg-rose-950/40 border border-rose-800/50 text-rose-300 text-xs">
            {error}
          </div>
        )}

        {!loading && playbook && (
          <div className="space-y-4">
            {/* Target File / Placement */}
            {playbook.file && (
              <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-950/60 px-3 py-2 rounded-lg border border-slate-800">
                <FileCode2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>Target Config:</span>
                <span className="text-slate-200 font-semibold">{playbook.file}</span>
              </div>
            )}

            {/* Code Snippet */}
            <div className="relative rounded-lg overflow-hidden border border-slate-800 bg-slate-950">
              <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800 text-xs text-slate-400">
                <span>{playbook.stack} Configuration</span>
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy Snippet'}</span>
                </button>
              </div>
              <pre className="p-4 text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed">
                {playbook.snippet}
              </pre>
            </div>

            {/* Compatibility Warnings */}
            {playbook.compatibilityWarnings && playbook.compatibilityWarnings.length > 0 && (
              <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-800/40 space-y-1.5">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-400">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>Compatibility Considerations</span>
                </div>
                <ul className="list-disc list-inside text-xs text-amber-300/80 space-y-1">
                  {playbook.compatibilityWarnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Validation & Rollback */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800 space-y-1">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  How to Validate
                </span>
                <p className="text-slate-400">{playbook.validationSteps}</p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800 space-y-1">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  Rollback Steps
                </span>
                <p className="text-slate-400">{playbook.rollbackSteps}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
