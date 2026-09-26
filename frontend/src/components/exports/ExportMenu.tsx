import React, { useState } from 'react';
import { Download, FileText, Code2, ShieldCheck, ChevronDown, Check } from 'lucide-react';
import { getSarifDownloadUrl, getMarkdownDownloadUrl } from '../../services/exportApi';

interface ExportMenuProps {
  scanId: string;
  targetHostname: string;
  onOpenPdfModal?: () => void;
}

export const ExportMenu: React.FC<ExportMenuProps> = ({ scanId, targetHostname, onOpenPdfModal }) => {
  const [open, setOpen] = useState<boolean>(false);

  const handleDownloadSarif = () => {
    window.open(getSarifDownloadUrl(scanId), '_blank');
    setOpen(false);
  };

  const handleDownloadMarkdown = () => {
    window.open(getMarkdownDownloadUrl(scanId), '_blank');
    setOpen(false);
  };

  return (
    <div className="relative inline-block text-left">
      <button
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition shadow-sm"
      >
        <Download className="w-4 h-4 text-cyan-400" />
        <span>Export Report</span>
        <ChevronDown className={`w-3.5 h-3.5 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-56 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl py-1.5 z-50 text-xs animate-in fade-in zoom-in-95 duration-100">
          {onOpenPdfModal && (
            <button
              onClick={() => {
                onOpenPdfModal();
                setOpen(false);
              }}
              className="w-full text-left px-4 py-2.5 hover:bg-slate-800/80 flex items-center gap-2.5 text-slate-200 transition"
            >
              <FileText className="w-4 h-4 text-rose-400" />
              <div>
                <p className="font-semibold">Executive PDF Audit</p>
                <p className="text-[10px] text-slate-400">Formatted visual summary report</p>
              </div>
            </button>
          )}

          <button
            onClick={handleDownloadMarkdown}
            className="w-full text-left px-4 py-2.5 hover:bg-slate-800/80 flex items-center gap-2.5 text-slate-200 transition"
          >
            <FileText className="w-4 h-4 text-cyan-400" />
            <div>
              <p className="font-semibold">Markdown (.md)</p>
              <p className="text-[10px] text-slate-400">Audit documentation for GitHub</p>
            </div>
          </button>

          <button
            onClick={handleDownloadSarif}
            className="w-full text-left px-4 py-2.5 hover:bg-slate-800/80 flex items-center gap-2.5 text-slate-200 transition"
          >
            <Code2 className="w-4 h-4 text-emerald-400" />
            <div>
              <p className="font-semibold">OASIS SARIF 2.1.0</p>
              <p className="text-[10px] text-slate-400">CI/CD & GitHub Security Tab</p>
            </div>
          </button>
        </div>
      )}
    </div>
  );
};
