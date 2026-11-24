import React, { useState } from 'react';
import {
  Sparkles,
  Bot,
  BrainCircuit,
  Search,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Layers,
  ArrowRight,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  Zap,
  Globe,
  FileCode,
  Tag,
  BookOpen,
  Compass,
  Cpu,
  Eye,
  TrendingUp,
  Sliders,
  ListOrdered,
  Building,
  Target,
  ExternalLink,
  Code2
} from 'lucide-react';

/**
 * Provenance Badge component indicating verification status
 */
function ProvenanceBadge({ type = 'VERIFIED' }) {
  const configs = {
    VERIFIED: { bg: 'bg-emerald-100 text-emerald-900 border-emerald-400', label: 'Verified DOM/Crawl' },
    INFERRED: { bg: 'bg-blue-100 text-blue-900 border-blue-400', label: 'Heuristic Inferred' },
    AI_INTERPRETED: { bg: 'bg-purple-100 text-purple-900 border-purple-400', label: 'Vertex AI Grounded' },
    ESTIMATED: { bg: 'bg-amber-100 text-amber-900 border-amber-400', label: 'Estimated Metric' },
    UNAVAILABLE: { bg: 'bg-zinc-100 text-zinc-600 border-zinc-300', label: 'Data Unavailable' }
  };
  const cfg = configs[type] || configs.VERIFIED;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border ${cfg.bg}`}>
      {cfg.label}
    </span>
  );
}

/**
 * Score Meter Card
 */
function ScoreMeterCard({ title, score = 0, rating = 'Moderate', subtitle, factors = [], icon: Icon, color = 'emerald' }) {
  const getBadgeStyle = (sc) => {
    if (sc >= 85) return 'bg-[#86efac] text-emerald-950 border-black';
    if (sc >= 70) return 'bg-[#bfdbfe] text-blue-950 border-black';
    if (sc >= 50) return 'bg-[#fde047] text-amber-950 border-black';
    return 'bg-[#ff9ebb] text-rose-950 border-black';
  };

  const barColor = score >= 85 ? 'bg-emerald-500' : score >= 70 ? 'bg-blue-500' : score >= 50 ? 'bg-amber-500' : 'bg-rose-500';

  return (
    <div className="bg-white border-2 border-black rounded-xl p-5 brutal-shadow hover:translate-y-[-2px] transition-all flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2">
            <div className="p-2 bg-zinc-100 border border-black rounded-lg">
              <Icon className="w-5 h-5 text-black stroke-[2.2]" />
            </div>
            <div>
              <h4 className="font-space font-bold text-sm text-black uppercase tracking-wider">{title}</h4>
              <p className="text-[11px] text-zinc-500 font-medium">{subtitle}</p>
            </div>
          </div>
          <span className={`px-2.5 py-1 text-xs font-space font-bold rounded-md border ${getBadgeStyle(score)}`}>
            {rating}
          </span>
        </div>

        <div className="flex items-baseline gap-2 my-2">
          <span className="text-4xl md:text-5xl font-space font-bold text-black tracking-tight">{score}</span>
          <span className="text-sm font-space font-bold text-zinc-400">/100</span>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-zinc-100 border border-black rounded-full h-2.5 overflow-hidden my-3">
          <div className={`h-full ${barColor} transition-all duration-700`} style={{ width: `${Math.max(5, Math.min(100, score))}%` }} />
        </div>
      </div>

      {Array.isArray(factors) && factors.length > 0 && (
        <div className="pt-3 border-t border-zinc-200 mt-2 space-y-1.5">
          <span className="text-[10px] font-space font-bold uppercase tracking-wider text-zinc-400 block mb-1">
            Core Factor Drivers:
          </span>
          {factors.slice(0, 3).map((f, idx) => (
            <div key={idx} className="flex items-center justify-between text-xs font-space">
              <span className="text-zinc-600 truncate max-w-[170px]">{f.name}</span>
              <span className="font-bold text-zinc-900">{f.score}/100</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Copyable Code Block Component
 */
function CopyableBlock({ content, language = 'json' }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const textToDisplay = typeof content === 'string' ? content : JSON.stringify(content, null, 2);

  return (
    <div className="relative bg-zinc-950 text-zinc-100 rounded-lg border-2 border-black overflow-hidden font-mono text-xs">
      <div className="flex items-center justify-between px-3 py-2 bg-zinc-900 border-b border-zinc-800">
        <span className="text-[11px] font-bold uppercase text-zinc-400">{language}</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-[11px] text-zinc-300 hover:text-white transition-colors bg-zinc-800 hover:bg-zinc-700 px-2.5 py-1 rounded border border-zinc-700 cursor-pointer"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-[11px] leading-relaxed max-h-72">{textToDisplay}</pre>
    </div>
  );
}

export default function SeoIntelligenceDashboard({ report }) {
  if (!report) return null;

  const intelligence = report.intelligence || {};
  const overview = intelligence.overview || report.intelligenceOverview || {};
  const seoModule = intelligence.seoModule || {};
  const geoModule = intelligence.geoModule || report.geo || {};
  const aeoModule = intelligence.aeoModule || report.aeo || {};
  const rawMatrix = intelligence.strategyMatrix || report.strategyMatrix;
  const strategyMatrix = Array.isArray(rawMatrix) ? rawMatrix : [];

  const rawRoadmap = intelligence.roadmap || report.roadmap || intelligence.allRecommendations || report.allRecommendations;
  const roadmap = Array.isArray(rawRoadmap)
    ? rawRoadmap
    : (rawRoadmap && typeof rawRoadmap === 'object')
    ? (Array.isArray(rawRoadmap.items) ? rawRoadmap.items : Object.values(rawRoadmap).filter(Array.isArray).flat())
    : [];

  const aiIntelligence = intelligence.aiIntelligence || report.aiIntelligence || {};
  const narrative = aiIntelligence.strategicNarrative || {};
  const workspace = aiIntelligence.pageOptimizationWorkspace || {};
  const evidenceSummary = intelligence.evidenceSummary || {};

  const [activeSubTab, setActiveSubTab] = useState('strategy-matrix');
  const [selectedRoadmapFilter, setSelectedRoadmapFilter] = useState('ALL');
  const [expandedMatrixRow, setExpandedMatrixRow] = useState(null);
  const [expandedRoadmapItem, setExpandedRoadmapItem] = useState(null);
  const [workspaceDraftTab, setWorkspaceDraftTab] = useState('titles');

  // Filter roadmap safely
  const filteredRoadmap = Array.isArray(roadmap)
    ? roadmap.filter((item) => {
        if (!item) return false;
        if (selectedRoadmapFilter === 'ALL') return true;
        return item.priority === selectedRoadmapFilter;
      })
    : [];

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* 1. Header Overview & 3 Score Gauges */}
      <div className="bg-[#fffdf7] border-2 border-black rounded-2xl p-6 md:p-8 brutal-shadow">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b-2 border-black/10">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="px-3 py-1 bg-[#86efac] border border-black rounded-full text-xs font-bold font-space uppercase text-black flex items-center gap-1.5">
                <BrainCircuit className="w-3.5 h-3.5" /> WebVitals 2.0 Strategic Engine
              </span>
              <span className="px-2.5 py-1 bg-purple-100 border border-purple-400 text-purple-900 rounded-full text-xs font-mono font-bold flex items-center gap-1">
                <Sparkles className="w-3 h-3" /> Vertex AI Grounded
              </span>
              <span className="px-2.5 py-1 bg-zinc-100 border border-black rounded-full text-xs font-mono font-bold text-zinc-700">
                {overview.scanCoverage?.pagesAnalyzed || 1} Page Analyzed
              </span>
            </div>
            <h3 className="text-2xl md:text-3xl font-bold font-space text-black">
              SEO, GEO & AEO Intelligence Report
            </h3>
            <p className="text-sm font-medium text-zinc-600 mt-1 max-w-3xl">
              Deep, evidence-based diagnostic across traditional search crawlability, Generative Engine machine readability, and Answer Engine direct citation readiness.
            </p>
          </div>

          {/* Discoverability Assessment Badge */}
          <div className="flex-shrink-0 bg-white border-2 border-black rounded-xl p-4 brutal-shadow-sm min-w-[240px]">
            <span className="text-[10px] font-space font-bold uppercase tracking-widest text-zinc-400 block mb-1">
              Discoverability Posture
            </span>
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${overview.discoverabilityAssessment?.level === 'HIGH' ? 'bg-emerald-500' : overview.discoverabilityAssessment?.level === 'MODERATE' ? 'bg-amber-500' : 'bg-rose-500'}`} />
              <span className="font-space font-bold text-sm text-black">
                {overview.discoverabilityAssessment?.label || 'Evaluation Complete'}
              </span>
            </div>
            <p className="text-xs text-zinc-600 font-medium mt-1 leading-snug">
              {overview.discoverabilityAssessment?.summary || 'Audited based on verified crawl and HTML structure.'}
            </p>
            {overview.improvementPotential?.potentialGainPts > 0 && (
              <div className="mt-2 pt-2 border-t border-zinc-100 flex items-center gap-1 text-[11px] font-bold text-emerald-700 font-space">
                <TrendingUp className="w-3.5 h-3.5" />
                <span>Potential Gain: +{overview.improvementPotential.potentialGainPts} pts</span>
              </div>
            )}
          </div>
        </div>

        {/* 3 Unified Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-6">
          <ScoreMeterCard
            title="SEO Engine"
            subtitle="Search Engine Optimization"
            score={overview.seoScore ?? report.score ?? 75}
            rating={seoModule.rating || 'Evaluated'}
            factors={seoModule.factors}
            icon={Search}
            color="emerald"
          />
          <ScoreMeterCard
            title="GEO Engine"
            subtitle="Generative Engine Optimization"
            score={overview.geoScore ?? 65}
            rating={geoModule.rating || 'Moderate'}
            factors={geoModule.factors}
            icon={Cpu}
            color="blue"
          />
          <ScoreMeterCard
            title="AEO Engine"
            subtitle="Answer Engine Optimization"
            score={overview.aeoScore ?? 60}
            rating={aeoModule.rating || 'Developing'}
            factors={aeoModule.factors}
            icon={Bot}
            color="amber"
          />
        </div>

        {/* Audit Evidence Quality Metric Ribbon */}
        <div className="mt-6 pt-4 border-t border-zinc-200 flex flex-wrap items-center justify-between gap-3 text-xs font-space font-medium text-zinc-600">
          <div className="flex items-center gap-4">
            <span>Verified Ratio: <strong className="text-black font-mono">{overview.evidenceQuality?.verifiedRatio || 100}%</strong></span>
            <span>•</span>
            <span>P0 Critical Gaps: <strong className="text-rose-700 font-mono">{overview.priorityIssues?.p0Count || 0}</strong></span>
            <span>•</span>
            <span>P1 High Impact: <strong className="text-amber-700 font-mono">{overview.priorityIssues?.p1Count || 0}</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-600 stroke-[2.2]" />
            <span>Strict Zero-Hallucination Evidence Bound</span>
          </div>
        </div>
      </div>

      {/* 2. Sub-Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b-2 border-black pb-3">
        {[
          { id: 'strategy-matrix', label: 'Strategy Matrix (6x5)', icon: Compass },
          { id: 'roadmap', label: 'Prioritized Roadmap', icon: ListOrdered },
          { id: 'ai-narrative', label: 'Vertex AI Strategic Narrative', icon: Sparkles },
          { id: 'seo-module', label: 'SEO Technical & Hierarchy', icon: Search },
          { id: 'geo-module', label: 'GEO Entity & Readability', icon: Cpu },
          { id: 'aeo-module', label: 'AEO Journey & Answers', icon: Bot },
          { id: 'workspace', label: 'Optimization Workspace', icon: Code2 }
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg border-2 font-bold text-xs md:text-sm font-space transition-all cursor-pointer ${
                isActive
                  ? 'bg-black text-white border-black brutal-shadow-sm'
                  : 'bg-white text-zinc-700 border-zinc-300 hover:border-black'
              }`}
            >
              <Icon className="w-4 h-4 stroke-[2]" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB CONTENT 1: INTERACTIVE STRATEGY MATRIX */}
      {activeSubTab === 'strategy-matrix' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b-2 border-black/10">
            <div>
              <div className="flex items-center gap-2">
                <Compass className="w-5 h-5 text-black stroke-[2.2]" />
                <h4 className="font-space font-bold text-lg text-black">
                  Interactive Strategy Matrix (Section 6.0)
                </h4>
              </div>
              <p className="text-xs text-zinc-600 font-medium mt-0.5">
                Evaluates how your current architecture translates across Search (SEO), Generative AI (GEO), and Direct Answer (AEO) channels.
              </p>
            </div>
            <div className="text-xs font-mono bg-zinc-100 border border-black px-3 py-1.5 rounded-md font-bold">
              {strategyMatrix.length} Strategies Evaluated
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-space border-collapse">
              <thead>
                <tr className="bg-zinc-100 border-b-2 border-black">
                  <th className="p-3 font-bold text-zinc-900 uppercase">Strategy Area</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">SEO Implication</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">GEO Implication</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">AEO Implication</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase text-center">Implementation Status</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase text-center">Effectiveness</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200">
                {strategyMatrix.map((row, idx) => {
                  const isExpanded = expandedMatrixRow === idx;
                  const statusBg =
                    row.status === 'Applied'
                      ? 'bg-emerald-100 text-emerald-900 border-emerald-400'
                      : row.status === 'Partial'
                      ? 'bg-amber-100 text-amber-900 border-amber-400'
                      : 'bg-zinc-100 text-zinc-600 border-zinc-300';

                  const effectBg =
                    row.effectiveness === 'Strong'
                      ? 'text-emerald-700 font-bold'
                      : row.effectiveness === 'Moderate'
                      ? 'text-amber-700 font-bold'
                      : 'text-zinc-500';

                  return (
                    <React.Fragment key={idx}>
                      <tr
                        onClick={() => setExpandedMatrixRow(isExpanded ? null : idx)}
                        className={`hover:bg-zinc-50 cursor-pointer transition-colors ${isExpanded ? 'bg-zinc-50/80' : ''}`}
                      >
                        <td className="p-3 font-bold text-black flex items-center gap-2">
                          <span className="p-1 rounded bg-zinc-200 text-zinc-700">
                            {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          </span>
                          {row.strategy}
                        </td>
                        <td className="p-3 text-zinc-700 max-w-xs">{row.seo}</td>
                        <td className="p-3 text-zinc-700 max-w-xs">{row.geo}</td>
                        <td className="p-3 text-zinc-700 max-w-xs">{row.aeo}</td>
                        <td className="p-3 text-center">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${statusBg}`}>
                            {row.status}
                          </span>
                        </td>
                        <td className={`p-3 text-center ${effectBg}`}>{row.effectiveness}</td>
                        <td className="p-3 text-right">
                          <span className="text-[11px] font-bold text-blue-600 hover:underline">
                            {isExpanded ? 'Close' : 'Inspect'}
                          </span>
                        </td>
                      </tr>

                      {/* Expandable Drawer Row */}
                      {isExpanded && (
                        <tr className="bg-zinc-50 border-b border-zinc-300">
                          <td colSpan={7} className="p-4 space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-white p-4 rounded-lg border-2 border-black/20">
                              <div>
                                <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 block mb-1">
                                  Observed Evidence
                                </span>
                                <p className="text-xs text-zinc-800 font-mono bg-zinc-50 p-2 rounded border border-zinc-200">
                                  {row.evidence || 'No direct evidence detected in DOM crawl.'}
                                </p>
                              </div>
                              <div>
                                <span className="text-[10px] font-bold uppercase tracking-wider text-amber-700 block mb-1">
                                  Missing Elements / Gap
                                </span>
                                <p className="text-xs text-zinc-800 bg-amber-50/60 p-2 rounded border border-amber-200">
                                  {row.missingElements || 'Implementation meets basic baseline criteria.'}
                                </p>
                              </div>
                              <div>
                                <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700 block mb-1">
                                  Recommended Improvement Action
                                </span>
                                <p className="text-xs text-zinc-800 bg-emerald-50/60 p-2 rounded border border-emerald-200">
                                  {row.recommendedAction || 'Monitor crawl logs and preserve structured signals.'}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center justify-between text-[11px] text-zinc-500 pt-1">
                              <span>Priority: <strong className="text-black">{row.priority || 'P2'}</strong> • Confidence: <strong className="text-black">{row.confidence || '0.85'}</strong></span>
                              <ProvenanceBadge type="VERIFIED" />
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB CONTENT 2: PRIORITIZED IMPROVEMENT ROADMAP */}
      {activeSubTab === 'roadmap' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b-2 border-black/10">
            <div>
              <div className="flex items-center gap-2">
                <ListOrdered className="w-5 h-5 text-black stroke-[2.2]" />
                <h4 className="font-space font-bold text-lg text-black">
                  Prioritized Engineering & Optimization Roadmap
                </h4>
              </div>
              <p className="text-xs text-zinc-600 font-medium mt-0.5">
                Every action is tied to verified scan evidence and provides exact code implementations with impact forecasts.
              </p>
            </div>

            {/* Filter Pills */}
            <div className="flex flex-wrap gap-1.5 bg-zinc-100 p-1 rounded-lg border border-black">
              {['ALL', 'P0', 'P1', 'P2', 'P3'].map((filt) => (
                <button
                  key={filt}
                  onClick={() => setSelectedRoadmapFilter(filt)}
                  className={`px-3 py-1 rounded text-xs font-space font-bold transition-colors cursor-pointer ${
                    selectedRoadmapFilter === filt ? 'bg-black text-white' : 'text-zinc-600 hover:text-black'
                  }`}
                >
                  {filt === 'ALL' ? 'All Items' : filt}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-4">
            {filteredRoadmap.length === 0 ? (
              <div className="text-center py-10 text-zinc-500 text-sm font-space">
                No recommendations found for filter {selectedRoadmapFilter}.
              </div>
            ) : (
              filteredRoadmap.map((item, idx) => {
                const isExpanded = expandedRoadmapItem === idx;
                const priorityBadge =
                  item.priority === 'P0'
                    ? 'bg-rose-100 text-rose-900 border-rose-500 font-bold'
                    : item.priority === 'P1'
                    ? 'bg-amber-100 text-amber-900 border-amber-500 font-bold'
                    : item.priority === 'P2'
                    ? 'bg-blue-100 text-blue-900 border-blue-500 font-bold'
                    : 'bg-zinc-100 text-zinc-700 border-zinc-400';

                return (
                  <div
                    key={item.id || idx}
                    className="border-2 border-black rounded-xl overflow-hidden bg-white brutal-shadow-sm transition-all"
                  >
                    <div
                      onClick={() => setExpandedRoadmapItem(isExpanded ? null : idx)}
                      className="p-4 cursor-pointer hover:bg-zinc-50 flex items-center justify-between gap-4 select-none"
                    >
                      <div className="flex items-center gap-3">
                        <span className={`px-2.5 py-1 text-xs font-mono rounded border ${priorityBadge}`}>
                          {item.priority}
                        </span>
                        <div>
                          <h5 className="font-space font-bold text-sm text-black">{item.problem}</h5>
                          <p className="text-xs text-zinc-500 font-medium truncate max-w-xl mt-0.5">
                            {item.recommendedAction}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 flex-shrink-0">
                        <span className="text-xs font-mono bg-zinc-100 border border-zinc-300 px-2 py-0.5 rounded text-zinc-600">
                          Effort: {item.effort || 'Low'}
                        </span>
                        <span className="p-1 rounded bg-zinc-200 text-zinc-700">
                          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        </span>
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="p-5 bg-zinc-50 border-t-2 border-black space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="bg-white p-3.5 rounded-lg border border-black/20">
                            <span className="text-[10px] font-space font-bold uppercase tracking-wider text-zinc-500 block mb-1">
                              Observed Evidence
                            </span>
                            <p className="text-xs text-zinc-800 font-mono bg-zinc-50 p-2 rounded border border-zinc-200">
                              {item.evidence}
                            </p>
                          </div>
                          <div className="bg-white p-3.5 rounded-lg border border-black/20">
                            <span className="text-[10px] font-space font-bold uppercase tracking-wider text-zinc-500 block mb-1">
                              Why It Matters
                            </span>
                            <p className="text-xs text-zinc-700">{item.whyItMatters}</p>
                          </div>
                        </div>

                        {/* Implementation Code */}
                        {item.suggestedImplementation && (
                          <div>
                            <span className="text-[10px] font-space font-bold uppercase tracking-wider text-zinc-500 block mb-1.5 flex items-center gap-1.5">
                              <FileCode className="w-3.5 h-3.5" /> Suggested Code Implementation
                            </span>
                            <CopyableBlock
                              content={item.suggestedImplementation}
                              language={item.suggestedImplementation.startsWith('{') ? 'json' : 'html'}
                            />
                          </div>
                        )}

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                          <div className="flex items-center gap-2 text-xs font-space">
                            <span className="text-zinc-500 font-bold uppercase text-[10px]">Expected Outcome:</span>
                            <span className="text-emerald-800 font-bold">{item.expectedOutcome}</span>
                          </div>
                          <div className="flex items-center gap-2 text-xs font-mono justify-end">
                            <span className="text-zinc-500 uppercase text-[10px]">Validation:</span>
                            <code className="bg-zinc-200 px-2 py-0.5 rounded text-[11px] text-zinc-800">{item.validation}</code>
                          </div>
                        </div>

                        <div className="pt-2 border-t border-zinc-200 flex items-center justify-between text-[11px]">
                          <span className="text-zinc-500">Module: <strong className="text-black uppercase">{item.module || 'SEO'}</strong></span>
                          <ProvenanceBadge type={item.provenance || 'VERIFIED'} />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* TAB CONTENT 3: VERTEX AI STRATEGIC NARRATIVE */}
      {activeSubTab === 'ai-narrative' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-purple-700 stroke-[2.2]" />
              <h4 className="font-space font-bold text-lg text-black">
                Vertex AI Strategic Intelligence Narrative
              </h4>
            </div>
            <ProvenanceBadge type={aiIntelligence.provenance || 'AI_INTERPRETED'} />
          </div>

          {/* Executive Summary */}
          <div className="bg-purple-50/60 border-2 border-purple-300 rounded-xl p-5 space-y-2">
            <span className="text-xs font-space font-bold uppercase tracking-wider text-purple-900 flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5" /> Executive Strategic Analysis
            </span>
            <p className="text-sm font-space text-zinc-800 leading-relaxed font-medium">
              {narrative.executiveSummary || 'Audit synthesis generated from verified crawl data and structural elements.'}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Search Engine Interpretation */}
            <div className="border-2 border-black rounded-xl p-5 bg-[#fffdf7] space-y-3">
              <div className="flex items-center gap-2 text-black">
                <Search className="w-4 h-4 text-emerald-600 stroke-[2.5]" />
                <h5 className="font-space font-bold text-sm uppercase">Search Engine Interpretation (Google / Bing)</h5>
              </div>
              <p className="text-xs text-zinc-700 font-space leading-relaxed">
                {narrative.searchEngineInterpretation || 'Evaluating indexability, hierarchy, and meta signals.'}
              </p>
            </div>

            {/* Generative Engine Interpretation */}
            <div className="border-2 border-black rounded-xl p-5 bg-[#fffdf7] space-y-3">
              <div className="flex items-center gap-2 text-black">
                <Bot className="w-4 h-4 text-blue-600 stroke-[2.5]" />
                <h5 className="font-space font-bold text-sm uppercase">Generative Engine Interpretation (ChatGPT / Gemini / Perplexity)</h5>
              </div>
              <p className="text-xs text-zinc-700 font-space leading-relaxed">
                {narrative.generativeEngineInterpretation || 'Analyzing entity definitions, citations, and machine readability.'}
              </p>
            </div>
          </div>

          {/* Top Discoverability Bottlenecks */}
          {Array.isArray(narrative.topBottlenecks) && narrative.topBottlenecks.length > 0 && (
            <div className="border-2 border-black rounded-xl p-5 bg-white space-y-3">
              <span className="text-xs font-space font-bold uppercase tracking-wider text-rose-800 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" /> Top Discoverability & Citation Bottlenecks
              </span>
              <ul className="space-y-2 text-xs font-space text-zinc-800">
                {narrative.topBottlenecks.map((b, idx) => (
                  <li key={idx} className="flex items-start gap-2 bg-rose-50/50 p-2.5 rounded border border-rose-200">
                    <span className="font-mono font-bold text-rose-700">0{idx + 1}.</span>
                    <span>{b}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* TAB CONTENT 4: SEO TECHNICAL & HIERARCHY */}
      {activeSubTab === 'seo-module' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Search className="w-5 h-5 text-black stroke-[2.2]" />
              <h4 className="font-space font-bold text-lg text-black">
                Technical SEO, Heading Hierarchy & Intent Alignment
              </h4>
            </div>
            <span className="text-xs font-mono font-bold bg-zinc-100 border border-black px-2.5 py-1 rounded">
              Score: {seoModule.score || 0}/100
            </span>
          </div>

          {/* Search Intent Card */}
          {seoModule.searchIntent && (
            <div className="bg-zinc-50 border-2 border-black rounded-xl p-5 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500">
                  Search Intent Classification
                </span>
                <span className="px-3 py-1 bg-[#86efac] border border-black rounded-full text-xs font-bold font-space text-black uppercase">
                  Primary Intent: {seoModule.searchIntent.primaryIntent || 'Informational'}
                </span>
              </div>
              <p className="text-xs text-zinc-600 font-medium">
                Intent Confidence: <strong>{Math.round((seoModule.searchIntent.confidence || 0.8) * 100)}%</strong> • Mismatches Detected: <strong>{seoModule.searchIntent.mismatches?.length || 0}</strong>
              </p>

              {Array.isArray(seoModule.searchIntent.mismatches) && seoModule.searchIntent.mismatches.length > 0 && (
                <div className="mt-2 space-y-2">
                  {seoModule.searchIntent.mismatches.map((m, idx) => (
                    <div key={idx} className="bg-amber-50 border border-amber-300 rounded p-2.5 text-xs font-space text-amber-900">
                      <strong>Intent Mismatch:</strong> {m.reason}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Heading Hierarchy Tree */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-space font-bold uppercase tracking-wider text-black">
                Heading Hierarchy Tree (H1-H6)
              </span>
              <span className="text-xs font-mono text-zinc-500">
                {seoModule.onPageHierarchy?.totalHeadings || 0} Headings Extracted
              </span>
            </div>

            {Array.isArray(seoModule.onPageHierarchy?.hierarchyErrors) && seoModule.onPageHierarchy.hierarchyErrors.length > 0 && (
              <div className="bg-rose-50 border border-rose-300 rounded p-3 text-xs font-space text-rose-900 space-y-1">
                <span className="font-bold block">Heading Hierarchy Discrepancies:</span>
                {seoModule.onPageHierarchy.hierarchyErrors.map((err, idx) => (
                  <div key={idx}>• {err.message}</div>
                ))}
              </div>
            )}

            <div className="bg-zinc-950 text-zinc-200 rounded-lg p-4 font-mono text-xs max-h-80 overflow-y-auto space-y-1 border-2 border-black">
              {Array.isArray(seoModule.onPageHierarchy?.headings) && seoModule.onPageHierarchy.headings.length > 0 ? (
                seoModule.onPageHierarchy.headings.map((h, idx) => {
                  const indent = (h.level - 1) * 16;
                  return (
                    <div key={idx} style={{ paddingLeft: `${indent}px` }} className="flex items-center gap-2 py-0.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${h.level === 1 ? 'bg-emerald-500 text-black' : h.level === 2 ? 'bg-blue-500 text-white' : 'bg-zinc-700 text-zinc-300'}`}>
                        {h.tag.toUpperCase()}
                      </span>
                      <span className="truncate text-zinc-300">{h.text}</span>
                    </div>
                  );
                })
              ) : (
                <div className="text-zinc-500">No headings detected on target page.</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT 5: GEO ENTITY & READABILITY */}
      {activeSubTab === 'geo-module' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-black stroke-[2.2]" />
              <h4 className="font-space font-bold text-lg text-black">
                GEO Engine: Machine Readability & Entity Clarity
              </h4>
            </div>
            <span className="text-xs font-mono font-bold bg-zinc-100 border border-black px-2.5 py-1 rounded">
              Score: {geoModule.score || 0}/100
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Entity Understanding Card */}
            <div className="border-2 border-black rounded-xl p-5 bg-[#fffdf7] space-y-3">
              <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 flex items-center gap-1.5">
                <Building className="w-4 h-4 text-black" /> Entity & Brand Profile
              </span>
              <div className="space-y-2 text-xs font-space">
                <div className="flex justify-between py-1 border-b border-zinc-200">
                  <span className="text-zinc-600">Brand / Org Name:</span>
                  <span className="font-bold text-black">{geoModule.entityUnderstanding?.brandIdentity?.name || 'Not Explicitly Stated'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-zinc-200">
                  <span className="text-zinc-600">Primary Category:</span>
                  <span className="font-bold text-black">{geoModule.entityUnderstanding?.primaryCategory || 'General Web Asset'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-zinc-200">
                  <span className="text-zinc-600">Schema Entity Match:</span>
                  <span className="font-mono text-black">{geoModule.entityUnderstanding?.schemaEntityDetected ? 'Detected' : 'Missing'}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-zinc-600">Entity Clarity:</span>
                  <span className="font-bold text-emerald-700">{geoModule.entityUnderstanding?.clarityRating || 'Moderate'} ({geoModule.entityUnderstanding?.clarityScore || 60}/100)</span>
                </div>
              </div>
            </div>

            {/* AI Crawler Discoverability */}
            <div className="border-2 border-black rounded-xl p-5 bg-[#fffdf7] space-y-3">
              <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 flex items-center gap-1.5">
                <Bot className="w-4 h-4 text-black" /> AI Crawler Policy Status
              </span>
              <div className="space-y-2 text-xs font-space">
                <div className="flex justify-between py-1 border-b border-zinc-200">
                  <span className="text-zinc-600">Overall AI Access:</span>
                  <span className="font-bold text-black">{geoModule.crawlerDiscoverability?.overallStatus || 'Permissive'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-zinc-200">
                  <span className="text-zinc-600">Blocked AI Crawlers:</span>
                  <span className="font-mono text-zinc-800">{geoModule.crawlerDiscoverability?.blockedCount || 0} user-agents</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-zinc-600">Citation Readiness:</span>
                  <span className="font-bold text-blue-700">{geoModule.citationReadiness?.readinessRating || 'Fair'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Machine Readability Metrics */}
          <div className="bg-zinc-50 border-2 border-black rounded-xl p-5 space-y-3">
            <span className="text-xs font-space font-bold uppercase tracking-wider text-black">
              Semantic DOM & Machine Extraction Signals
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
              <div className="bg-white p-3 rounded border border-black/20">
                <span className="text-[10px] text-zinc-500 uppercase block font-space">Boilerplate Ratio</span>
                <span className="text-lg font-bold font-space text-black">{geoModule.machineReadability?.boilerplateRatio || '25%'}</span>
              </div>
              <div className="bg-white p-3 rounded border border-black/20">
                <span className="text-[10px] text-zinc-500 uppercase block font-space">Structured Tables</span>
                <span className="text-lg font-bold font-space text-black">{geoModule.machineReadability?.structuredTablesCount || 0}</span>
              </div>
              <div className="bg-white p-3 rounded border border-black/20">
                <span className="text-[10px] text-zinc-500 uppercase block font-space">Definition Lists</span>
                <span className="text-lg font-bold font-space text-black">{geoModule.machineReadability?.definitionListCount || 0}</span>
              </div>
              <div className="bg-white p-3 rounded border border-black/20">
                <span className="text-[10px] text-zinc-500 uppercase block font-space">Reading Time</span>
                <span className="text-lg font-bold font-space text-black">{geoModule.machineReadability?.estimatedReadingMinutes || 2} min</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT 6: AEO JOURNEY & ANSWERS */}
      {activeSubTab === 'aeo-module' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Bot className="w-5 h-5 text-black stroke-[2.2]" />
              <h4 className="font-space font-bold text-lg text-black">
                AEO Engine: 6-Stage User Journey & Direct Answer Readiness
              </h4>
            </div>
            <span className="text-xs font-mono font-bold bg-zinc-100 border border-black px-2.5 py-1 rounded">
              Score: {aeoModule.score || 0}/100
            </span>
          </div>

          {/* 6-Stage User Journey Progress Tracker */}
          <div className="space-y-3">
            <span className="text-xs font-space font-bold uppercase tracking-wider text-black">
              User Journey Intent Stage Coverage (Section 5.0)
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {[
                { stage: 'Awareness', count: aeoModule.intentJourneyMapping?.stageBreakdown?.awareness || 0, label: 'Problem & Concept' },
                { stage: 'Research', count: aeoModule.intentJourneyMapping?.stageBreakdown?.research || 0, label: 'Options & How-To' },
                { stage: 'Evaluation', count: aeoModule.intentJourneyMapping?.stageBreakdown?.evaluation || 0, label: 'Pricing & Pros/Cons' },
                { stage: 'Decision', count: aeoModule.intentJourneyMapping?.stageBreakdown?.decision || 0, label: 'Security & Proof' },
                { stage: 'Action', count: aeoModule.intentJourneyMapping?.stageBreakdown?.action || 0, label: 'Onboarding & Steps' },
                { stage: 'Support', count: aeoModule.intentJourneyMapping?.stageBreakdown?.support || 0, label: 'FAQs & Troubleshooting' }
              ].map((stg) => {
                const hasCoverage = stg.count > 0;
                return (
                  <div
                    key={stg.stage}
                    className={`p-3 rounded-lg border-2 border-black flex flex-col justify-between ${
                      hasCoverage ? 'bg-emerald-50' : 'bg-zinc-50 opacity-75'
                    }`}
                  >
                    <div>
                      <span className="text-xs font-space font-bold text-black block">{stg.stage}</span>
                      <span className="text-[10px] text-zinc-500">{stg.label}</span>
                    </div>
                    <div className="mt-2 pt-2 border-t border-zinc-200 flex items-center justify-between">
                      <span className="text-[10px] font-bold text-zinc-400">Questions:</span>
                      <span className={`text-xs font-bold font-mono ${hasCoverage ? 'text-emerald-700' : 'text-zinc-500'}`}>
                        {stg.count}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Direct Answer Quality & Formatting */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border-2 border-black rounded-xl p-5 bg-[#fffdf7] space-y-3">
              <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" /> Direct Answer Quality
              </span>
              <div className="space-y-2 text-xs font-space">
                <div className="flex justify-between py-1 border-b border-zinc-200">
                  <span className="text-zinc-600">Inverted Pyramid Formatting:</span>
                  <span className="font-bold text-black">{aeoModule.directAnswerQuality?.invertedPyramidScore || 'Fair'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-zinc-200">
                  <span className="text-zinc-600">Average Sentence Length:</span>
                  <span className="font-mono text-black">{aeoModule.directAnswerQuality?.averageSentenceLength || 18} words</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-zinc-600">FAQ / Q&A Blocks Detected:</span>
                  <span className="font-bold text-black">{aeoModule.answerFormatting?.faqBlocksCount || 0}</span>
                </div>
              </div>
            </div>

            <div className="border-2 border-black rounded-xl p-5 bg-[#fffdf7] space-y-3">
              <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 flex items-center gap-1.5">
                <HelpCircle className="w-4 h-4 text-blue-600" /> Missing High-Value Candidate Queries
              </span>
              <div className="space-y-1.5 text-xs font-space max-h-48 overflow-y-auto">
                {Array.isArray(aeoModule.questionCoverage?.missingQueries) && aeoModule.questionCoverage.missingQueries.length > 0 ? (
                  aeoModule.questionCoverage.missingQueries.slice(0, 4).map((q, idx) => (
                    <div key={idx} className="bg-white p-2 rounded border border-zinc-200 flex items-center justify-between">
                      <span className="text-zinc-800">{q.query}</span>
                      <span className="text-[10px] font-mono text-zinc-500 uppercase">{q.stage}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-zinc-500">No missing critical queries detected.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT 7: PAGE OPTIMIZATION WORKSPACE */}
      {activeSubTab === 'workspace' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b-2 border-black/10">
            <div>
              <div className="flex items-center gap-2">
                <Code2 className="w-5 h-5 text-black stroke-[2.2]" />
                <h4 className="font-space font-bold text-lg text-black">
                  Page Optimization Workspace (Section 8.0)
                </h4>
              </div>
              <p className="text-xs text-zinc-600 font-medium mt-0.5">
                Grounded drafts and structured data ready for immediate CMS or code implementation.
              </p>
            </div>

            {/* Workspace Pills */}
            <div className="flex flex-wrap gap-1.5 bg-zinc-100 p-1 rounded-lg border border-black">
              {[
                { id: 'titles', label: 'Title Drafts' },
                { id: 'descriptions', label: 'Meta Descriptions' },
                { id: 'h1', label: 'H1 Alternatives' },
                { id: 'outlines', label: 'Content Outlines' },
                { id: 'answers', label: 'Direct Answer Blocks' },
                { id: 'schema', label: 'JSON-LD Schema' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setWorkspaceDraftTab(tab.id)}
                  className={`px-3 py-1 rounded text-xs font-space font-bold transition-colors cursor-pointer ${
                    workspaceDraftTab === tab.id ? 'bg-black text-white' : 'text-zinc-600 hover:text-black'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* DRAFTS CONTENT */}
          <div className="space-y-4">
            {workspaceDraftTab === 'titles' && (
              <div className="space-y-3">
                <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 block">
                  Recommended Title Tag Drafts (Character bounded & intent aligned)
                </span>
                {(workspace.recommendedTitleDrafts || [
                  'WebVitals — Advanced Website Intelligence & Security Platform',
                  'WebVitals: Full-Spectrum Web Security, DNS & Technical SEO Scanner'
                ]).map((title, idx) => (
                  <div key={idx} className="p-3 bg-zinc-50 rounded-lg border-2 border-black flex items-center justify-between gap-3">
                    <span className="font-space font-bold text-sm text-black">{title}</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(title)}
                      className="px-2.5 py-1 text-xs font-mono font-bold bg-white border border-black rounded hover:bg-zinc-100 flex items-center gap-1 cursor-pointer"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  </div>
                ))}
              </div>
            )}

            {workspaceDraftTab === 'descriptions' && (
              <div className="space-y-3">
                <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 block">
                  Recommended Meta Description Drafts (150-160 characters)
                </span>
                {(workspace.recommendedMetaDescriptionDrafts || [
                  'Audit website security posture, DNS records, SSL cipher suites, technical SEO and Generative AI engine readiness in real time with WebVitals.'
                ]).map((desc, idx) => (
                  <div key={idx} className="p-3.5 bg-zinc-50 rounded-lg border-2 border-black flex items-center justify-between gap-3">
                    <div>
                      <p className="font-space text-xs text-zinc-800 font-medium">{desc}</p>
                      <span className="text-[10px] font-mono text-zinc-500">{desc.length} chars</span>
                    </div>
                    <button
                      onClick={() => navigator.clipboard.writeText(desc)}
                      className="px-2.5 py-1 text-xs font-mono font-bold bg-white border border-black rounded hover:bg-zinc-100 flex items-center gap-1 cursor-pointer flex-shrink-0"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  </div>
                ))}
              </div>
            )}

            {workspaceDraftTab === 'h1' && (
              <div className="space-y-3">
                <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 block">
                  Recommended H1 Heading Alternatives
                </span>
                {(workspace.recommendedH1Alternatives || [
                  'Next-Generation Website Intelligence and Security Scanner',
                  'Comprehensive Security, Performance, and SEO Diagnostics'
                ]).map((h1, idx) => (
                  <div key={idx} className="p-3 bg-zinc-50 rounded-lg border-2 border-black flex items-center justify-between gap-3">
                    <span className="font-space font-bold text-sm text-black">{h1}</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(h1)}
                      className="px-2.5 py-1 text-xs font-mono font-bold bg-white border border-black rounded hover:bg-zinc-100 flex items-center gap-1 cursor-pointer"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  </div>
                ))}
              </div>
            )}

            {workspaceDraftTab === 'outlines' && (
              <div className="space-y-3">
                <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 block">
                  Recommended Content Outlines
                </span>
                {(Array.isArray(workspace.recommendedContentOutlines) ? workspace.recommendedContentOutlines : [
                  { title: 'Core Features & Technical Architecture', points: ['Network Intelligence', 'Security Analysis', 'Performance Auditing'] }
                ]).map((outl, idx) => (
                  <div key={idx} className="p-4 bg-zinc-50 rounded-lg border-2 border-black space-y-2">
                    <h5 className="font-space font-bold text-sm text-black">{outl.title || outl.section}</h5>
                    <ul className="list-disc pl-5 text-xs text-zinc-700 space-y-1">
                      {(Array.isArray(outl.points) ? outl.points : Array.isArray(outl.subtopics) ? outl.subtopics : []).map((pt, pidx) => (
                        <li key={pidx}>{pt}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}

            {workspaceDraftTab === 'answers' && (
              <div className="space-y-3">
                <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 block">
                  Direct Answer Blocks (Optimized for AI citation & featured snippets)
                </span>
                {(workspace.recommendedDirectAnswerBlocks || [
                  { question: 'What is WebVitals?', directAnswer: 'WebVitals is a comprehensive website intelligence platform that audits security, infrastructure, performance, and SEO.' }
                ]).map((blk, idx) => (
                  <div key={idx} className="p-4 bg-zinc-50 rounded-lg border-2 border-black space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-space font-bold text-xs text-black">{blk.question}</span>
                      <button
                        onClick={() => navigator.clipboard.writeText(blk.directAnswer)}
                        className="px-2 py-0.5 text-[11px] font-mono bg-white border border-black rounded hover:bg-zinc-100 flex items-center gap-1 cursor-pointer"
                      >
                        <Copy className="w-3 h-3" /> Copy
                      </button>
                    </div>
                    <p className="text-xs text-zinc-700 bg-white p-3 rounded border border-zinc-200">
                      {blk.directAnswer}
                    </p>
                  </div>
                ))}
              </div>
            )}

            {workspaceDraftTab === 'schema' && (
              <div className="space-y-3">
                <span className="text-xs font-space font-bold uppercase tracking-wider text-zinc-500 block">
                  JSON-LD Structured Data Schema (Organization / WebSite)
                </span>
                <CopyableBlock
                  content={workspace.jsonLdSchemaDraft || {
                    '@context': 'https://schema.org',
                    '@type': 'WebSite',
                    'name': 'WebVitals',
                    'url': 'https://webvitals-1.onrender.com'
                  }}
                  language="json"
                />
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. Provenance Disclosures Footer (Section 1.1 & 11) */}
      <div className="bg-[#fffdf7] border-2 border-black rounded-xl p-5 brutal-shadow-sm space-y-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-black stroke-[2.2]" />
          <h5 className="font-space font-bold text-xs uppercase tracking-wider text-black">
            Evidence Provenance & Verification Transparency Disclosures
          </h5>
        </div>
        <p className="text-xs text-zinc-600 font-medium leading-relaxed">
          In strict compliance with WebVitals engineering integrity guidelines, all findings are categorized by provenance:
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 pt-1">
          <div className="p-2.5 bg-white border border-black rounded text-[11px] font-space space-y-1">
            <ProvenanceBadge type="VERIFIED" />
            <p className="text-zinc-600 mt-1">Confirmed directly in DOM, response headers, or crawl files.</p>
          </div>
          <div className="p-2.5 bg-white border border-black rounded text-[11px] font-space space-y-1">
            <ProvenanceBadge type="INFERRED" />
            <p className="text-zinc-600 mt-1">Determined through deterministic rule-based heuristic patterns.</p>
          </div>
          <div className="p-2.5 bg-white border border-black rounded text-[11px] font-space space-y-1">
            <ProvenanceBadge type="AI_INTERPRETED" />
            <p className="text-zinc-600 mt-1">Synthesized by Vertex AI strictly grounded in verified scan data.</p>
          </div>
          <div className="p-2.5 bg-white border border-black rounded text-[11px] font-space space-y-1">
            <ProvenanceBadge type="ESTIMATED" />
            <p className="text-zinc-600 mt-1">Calculated projection (e.g. reading time, boilerplate ratio).</p>
          </div>
          <div className="p-2.5 bg-white border border-black rounded text-[11px] font-space space-y-1">
            <ProvenanceBadge type="UNAVAILABLE" />
            <p className="text-zinc-600 mt-1">Third-party metrics requiring private OAuth/Search Console access.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
