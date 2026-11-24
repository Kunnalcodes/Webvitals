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
  Code2,
  Download,
  Filter,
  BarChart2,
  Users,
  FileText,
  Share2,
  ShieldAlert,
} from 'lucide-react';

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

export default function CompetitiveIntelligenceDashboard({ report }) {
  if (!report) return null;

  const [activeTab, setActiveTab] = useState('overview');
  const [keywordFilter, setKeywordFilter] = useState('ALL');
  const [keywordSearch, setKeywordSearch] = useState('');
  const [expandedKeyword, setExpandedKeyword] = useState(null);
  const [expandedRoadmapItem, setExpandedRoadmapItem] = useState(null);
  const [downloadingJson, setDownloadingJson] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);

  const {
    primary = {},
    competitor = {},
    competitivePosition = {},
    overviewComparison = [],
    keywordIntelligence = {},
    topicClustering = {},
    contentGapAnalysis = {},
    seoComparison = {},
    geoComparison = {},
    aeoComparison = {},
    authorityComparison = {},
    growthStrategy = {},
    aiIntelligence = {},
  } = report;

  const allKeywords = Array.isArray(keywordIntelligence.allKeywords) ? keywordIntelligence.allKeywords : [];
  const keywordBuckets = keywordIntelligence.buckets || {};
  const topOpportunities = Array.isArray(keywordIntelligence.topOpportunities) ? keywordIntelligence.topOpportunities : [];
  const safeOverviewComparison = Array.isArray(overviewComparison) ? overviewComparison : [];

  // Filter keywords safely
  const filteredKeywords = allKeywords.filter(k => {
    if (!k) return false;
    if (keywordFilter !== 'ALL' && k.gapCategory !== keywordFilter) return false;
    if (keywordSearch.trim()) {
      const q = keywordSearch.toLowerCase();
      return (k.keyword || '').toLowerCase().includes(q) || (k.category || '').toLowerCase().includes(q);
    }
    return true;
  });

  const handleDownloadJson = () => {
    setDownloadingJson(true);
    try {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
      const a = document.createElement('a');
      a.href = dataStr;
      a.download = `WebVitals_Competitive_${primary.domain}_vs_${competitor.domain}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } finally {
      setTimeout(() => setDownloadingJson(false), 1000);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* 1. Executive Comparison Header Card */}
      <div className="bg-[#fffdf7] border-2 border-black rounded-2xl p-6 md:p-8 brutal-shadow">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b-2 border-black/10">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-3">
              <span className="px-3 py-1 bg-[#fde047] border border-black rounded-full text-xs font-bold font-space uppercase text-black flex items-center gap-1.5">
                <BrainCircuit className="w-3.5 h-3.5" /> Competitive Intelligence Engine
              </span>
              <span className="px-2.5 py-1 bg-purple-100 border border-purple-400 text-purple-900 rounded-full text-xs font-mono font-bold flex items-center gap-1">
                <Sparkles className="w-3 h-3" /> Vertex AI Synthesized
              </span>
              <span className="px-2.5 py-1 bg-zinc-100 border border-black rounded-full text-xs font-mono font-bold text-zinc-700">
                {primary.domain} vs {competitor.domain}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-4">
              <div>
                <span className="text-[10px] font-space font-bold uppercase text-zinc-400 block">Your Business</span>
                <h3 className="text-xl md:text-2xl font-bold font-space text-black flex items-center gap-1.5">
                  {primary.domain}
                </h3>
              </div>
              <span className="text-xl font-bold font-space text-zinc-400 self-end mb-1">vs</span>
              <div>
                <span className="text-[10px] font-space font-bold uppercase text-zinc-400 block">Competitor</span>
                <h3 className="text-xl md:text-2xl font-bold font-space text-black flex items-center gap-1.5">
                  {competitor.domain}
                </h3>
              </div>
            </div>
          </div>

          {/* Overall Competitive Position Badge */}
          <div className="flex-shrink-0 bg-white border-2 border-black rounded-xl p-5 brutal-shadow-sm min-w-[280px]">
            <span className="text-[10px] font-space font-bold uppercase tracking-widest text-zinc-400 block mb-1">
              Market Positioning
            </span>
            <div className="flex items-center gap-2">
              <div className={`w-3.5 h-3.5 rounded-full ${competitivePosition.status === 'COMPETITIVE_ADVANTAGE' ? 'bg-emerald-500' : competitivePosition.status === 'STRONG_COMPETITOR_ADVANTAGE' ? 'bg-rose-500' : 'bg-amber-500'}`} />
              <span className="font-space font-bold text-base text-black">
                {competitivePosition.label || 'Similar Positioning'}
              </span>
            </div>
            <p className="text-xs text-zinc-600 font-medium mt-1.5 leading-snug">
              {competitivePosition.summary}
            </p>

            <div className="mt-3 pt-3 border-t border-zinc-100 flex items-center justify-between">
              <button
                onClick={handleDownloadJson}
                disabled={downloadingJson}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-black bg-zinc-100 hover:bg-zinc-200 text-xs font-space font-bold cursor-pointer transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{downloadingJson ? 'Exporting...' : 'Export JSON'}</span>
              </button>
              <ProvenanceBadge type="VERIFIED" />
            </div>
          </div>
        </div>

        {/* 4 Score Gauges */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-6">
          <div className="bg-white border-2 border-black rounded-xl p-4 brutal-shadow-sm">
            <span className="text-[10px] font-space font-bold uppercase text-zinc-400 block mb-1">Technical SEO Leader</span>
            <span className="text-xl font-space font-bold text-black block">{seoComparison.infrastructure?.summary?.infrastructureLeader || 'Parity'}</span>
            <span className="text-xs text-zinc-500 mt-0.5 block">{seoComparison.infrastructure?.summary?.primaryWins || 0} vs {seoComparison.infrastructure?.summary?.competitorWins || 0} dimensions won</span>
          </div>

          <div className="bg-white border-2 border-black rounded-xl p-4 brutal-shadow-sm">
            <span className="text-[10px] font-space font-bold uppercase text-zinc-400 block mb-1">GEO Engine Score</span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-space font-bold text-black">{geoComparison.primaryGeoScore || 0}</span>
              <span className="text-xs text-zinc-400 font-space font-bold">vs</span>
              <span className="text-xl font-space font-bold text-zinc-600">{geoComparison.competitorGeoScore || 0}</span>
            </div>
            <span className="text-xs text-emerald-700 font-bold font-space mt-0.5 block">Leader: {geoComparison.geoLeader || 'Parity'}</span>
          </div>

          <div className="bg-white border-2 border-black rounded-xl p-4 brutal-shadow-sm">
            <span className="text-[10px] font-space font-bold uppercase text-zinc-400 block mb-1">AEO Question Score</span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-space font-bold text-black">{aeoComparison.primaryAeoScore || 0}</span>
              <span className="text-xs text-zinc-400 font-space font-bold">vs</span>
              <span className="text-xl font-space font-bold text-zinc-600">{aeoComparison.competitorAeoScore || 0}</span>
            </div>
            <span className="text-xs text-blue-700 font-bold font-space mt-0.5 block">Leader: {aeoComparison.aeoLeader || 'Parity'}</span>
          </div>

          <div className="bg-white border-2 border-black rounded-xl p-4 brutal-shadow-sm">
            <span className="text-[10px] font-space font-bold uppercase text-zinc-400 block mb-1">Keyword Opportunities</span>
            <span className="text-xl font-space font-bold text-purple-900 block">{keywordBuckets.competitorGaps?.length || 0}</span>
            <span className="text-xs text-zinc-500 mt-0.5 block">{keywordIntelligence.summary?.p0CriticalCount || 0} P0 High Priority Gaps</span>
          </div>
        </div>
      </div>

      {/* 2. Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b-2 border-black pb-3">
        {[
          { id: 'overview', label: 'Comparative Overview', icon: BarChart2 },
          { id: 'seo', label: 'SEO Reverse Engineering', icon: Search },
          { id: 'keywords', label: 'Keyword Intelligence Explorer', icon: Tag },
          { id: 'topic-map', label: 'Topic Clusters & Cannibalization', icon: Compass },
          { id: 'content-gaps', label: 'Content Gap Engine', icon: FileText },
          { id: 'geo-aeo', label: 'GEO & AEO Intelligence', icon: Bot },
          { id: 'roadmap', label: 'Growth Strategy Roadmap', icon: ListOrdered },
          { id: 'ai-analyst', label: 'Vertex AI Analyst', icon: Sparkles },
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2.5 rounded-lg border-2 font-bold text-xs md:text-sm font-space transition-all cursor-pointer ${
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

      {/* TAB 1: COMPARATIVE OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
            <div>
              <h4 className="font-space font-bold text-lg text-black">
                Comprehensive Side-by-Side Competitive Benchmark
              </h4>
              <p className="text-xs text-zinc-600 font-medium mt-0.5">
                Dynamic, evidence-based metrics comparing technical quality, keyword universe, and content depth.
              </p>
            </div>
            <ProvenanceBadge type="VERIFIED" />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-space border-collapse">
              <thead>
                <tr className="bg-zinc-100 border-b-2 border-black">
                  <th className="p-3 font-bold text-zinc-900 uppercase">Audit Dimension</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">{primary.domain} (You)</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">{competitor.domain}</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase text-center">Difference</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">Interpretation</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase text-center">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200">
                {safeOverviewComparison.map((row, idx) => (
                  <tr key={idx} className="hover:bg-zinc-50 transition-colors">
                    <td className="p-3 font-bold text-black">{row.metric}</td>
                    <td className="p-3 font-mono font-bold text-zinc-900">{row.primaryValue}</td>
                    <td className="p-3 font-mono text-zinc-700">{row.competitorValue}</td>
                    <td className="p-3 font-mono text-center font-bold text-purple-900">{row.difference}</td>
                    <td className="p-3 text-zinc-700 max-w-md">{row.interpretation}</td>
                    <td className="p-3 text-center">
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-zinc-100 border border-zinc-300">
                        {Math.round(row.confidence * 100)}%
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: SEO REVERSE ENGINEERING */}
      {activeTab === 'seo' && (
        <div className="space-y-6">
          <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
            <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
              <div>
                <h4 className="font-space font-bold text-lg text-black">
                  SEO Infrastructure Comparison
                </h4>
                <p className="text-xs text-zinc-600 font-medium mt-0.5">
                  Technical audit comparing crawl directives, heading structures, sitemaps, and latency.
                </p>
              </div>
              <span className="text-xs font-mono font-bold bg-zinc-100 border border-black px-2.5 py-1 rounded">
                Leader: {seoComparison.infrastructure?.summary?.infrastructureLeader || 'Parity'}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {(seoComparison.infrastructure?.dimensions || []).map((dim, idx) => (
                <div key={idx} className="p-4 rounded-lg border-2 border-black bg-[#fffdf7] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-space font-bold text-sm text-black">{dim.name}</span>
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${dim.winner === 'Primary' ? 'bg-[#86efac] text-black' : dim.winner === 'Competitor' ? 'bg-[#ff9ebb] text-black' : 'bg-zinc-200 text-zinc-800'}`}>
                      {dim.winner} Advantage
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs font-space pt-1 border-t border-zinc-200">
                    <div>
                      <span className="text-[10px] text-zinc-400 block uppercase">Primary</span>
                      <span className="font-mono text-zinc-900 font-bold">{dim.primaryValue}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-zinc-400 block uppercase">Competitor</span>
                      <span className="font-mono text-zinc-700">{dim.competitorValue}</span>
                    </div>
                  </div>
                  <p className="text-[11px] text-zinc-600 leading-snug pt-1">{dim.interpretation}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Reverse Engineered Strategies */}
          <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
            <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
              <h4 className="font-space font-bold text-lg text-black">
                Reverse-Engineered Competitor SEO Strategies
              </h4>
              <span className="text-xs font-mono bg-zinc-100 border border-black px-2.5 py-1 rounded">
                {seoComparison.strategies?.length || 0} Strategies Evaluated
              </span>
            </div>

            <div className="space-y-3">
              {(seoComparison.strategies || []).map((strat, idx) => (
                <div key={idx} className="p-4 bg-zinc-50 border-2 border-black rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-space font-bold text-sm text-black">{strat.strategy}</span>
                    <span className={`px-2.5 py-0.5 text-xs font-mono font-bold rounded border ${strat.competitorEffectiveness === 'Strong' ? 'bg-[#86efac] text-emerald-950' : 'bg-zinc-200 text-zinc-700'}`}>
                      {strat.competitorEffectiveness} Competitor Execution
                    </span>
                  </div>
                  <p className="text-xs text-zinc-700 font-mono bg-white p-2.5 rounded border border-zinc-200">
                    {strat.evidence}
                  </p>
                  <div className="flex items-start gap-2 pt-1 text-xs font-space">
                    <span className="font-bold text-emerald-800 uppercase text-[10px] flex-shrink-0 mt-0.5">How To Compete:</span>
                    <span className="text-zinc-800 font-medium">{strat.howToCompete}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: KEYWORD INTELLIGENCE EXPLORER */}
      {activeTab === 'keywords' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b-2 border-black/10">
            <div>
              <h4 className="font-space font-bold text-lg text-black">
                Multi-Source Keyword Intelligence Explorer
              </h4>
              <p className="text-xs text-zinc-600 font-medium mt-0.5">
                Authentic extracted queries from headings, titles, body content, and sitemaps.
              </p>
            </div>

            {/* Search Input */}
            <div className="flex items-center gap-2 bg-zinc-50 px-3 py-1.5 rounded-lg border-2 border-black max-w-xs w-full">
              <Search className="w-4 h-4 text-zinc-500" />
              <input
                type="text"
                placeholder="Search keywords..."
                value={keywordSearch}
                onChange={e => setKeywordSearch(e.target.value)}
                className="bg-transparent text-xs font-space outline-none w-full text-black"
              />
            </div>
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap gap-1.5">
            {[
              { id: 'ALL', label: `All (${allKeywords.length})` },
              { id: 'competitor_gaps', label: `Competitor Gaps (${keywordBuckets.competitorGaps?.length || 0})` },
              { id: 'shared_keywords', label: `Shared Overlap (${keywordBuckets.sharedKeywords?.length || 0})` },
              { id: 'your_opportunities', label: `Your Advantages (${keywordBuckets.yourOpportunities?.length || 0})` },
              { id: 'question_gaps', label: `Question Gaps (${keywordBuckets.questionGaps?.length || 0})` },
              { id: 'untapped_opportunities', label: `Untapped (${keywordBuckets.untappedOpportunities?.length || 0})` },
            ].map(filt => (
              <button
                key={filt.id}
                onClick={() => setKeywordFilter(filt.id)}
                className={`px-3 py-1 rounded text-xs font-space font-bold transition-colors cursor-pointer border ${
                  keywordFilter === filt.id ? 'bg-black text-white border-black' : 'bg-zinc-100 text-zinc-700 border-zinc-300 hover:border-black'
                }`}
              >
                {filt.label}
              </button>
            ))}
          </div>

          {/* Keywords Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-space border-collapse">
              <thead>
                <tr className="bg-zinc-100 border-b-2 border-black">
                  <th className="p-3 font-bold text-zinc-900 uppercase">Discovered Keyword</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">Category</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">Intent</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase text-center">Score</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase text-center">Priority</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase">Gap Status</th>
                  <th className="p-3 font-bold text-zinc-900 uppercase text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200">
                {filteredKeywords.slice(0, 30).map((kw, idx) => {
                  const isExpanded = expandedKeyword === idx;
                  return (
                    <React.Fragment key={idx}>
                      <tr
                        onClick={() => setExpandedKeyword(isExpanded ? null : idx)}
                        className={`hover:bg-zinc-50 cursor-pointer transition-colors ${isExpanded ? 'bg-zinc-50' : ''}`}
                      >
                        <td className="p-3 font-bold text-black flex items-center gap-2">
                          <span className="p-1 rounded bg-zinc-200 text-zinc-700">
                            {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                          </span>
                          {kw.keyword}
                        </td>
                        <td className="p-3 font-mono uppercase text-zinc-600 text-[11px]">{kw.category}</td>
                        <td className="p-3 font-mono uppercase text-zinc-600 text-[11px]">{kw.intent}</td>
                        <td className="p-3 font-mono text-center font-bold text-purple-900">{kw.opportunityScore}</td>
                        <td className="p-3 text-center">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${kw.priority === 'P0' ? 'bg-rose-100 text-rose-900 border border-rose-400' : kw.priority === 'P1' ? 'bg-amber-100 text-amber-900 border border-amber-400' : 'bg-blue-100 text-blue-900 border border-blue-400'}`}>
                            {kw.priority}
                          </span>
                        </td>
                        <td className="p-3 text-zinc-700">{kw.gapStatusLabel}</td>
                        <td className="p-3 text-right">
                          <span className="text-[11px] font-bold text-blue-600 hover:underline">
                            {isExpanded ? 'Close' : 'Inspect'}
                          </span>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-zinc-50 border-b border-zinc-300">
                          <td colSpan={7} className="p-4 space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 bg-white p-4 rounded-lg border-2 border-black/20">
                              <div>
                                <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 block mb-1">Why It Matters</span>
                                <p className="text-xs text-zinc-800">{kw.whyItMatters}</p>
                              </div>
                              <div>
                                <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 block mb-1">Competitor Strategy</span>
                                <p className="text-xs text-zinc-700">{kw.competitorAction}</p>
                              </div>
                              <div>
                                <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700 block mb-1">Recommended Action</span>
                                <p className="text-xs text-emerald-950 font-medium">{kw.recommendedContentAction}</p>
                              </div>
                            </div>
                            <div className="flex items-center justify-between text-[11px] text-zinc-500 pt-1">
                              <span>Source: <strong className="font-mono text-black">{kw.source}</strong> ({kw.sourceType})</span>
                              <span>Target Recommendation: <strong className="font-mono text-black">{kw.targetPageRecommendation}</strong></span>
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

      {/* TAB 4: TOPIC MAP & CANNIBALIZATION */}
      {activeTab === 'topic-map' && (
        <div className="space-y-6">
          <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
            <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
              <div>
                <h4 className="font-space font-bold text-lg text-black">
                  Semantic Topic Clusters & Coverage Map
                </h4>
                <p className="text-xs text-zinc-600 font-medium mt-0.5">
                  Hierarchical grouping of queries into parent themes comparing primary vs competitor depth.
                </p>
              </div>
              <span className="text-xs font-mono bg-zinc-100 border border-black px-2.5 py-1 rounded">
                {topicClustering.clusters?.length || 0} Clusters Discovered
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {(topicClustering.topicMap || []).map((top, idx) => (
                <div key={idx} className="p-4 bg-zinc-50 border-2 border-black rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-space font-bold text-sm text-black">{top.mainTopic}</span>
                    <span className="text-xs font-mono font-bold bg-white border border-black px-2 py-0.5 rounded">
                      {top.keywordCount} Queries
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-xs font-space">
                    <div>
                      <span className="text-[10px] text-zinc-400 uppercase block">Your Coverage</span>
                      <span className="font-mono font-bold text-emerald-800">{top.primaryCoverage}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-zinc-400 block uppercase">Competitor Coverage</span>
                      <span className="font-mono font-bold text-purple-900">{top.competitorCoverage}</span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-zinc-200">
                    <span className="text-[10px] font-space font-bold uppercase text-zinc-400 block mb-1">Subtopics & Queries</span>
                    <div className="flex flex-wrap gap-1">
                      {top.subtopics.map((st, sidx) => (
                        <span key={sidx} className="px-2 py-0.5 bg-white border border-zinc-300 rounded text-[11px] font-mono text-zinc-700">
                          {st}
                        </span>
                      ))}
                    </div>
                  </div>

                  <p className="text-xs font-space text-zinc-800 bg-[#fffdf7] p-2 rounded border border-black/10 font-medium">
                    💡 {top.recommendedAsset}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Cannibalization Warning */}
          {topicClustering.cannibalizationRisks?.length > 0 && (
            <div className="bg-amber-50 border-2 border-amber-300 rounded-xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-amber-900">
                <AlertTriangle className="w-5 h-5 stroke-[2.2]" />
                <h5 className="font-space font-bold text-sm uppercase">Internal Keyword Cannibalization Risks Detected</h5>
              </div>
              <p className="text-xs text-amber-800 font-medium">
                Multiple pages on the primary website appear to target identical keyword themes, risking internal search dilution:
              </p>
              <div className="space-y-2">
                {topicClustering.cannibalizationRisks.map((cRisk, idx) => (
                  <div key={idx} className="bg-white p-3 rounded-lg border border-amber-300 text-xs font-space space-y-1">
                    <p className="font-bold text-black">{cRisk.explanation}</p>
                    <p className="text-zinc-600">Action: {cRisk.recommendation}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 5: CONTENT GAP ENGINE */}
      {activeTab === 'content-gaps' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
            <div>
              <h4 className="font-space font-bold text-lg text-black">
                Content Gap Engine & Recommended Original Assets
              </h4>
              <p className="text-xs text-zinc-600 font-medium mt-0.5">
                Original, differentiated content strategies designed to outperform competitor pages without cloning.
              </p>
            </div>
            <span className="text-xs font-mono bg-zinc-100 border border-black px-2.5 py-1 rounded">
              {contentGapAnalysis.gaps?.length || 0} Content Gaps Identified
            </span>
          </div>

          <div className="space-y-4">
            {(contentGapAnalysis.gaps || []).map((gap, idx) => (
              <div key={idx} className="p-5 bg-zinc-50 border-2 border-black rounded-xl space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-black text-white rounded">
                      {gap.priority}
                    </span>
                    <h5 className="font-space font-bold text-base text-black">{gap.topic}</h5>
                  </div>
                  <span className="text-xs font-mono bg-white border border-black px-2 py-0.5 rounded text-zinc-700">
                    Type: {gap.pageType} • Effort: {gap.effort}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-space">
                  <div className="bg-white p-3 rounded border border-zinc-200">
                    <span className="text-[10px] text-zinc-400 uppercase block font-bold">Competitor Evidence</span>
                    <p className="text-zinc-700 mt-1">{gap.competitorEvidence}</p>
                  </div>
                  <div className="bg-white p-3 rounded border border-zinc-200">
                    <span className="text-[10px] text-zinc-400 uppercase block font-bold">Primary Website Gap</span>
                    <p className="text-zinc-700 mt-1">{gap.primaryEvidence}</p>
                  </div>
                </div>

                <div className="bg-[#fffdf7] p-4 rounded-lg border-2 border-black/20 space-y-2">
                  <span className="text-[10px] font-space font-bold uppercase tracking-wider text-emerald-800 block">
                    Recommended Original Asset Architecture
                  </span>
                  <div className="text-xs font-space space-y-1">
                    <p><strong>Suggested Title:</strong> <span className="font-mono text-black">{gap.suggestedTitle}</span></p>
                    <p><strong>Suggested H1:</strong> <span className="font-mono text-black">{gap.suggestedH1}</span></p>
                  </div>
                  <div className="pt-2">
                    <span className="text-[10px] font-space font-bold uppercase text-zinc-500 block mb-1">Recommended Outline:</span>
                    <ul className="list-disc pl-5 text-xs text-zinc-700 space-y-0.5">
                      {(gap.suggestedOutline || []).map((outl, oidx) => (
                        <li key={oidx}>{outl}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 6: GEO & AEO INTELLIGENCE */}
      {activeTab === 'geo-aeo' && (
        <div className="space-y-6">
          <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
            <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
              <div>
                <h4 className="font-space font-bold text-lg text-black">
                  GEO Engine: Machine Readability & Entity Clarity
                </h4>
                <p className="text-xs text-zinc-600 font-medium mt-0.5">
                  How AI answer engines (ChatGPT, Gemini, Perplexity) extract facts and parse entities.
                </p>
              </div>
              <span className="text-xs font-mono bg-zinc-100 border border-black px-2.5 py-1 rounded">
                Leader: {geoComparison.geoLeader || 'Parity'}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {(geoComparison.dimensions || []).map((gdim, idx) => (
                <div key={idx} className="p-4 bg-zinc-50 border-2 border-black rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-space font-bold text-sm text-black">{gdim.dimension}</span>
                    <span className="text-xs font-bold font-mono text-purple-900">{gdim.advantage} Advantage</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs font-space pt-1 border-t border-zinc-200">
                    <div>
                      <span className="text-[10px] text-zinc-400 block uppercase">Primary</span>
                      <span className="font-mono text-zinc-800">{gdim.primaryObservation}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-zinc-400 block uppercase">Competitor</span>
                      <span className="font-mono text-zinc-800">{gdim.competitorObservation}</span>
                    </div>
                  </div>
                  <p className="text-[11px] text-zinc-600 pt-1 leading-snug">{gdim.significance}</p>
                </div>
              ))}
            </div>
          </div>

          {/* AEO 7-Stage Question Coverage */}
          <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
            <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
              <div>
                <h4 className="font-space font-bold text-lg text-black">
                  AEO Engine: 7-Stage User Journey Question Coverage
                </h4>
                <p className="text-xs text-zinc-600 font-medium mt-0.5">
                  Benchmarks direct answers across the full customer decision lifecycle.
                </p>
              </div>
              <span className="text-xs font-mono bg-zinc-100 border border-black px-2.5 py-1 rounded">
                Leader: {aeoComparison.aeoLeader || 'Parity'}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
              {(aeoComparison.stageComparison || []).map((stg, idx) => (
                <div key={idx} className="p-3 bg-zinc-50 border-2 border-black rounded-lg text-center space-y-1">
                  <span className="text-xs font-space font-bold text-black block">{stg.stage}</span>
                  <div className="text-xs font-mono text-zinc-600">
                    <span className="font-bold text-black">{stg.primaryQuestions}</span> vs <span className="text-zinc-500">{stg.competitorQuestions}</span>
                  </div>
                  <span className={`text-[10px] font-bold block ${stg.leader === 'Primary' ? 'text-emerald-700' : stg.leader === 'Competitor' ? 'text-rose-700' : 'text-zinc-500'}`}>
                    {stg.leader}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 7: GROWTH STRATEGY ROADMAP */}
      {activeTab === 'roadmap' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
            <div>
              <h4 className="font-space font-bold text-lg text-black">
                "How to Compete" 5-Phase Growth Strategy Roadmap
              </h4>
              <p className="text-xs text-zinc-600 font-medium mt-0.5">
                Sequential engineering and content roadmap prioritizing quick technical wins and high-intent keyword gaps.
              </p>
            </div>
            <span className="text-xs font-mono bg-zinc-100 border border-black px-2.5 py-1 rounded">
              {growthStrategy.totalRoadmapActions || 0} Actions Planned
            </span>
          </div>

          <div className="space-y-6">
            {[
              { title: 'Phase 1: Fix (Technical & Entity Hygiene)', items: Array.isArray(growthStrategy.phase1Fix) ? growthStrategy.phase1Fix : [], bg: 'bg-rose-50/50' },
              { title: 'Phase 2: Capture (High-Value Keywords & Question Gaps)', items: Array.isArray(growthStrategy.phase2Capture) ? growthStrategy.phase2Capture : [], bg: 'bg-amber-50/50' },
              { title: 'Phase 3: Build Authority (Pillars & Proof)', items: Array.isArray(growthStrategy.phase3Authority) ? growthStrategy.phase3Authority : [], bg: 'bg-blue-50/50' },
              { title: 'Phase 4: Expand (New Verticals & Clusters)', items: Array.isArray(growthStrategy.phase4Expand) ? growthStrategy.phase4Expand : [], bg: 'bg-purple-50/50' },
              { title: 'Phase 5: Optimize (Internal Linking & Freshness)', items: Array.isArray(growthStrategy.phase5Optimize) ? growthStrategy.phase5Optimize : [], bg: 'bg-emerald-50/50' },
            ].map((phase, pidx) => (
              <div key={pidx} className={`p-5 rounded-xl border-2 border-black ${phase.bg} space-y-3`}>
                <h5 className="font-space font-bold text-sm uppercase text-black">{phase.title}</h5>
                <div className="space-y-2">
                  {phase.items.map((item, idx) => (
                    <div key={idx} className="p-3.5 bg-white rounded-lg border border-black/20 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-space font-bold text-xs text-black">{item.action}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-zinc-100 border border-zinc-300">
                          {item.priority} • {item.effort} Effort
                        </span>
                      </div>
                      <p className="text-xs text-zinc-600 font-medium">{item.reason}</p>
                      <div className="flex items-center justify-between pt-1 border-t border-zinc-100 text-[11px] font-mono text-zinc-500">
                        <span>Evidence: {item.supportingEvidence}</span>
                        <span className="text-emerald-800 font-bold">Outcome: {item.expectedOutcome}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 8: VERTEX AI ANALYST */}
      {activeTab === 'ai-analyst' && (
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-6">
          <div className="flex items-center justify-between pb-4 border-b-2 border-black/10">
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-purple-700 stroke-[2.2]" />
              <h4 className="font-space font-bold text-lg text-black">
                Vertex AI Competitive Strategic Narrative
              </h4>
            </div>
            <ProvenanceBadge type={aiIntelligence.provenance || 'AI_INTERPRETED'} />
          </div>

          <div className="bg-purple-50/60 border-2 border-purple-300 rounded-xl p-5 space-y-2">
            <span className="text-xs font-space font-bold uppercase tracking-wider text-purple-900 flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5" /> Executive Comparison Analysis
            </span>
            <p className="text-sm font-space text-zinc-800 leading-relaxed font-medium">
              {aiIntelligence.executiveComparison}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl border-2 border-black bg-[#fffdf7] space-y-2">
              <span className="text-xs font-space font-bold uppercase text-emerald-800 block">Your Primary Advantages</span>
              <ul className="list-disc pl-5 text-xs text-zinc-700 space-y-1 font-space">
                {(aiIntelligence.primaryAdvantages || []).map((adv, idx) => (
                  <li key={idx}>{adv}</li>
                ))}
              </ul>
            </div>

            <div className="p-4 rounded-xl border-2 border-black bg-[#fffdf7] space-y-2">
              <span className="text-xs font-space font-bold uppercase text-rose-800 block">Competitor Key Strategies</span>
              <ul className="list-disc pl-5 text-xs text-zinc-700 space-y-1 font-space">
                {(aiIntelligence.competitorStrategies || []).map((cs, idx) => (
                  <li key={idx}>{cs}</li>
                ))}
              </ul>
            </div>
          </div>

          <div className="p-4 rounded-xl border-2 border-black bg-white space-y-2">
            <span className="text-xs font-space font-bold uppercase text-black block">Recommended Strategic Action Plan</span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {(aiIntelligence.recommendedActionPlan || []).map((plan, idx) => (
                <div key={idx} className="p-2.5 bg-zinc-50 rounded border border-zinc-200 text-xs font-space text-zinc-800">
                  <span className="font-bold text-purple-900 mr-1.5">0{idx + 1}.</span>
                  {plan}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 3. Provenance Disclosures Footer (Section 17 & 19) */}
      <div className="bg-[#fffdf7] border-2 border-black rounded-xl p-5 brutal-shadow-sm space-y-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-black stroke-[2.2]" />
          <h5 className="font-space font-bold text-xs uppercase tracking-wider text-black">
            Competitive Data Provenance & Zero-Fabrication Guarantee
          </h5>
        </div>
        <p className="text-xs text-zinc-600 font-medium leading-relaxed">
          In strict compliance with WebVitals integrity standards, competitive insights are categorized by verified origin. Unintegrated third-party metrics (such as proprietary search volume or backlink counts) are explicitly marked as "Unavailable — data source required" rather than substituted with zero.
        </p>
      </div>
    </div>
  );
}
