import React, { useState } from 'react';
import {
  Sparkles,
  Gauge,
  Image as ImageIcon,
  FileText,
  Share2,
  CheckCircle2,
  AlertCircle,
  Layers,
  Search,
  Zap,
  Globe,
  CheckSquare,
  RefreshCw,
  ExternalLink,
  BrainCircuit,
} from 'lucide-react';
import SeoScoreCard from './SeoScoreCard';
import SeoCategoryCards from './SeoCategoryCards';
import SeoIssuesList from './SeoIssuesList';
import SeoPreviews from './SeoPreviews';
import SeoLighthouseTab from './SeoLighthouseTab';
import SeoMediaLinksTab from './SeoMediaLinksTab';
import SeoAiOptimizerTab from './SeoAiOptimizerTab';
import SeoIntelligenceDashboard from './SeoIntelligenceDashboard';
import ErrorBoundary from '../ErrorBoundary';

const SAMPLE_SEO_PREVIEWS = [
  {
    id: 'optimized',
    title: 'Optimized SaaS Homepage',
    domain: 'https://webvitals.dev',
    score: 96,
    metaTitle: 'WebVitals — 10-Channel Web Security & SEO Engine',
    metaDesc: 'Audit URL security, detect phishing risks, SSL cipher suites, DNS security, and inspect on-page SEO with Google Lighthouse metrics in real time.',
    serpUrl: 'https://webvitals.dev › scanner › web-security',
    lighthouse: { perf: 98, acc: 100, bp: 96, seo: 100 },
    checks: [
      { name: 'H1 Tag Present & Unique (1 found)', status: 'pass' },
      { name: 'Meta Description Optimal (154 characters)', status: 'pass' },
      { name: 'OpenGraph & Twitter Card Active (og:image, twitter:card)', status: 'pass' },
      { name: 'Robots.txt & XML Sitemap Discovered', status: 'pass' },
      { name: 'Canonical Tag & Viewport Responsive', status: 'pass' },
    ],
  },
  {
    id: 'needs_work',
    title: 'Needs Optimization Example',
    domain: 'https://example-shop.com',
    score: 62,
    metaTitle: 'Home | Buy Best Products Online Fast Delivery Today',
    metaDesc: 'Welcome to our online store. We sell lots of good items with discount and fast shipping.',
    serpUrl: 'https://example-shop.com › home',
    lighthouse: { perf: 58, acc: 74, bp: 70, seo: 72 },
    checks: [
      { name: 'Multiple H1 Tags Detected (3 separate H1 elements)', status: 'warn' },
      { name: 'Missing OpenGraph Social Image (og:image)', status: 'fail' },
      { name: '4 Image Elements Missing alt Text Attributes', status: 'fail' },
      { name: 'Canonical URL Tag Missing in Head', status: 'warn' },
      { name: 'Cumulative Layout Shift (CLS) Exceeds Threshold', status: 'fail' },
    ],
  },
];

export default function SeoAuditSection({ seoState, onScan }) {
  const [activePreviewSample, setActivePreviewSample] = useState(SAMPLE_SEO_PREVIEWS[0]);
  const [inputUrl, setInputUrl] = useState('');
  const [activeTab, setActiveTab] = useState('intelligence');

  const report = seoState?.report;
  const status = seoState?.status;
  const isAuditing = status === 'auditing';

  const handleAuditSubmit = (e) => {
    e.preventDefault();
    if (inputUrl.trim()) {
      if (onScan) {
        onScan(inputUrl.trim(), { includeSecurity: true, includeTechStack: true, includeSeo: true });
      } else if (seoState?.audit) {
        seoState.audit(inputUrl.trim());
      }
    }
  };

  return (
    <section id="seo-audit" className="py-20 px-6 bg-[#fffdf7] border-t-2 border-black relative">
      <div className="max-w-7xl mx-auto">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-10">
          <div className="inline-flex items-center gap-2 bg-[#86efac] border-2 border-black px-3.5 py-1.5 rounded-full brutal-shadow-sm mb-4 font-space text-xs font-bold uppercase tracking-wider text-black">
            <Sparkles className="w-4 h-4 stroke-[2.5]" /> Comprehensive Technical SEO & Web Vitals
          </div>
          <h2 className="text-3xl md:text-5xl font-bold font-space tracking-tight text-black mb-4">
            Complete Website SEO & Lighthouse Engine
          </h2>
          <p className="text-base md:text-lg font-medium text-zinc-700 leading-relaxed">
            Audit meta tags, H1-H3 hierarchy, canonical rules, robots.txt, XML sitemaps, OpenGraph social cards, broken links, image alt attributes, and run local Google Lighthouse performance benchmarks with zero API keys.
          </p>
        </div>

        {/* Live SEO Input Search Form */}
        <div className="max-w-2xl mx-auto mb-14">
          <form onSubmit={handleAuditSubmit} className="relative">
            <div className="bg-white p-2.5 rounded-2xl border-2 border-black brutal-shadow-lg flex flex-col sm:flex-row gap-2.5 items-stretch">
              <div className="flex-1 flex items-center gap-3 px-3 bg-zinc-50 rounded-xl border-2 border-black/10">
                <Globe className="w-5 h-5 text-zinc-500 stroke-[2] flex-shrink-0" />
                <input
                  type="text"
                  value={inputUrl}
                  onChange={(e) => setInputUrl(e.target.value)}
                  placeholder="Enter URL for deep SEO & Lighthouse audit..."
                  className="w-full bg-transparent py-3 text-sm md:text-base font-medium font-space outline-none text-zinc-900 placeholder:text-zinc-400"
                />
              </div>
              <button
                type="submit"
                disabled={isAuditing || !inputUrl.trim()}
                className="px-6 py-3.5 bg-[#fde047] text-black rounded-xl font-bold border-2 border-black brutal-shadow brutal-hover flex items-center justify-center gap-2.5 font-space cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex-shrink-0"
              >
                {isAuditing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Auditing SEO...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4 stroke-[2.5]" />
                    <span>Audit SEO</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </div>

        {/* If live report exists, render full interactive SEO Diagnostic Engine */}
        {report && (
          <div className="mb-14 space-y-8 animate-in fade-in duration-300">
            <SeoScoreCard report={report} />

            <div className="flex flex-wrap items-center gap-2 border-b-2 border-black pb-3">
              {[
                { id: 'intelligence', label: 'Intelligence (SEO • GEO • AEO)' },
                { id: 'overview', label: 'Overview & Categories' },
                { id: 'ai-optimizer', label: 'AI Meta & Keywords' },
                { id: 'issues', label: 'All Checks & Fixes' },
                { id: 'previews', label: 'SERP & Social Previews' },
                { id: 'lighthouse', label: 'Lighthouse Performance' },
                { id: 'media', label: 'Images & Links Prober' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-2 rounded-lg border-2 font-bold text-xs md:text-sm font-space transition-all cursor-pointer ${
                    activeTab === tab.id
                      ? 'bg-[#fde047] text-black border-black brutal-shadow-sm'
                      : 'bg-white text-zinc-700 border-zinc-300 hover:border-black'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div>
              {activeTab === 'intelligence' && (
                <ErrorBoundary title="SEO / GEO / AEO Intelligence Dashboard">
                  <SeoIntelligenceDashboard report={report} />
                </ErrorBoundary>
              )}
              {activeTab === 'overview' && (
                <div>
                  <SeoCategoryCards categories={report.categories} />
                  <SeoIssuesList checks={report.checks} recommendations={report.recommendations} />
                </div>
              )}
              {activeTab === 'ai-optimizer' && <SeoAiOptimizerTab aiOptimization={report.aiOptimization} />}
              {activeTab === 'issues' && <SeoIssuesList checks={report.checks} recommendations={report.recommendations} />}
              {activeTab === 'previews' && <SeoPreviews report={report} />}
              {activeTab === 'lighthouse' && <SeoLighthouseTab lighthouse={report.lighthouse} />}
              {activeTab === 'media' && <SeoMediaLinksTab report={report} />}
            </div>
          </div>
        )}

        {/* 4 Core SEO Pillars */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-14">
          <div className="bg-white border-2 border-black rounded-xl p-5 brutal-shadow hover:translate-y-[-2px] transition-transform">
            <div className="w-10 h-10 bg-[#86efac] border-2 border-black rounded-lg flex items-center justify-center mb-3 brutal-shadow-sm">
              <FileText className="w-5 h-5 text-black stroke-[2.5]" />
            </div>
            <h3 className="font-bold text-base font-space text-black mb-1">On-Page & Meta Tags</h3>
            <p className="text-xs text-zinc-600 font-medium leading-relaxed">
              Analyzes title length, meta description, heading structure (H1-H6), canonical URLs, charset, and lang tags.
            </p>
          </div>

          <div className="bg-white border-2 border-black rounded-xl p-5 brutal-shadow hover:translate-y-[-2px] transition-transform">
            <div className="w-10 h-10 bg-[#fde047] border-2 border-black rounded-lg flex items-center justify-center mb-3 brutal-shadow-sm">
              <Gauge className="w-5 h-5 text-black stroke-[2.5]" />
            </div>
            <h3 className="font-bold text-base font-space text-black mb-1">Lighthouse & Core Vitals</h3>
            <p className="text-xs text-zinc-600 font-medium leading-relaxed">
              Benchmarks Performance, FCP, LCP, CLS, Accessibility, Best Practices, and mobile rendering readiness.
            </p>
          </div>

          <div className="bg-white border-2 border-black rounded-xl p-5 brutal-shadow hover:translate-y-[-2px] transition-transform">
            <div className="w-10 h-10 bg-[#bfdbfe] border-2 border-black rounded-lg flex items-center justify-center mb-3 brutal-shadow-sm">
              <Share2 className="w-5 h-5 text-black stroke-[2.5]" />
            </div>
            <h3 className="font-bold text-base font-space text-black mb-1">SERP & Social Previews</h3>
            <p className="text-xs text-zinc-600 font-medium leading-relaxed">
              Renders live previews of Google Search snippets, OpenGraph Facebook cards, and Twitter/X summary embeds.
            </p>
          </div>

          <div className="bg-white border-2 border-black rounded-xl p-5 brutal-shadow hover:translate-y-[-2px] transition-transform">
            <div className="w-10 h-10 bg-[#fed7aa] border-2 border-black rounded-lg flex items-center justify-center mb-3 brutal-shadow-sm">
              <ImageIcon className="w-5 h-5 text-black stroke-[2.5]" />
            </div>
            <h3 className="font-bold text-base font-space text-black mb-1">Media & Link Prober</h3>
            <p className="text-xs text-zinc-600 font-medium leading-relaxed">
              Validates image alt text coverage, internal vs external linking ratios, broken href links, and crawler headers.
            </p>
          </div>
        </div>

        {/* Example Preview Showcase Box */}
        {!report && (
          <div className="bg-white border-2 border-black rounded-2xl p-6 md:p-8 brutal-shadow">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b-2 border-black/10">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="bg-[#86efac] text-black font-bold px-2 py-0.5 rounded border border-black text-[11px] font-space uppercase">
                    SEO Audit Showcase
                  </span>
                  <span className="text-xs text-zinc-500 font-space font-medium">Interactive Benchmark Samples</span>
                </div>
                <h3 className="text-xl md:text-2xl font-bold font-space text-black">
                  How WebVitals Diagnoses Technical SEO & Performance
                </h3>
                <p className="text-xs md:text-sm text-zinc-600 font-medium mt-1">
                  Explore how the engine simulates Google SERP rendering, validates OpenGraph cards, and inspects Core Web Vitals.
                </p>
              </div>

              {/* Selector Tabs */}
              <div className="flex flex-wrap gap-2">
                {SAMPLE_SEO_PREVIEWS.map((sample) => (
                  <button
                    key={sample.id}
                    type="button"
                    onClick={() => setActivePreviewSample(sample)}
                    className={`px-3.5 py-1.5 rounded-lg border-2 font-bold text-xs font-space transition-all cursor-pointer ${
                      activePreviewSample.id === sample.id
                        ? 'bg-black text-white border-black brutal-shadow-sm'
                        : 'bg-zinc-100 border-zinc-300 text-zinc-700 hover:border-black'
                    }`}
                  >
                    {sample.title}
                  </button>
                ))}
              </div>
            </div>

            {/* Interactive Showcase Card Content */}
            <div className="grid lg:grid-cols-12 gap-6 pt-6">
              {/* Left Column: Simulated SERP & Social Card */}
              <div className="lg:col-span-7 space-y-5">
                <div className="border-2 border-black rounded-xl p-4 bg-zinc-50">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold font-space text-zinc-500 uppercase tracking-wider flex items-center gap-1.5">
                      <Search className="w-3.5 h-3.5" /> Simulated Google SERP Snippet
                    </span>
                    <span className="text-[10px] bg-green-100 text-green-800 font-mono px-2 py-0.5 rounded border border-green-300 font-bold">
                      Indexable
                    </span>
                  </div>
                  <div className="bg-white p-4 rounded-lg border border-zinc-300 font-sans">
                    <div className="text-xs text-[#202124] mb-1 font-mono truncate">{activePreviewSample.serpUrl}</div>
                    <div className="text-base text-[#1a0dab] font-medium hover:underline cursor-pointer mb-1 leading-snug line-clamp-1">
                      {activePreviewSample.metaTitle}
                    </div>
                    <div className="text-xs text-[#4d5156] leading-relaxed line-clamp-2">
                      {activePreviewSample.metaDesc}
                    </div>
                  </div>
                </div>

                {/* Score meters */}
                <div className="grid grid-cols-4 gap-3">
                  {[
                    { label: 'Perf', val: activePreviewSample.lighthouse.perf, color: 'bg-[#86efac]' },
                    { label: 'Access', val: activePreviewSample.lighthouse.acc, color: 'bg-[#86efac]' },
                    { label: 'Best Pr', val: activePreviewSample.lighthouse.bp, color: 'bg-[#86efac]' },
                    { label: 'SEO', val: activePreviewSample.lighthouse.seo, color: 'bg-[#86efac]' },
                  ].map((item, idx) => (
                    <div key={idx} className="bg-zinc-50 border-2 border-black rounded-xl p-3 text-center brutal-shadow-sm">
                      <div className="text-[11px] font-bold font-space text-zinc-500 uppercase">{item.label}</div>
                      <div className="text-xl font-bold font-space text-black my-0.5">{item.val}</div>
                      <div className="w-full bg-zinc-200 h-1.5 rounded-full overflow-hidden border border-black/20">
                        <div className={`${item.color} h-full`} style={{ width: `${item.val}%` }}></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right Column: Diagnostic Checklist */}
              <div className="lg:col-span-5 bg-zinc-50 border-2 border-black rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-bold font-space text-zinc-700 uppercase tracking-wider flex items-center gap-1.5">
                      <CheckSquare className="w-4 h-4 text-black" /> Audit Check Breakdown
                    </span>
                    <span className="bg-black text-white px-2 py-0.5 rounded text-xs font-space font-bold">
                      {activePreviewSample.score}/100
                    </span>
                  </div>

                  <div className="space-y-2">
                    {activePreviewSample.checks.map((c, i) => (
                      <div key={i} className="flex items-start gap-2 text-xs font-medium text-zinc-800 bg-white p-2.5 rounded-lg border border-black/10">
                        {c.status === 'pass' && <CheckCircle2 className="w-4 h-4 text-green-600 flex-shrink-0 mt-0.5" />}
                        {c.status === 'warn' && <AlertCircle className="w-4 h-4 text-yellow-600 flex-shrink-0 mt-0.5" />}
                        {c.status === 'fail' && <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />}
                        <span className="leading-tight">{c.name}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-black/10 text-center">
                  <button
                    type="button"
                    onClick={() => {
                      setInputUrl(activePreviewSample.domain);
                      if (onScan) onScan(activePreviewSample.domain, { includeSecurity: true, includeTechStack: true, includeSeo: true });
                    }}
                    className="w-full py-2.5 bg-black text-white rounded-lg font-bold text-xs font-space brutal-shadow-sm brutal-hover cursor-pointer"
                  >
                    Run Live Audit on {activePreviewSample.domain}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
