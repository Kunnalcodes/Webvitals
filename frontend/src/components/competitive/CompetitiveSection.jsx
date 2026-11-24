import React, { useState } from 'react';
import {
  Users,
  Search,
  Sparkles,
  ArrowRight,
  RefreshCw,
  Globe,
  Sliders,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  BrainCircuit,
  Zap,
} from 'lucide-react';
import { useCompetitiveScanner } from '../../hooks/useCompetitiveScanner';
import CompetitiveIntelligenceDashboard from './CompetitiveIntelligenceDashboard';

const SAMPLE_COMPARISONS = [
  {
    label: 'Cybersecurity Scanner vs OSINT',
    primary: 'webvitals.dev',
    competitor: 'securitytrails.com',
    industry: 'Cybersecurity & Network Defense',
  },
  {
    label: 'Fintech Payment Infrastructure',
    primary: 'stripe.com',
    competitor: 'adyen.com',
    industry: 'Fintech & Digital Payments',
  },
  {
    label: 'Developer Tooling & Issues',
    primary: 'linear.app',
    competitor: 'atlassian.com',
    industry: 'SaaS & Developer Ergonomics',
  },
];

export default function CompetitiveSection() {
  const { status, report, error, progress, compare, reset } = useCompetitiveScanner();

  const [primaryUrl, setPrimaryUrl] = useState('');
  const [competitorUrl, setCompetitorUrl] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [businessName, setBusinessName] = useState('');
  const [targetLocation, setTargetLocation] = useState('');
  const [industry, setIndustry] = useState('');

  const isScanning = status === 'scanning';

  const handleSubmit = (e) => {
    e.preventDefault();
    if (primaryUrl.trim() && competitorUrl.trim()) {
      compare(primaryUrl.trim(), competitorUrl.trim(), {
        businessName: businessName.trim(),
        targetLocation: targetLocation.trim(),
        industry: industry.trim(),
      });
    }
  };

  const handleSelectSample = (sample) => {
    setPrimaryUrl(sample.primary);
    setCompetitorUrl(sample.competitor);
    setIndustry(sample.industry);
    compare(sample.primary, sample.competitor, { industry: sample.industry });
  };

  return (
    <section id="competitive-intelligence" className="py-20 px-6 bg-[#fffdf7] border-t-2 border-black relative">
      <div className="max-w-7xl mx-auto">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-10">
          <div className="inline-flex items-center gap-2 bg-[#fde047] border-2 border-black px-3.5 py-1.5 rounded-full brutal-shadow-sm mb-4 font-space text-xs font-bold uppercase tracking-wider text-black">
            <Users className="w-4 h-4 stroke-[2.5]" /> AI Competitor Intelligence & SEO/GEO/AEO Engine
          </div>
          <h2 className="text-3xl md:text-5xl font-bold font-space tracking-tight text-black mb-4">
            Reverse-Engineer Your Competitor's Growth Strategy
          </h2>
          <p className="text-base md:text-lg font-medium text-zinc-700 leading-relaxed">
            Compare two websites across technical SEO infrastructure, machine-readable GEO entity clarity, AEO direct answer quality, and uncover high-value keyword opportunities with Vertex AI.
          </p>
        </div>

        {/* Dual Input Form */}
        <div className="max-w-3xl mx-auto mb-10">
          <form onSubmit={handleSubmit} className="bg-white p-6 rounded-2xl border-2 border-black brutal-shadow-lg space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-space font-bold uppercase text-zinc-700 mb-1.5">
                  Your Website / Business Domain
                </label>
                <div className="flex items-center gap-2 px-3 bg-zinc-50 rounded-xl border-2 border-black/20 focus-within:border-black transition-colors">
                  <Globe className="w-4 h-4 text-zinc-500 flex-shrink-0" />
                  <input
                    type="text"
                    value={primaryUrl}
                    onChange={(e) => setPrimaryUrl(e.target.value)}
                    placeholder="e.g. webvitals.dev"
                    disabled={isScanning}
                    className="w-full bg-transparent py-3 text-xs md:text-sm font-medium font-space outline-none text-zinc-900"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-space font-bold uppercase text-zinc-700 mb-1.5">
                  Competitor Website Domain
                </label>
                <div className="flex items-center gap-2 px-3 bg-zinc-50 rounded-xl border-2 border-black/20 focus-within:border-black transition-colors">
                  <Globe className="w-4 h-4 text-zinc-500 flex-shrink-0" />
                  <input
                    type="text"
                    value={competitorUrl}
                    onChange={(e) => setCompetitorUrl(e.target.value)}
                    placeholder="e.g. securitytrails.com"
                    disabled={isScanning}
                    className="w-full bg-transparent py-3 text-xs md:text-sm font-medium font-space outline-none text-zinc-900"
                    required
                  />
                </div>
              </div>
            </div>

            {/* Advanced Configuration Accordion */}
            <div className="pt-1">
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="text-xs font-space font-bold text-zinc-600 hover:text-black flex items-center gap-1.5 cursor-pointer"
              >
                <Sliders className="w-3.5 h-3.5" />
                <span>{showAdvanced ? 'Hide Optional Parameters' : 'Add Optional Target Context (Location, Industry, Brand)'}</span>
                {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>

              {showAdvanced && (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3">
                  <div>
                    <label className="block text-[11px] font-space font-bold text-zinc-500 mb-1">Business Name</label>
                    <input
                      type="text"
                      value={businessName}
                      onChange={(e) => setBusinessName(e.target.value)}
                      placeholder="e.g. WebVitals"
                      className="w-full px-3 py-2 text-xs bg-zinc-50 border border-black/20 rounded-lg outline-none font-space"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-space font-bold text-zinc-500 mb-1">Target Location</label>
                    <input
                      type="text"
                      value={targetLocation}
                      onChange={(e) => setTargetLocation(e.target.value)}
                      placeholder="e.g. Global, US, UK"
                      className="w-full px-3 py-2 text-xs bg-zinc-50 border border-black/20 rounded-lg outline-none font-space"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-space font-bold text-zinc-500 mb-1">Industry / Category</label>
                    <input
                      type="text"
                      value={industry}
                      onChange={(e) => setIndustry(e.target.value)}
                      placeholder="e.g. Cybersecurity"
                      className="w-full px-3 py-2 text-xs bg-zinc-50 border border-black/20 rounded-lg outline-none font-space"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isScanning || !primaryUrl.trim() || !competitorUrl.trim()}
                className="w-full py-3.5 bg-black text-white hover:bg-zinc-800 rounded-xl font-bold border-2 border-black brutal-shadow brutal-hover flex items-center justify-center gap-2 font-space cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Analyzing Competitor Intelligence...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 text-[#fde047] fill-[#fde047]" />
                    <span>Run AI Competitive Intelligence Audit</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Quick Presets */}
          <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-xs font-space">
            <span className="text-zinc-500 font-bold uppercase text-[10px]">Quick Presets:</span>
            {SAMPLE_COMPARISONS.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectSample(sample)}
                disabled={isScanning}
                className="px-2.5 py-1 bg-white hover:bg-zinc-100 border border-black/30 rounded-full font-medium text-zinc-700 transition-colors cursor-pointer"
              >
                {sample.label}
              </button>
            ))}
          </div>

          {/* Progress Indicator */}
          {isScanning && (
            <div className="mt-6 p-5 bg-white border-2 border-black rounded-xl brutal-shadow-sm space-y-3 animate-in fade-in">
              <div className="flex items-center justify-between text-xs font-space font-bold">
                <span className="flex items-center gap-2">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-purple-700" />
                  {progress.message || 'Processing comparison...'}
                </span>
                <span className="font-mono">{progress.percent}%</span>
              </div>
              <div className="w-full bg-zinc-100 border border-black rounded-full h-2 overflow-hidden">
                <div
                  className="bg-purple-600 h-full transition-all duration-300"
                  style={{ width: `${Math.max(10, progress.percent)}%` }}
                />
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="mt-4 p-4 bg-rose-50 border-2 border-rose-400 rounded-xl flex items-start gap-3 text-rose-900 text-xs font-space animate-in fade-in">
              <AlertCircle className="w-4 h-4 text-rose-600 flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block">Audit Failed</span>
                <span>{error}</span>
              </div>
            </div>
          )}
        </div>

        {/* Live Comparison Dashboard */}
        {report && (
          <div className="mt-12">
            <CompetitiveIntelligenceDashboard report={report} />
          </div>
        )}
      </div>
    </section>
  );
}
