import React, { useState } from 'react';
import { Sparkles, Copy, Check, Tag, Target, Code, Lightbulb, ArrowRight } from 'lucide-react';

export default function SeoAiOptimizerTab({ aiOptimization }) {
  const [copiedIndex, setCopiedIndex] = useState(null);

  if (!aiOptimization) {
    return (
      <div className="bg-white border-2 border-black rounded-xl p-8 text-center brutal-shadow">
        <Sparkles className="w-8 h-8 text-amber-500 mx-auto mb-3 animate-pulse" />
        <h4 className="text-lg font-bold font-space text-black mb-1">AI SEO Optimization Generating...</h4>
        <p className="text-xs text-zinc-600 max-w-md mx-auto">
          Vertex AI / Gemini is analyzing the page content to craft high-CTR titles, conversion descriptions, and rich semantic keywords.
        </p>
      </div>
    );
  }

  const {
    optimizedTitles = [],
    optimizedDescriptions = [],
    richKeywords = {},
    contentActionItems = [],
    schemaJsonLd = null,
  } = aiOptimization;

  const copyToClipboard = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-amber-50 via-yellow-50 to-orange-50 border-2 border-black rounded-xl p-6 brutal-shadow flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-[#fde047] border-2 border-black flex items-center justify-center brutal-shadow-sm flex-shrink-0">
            <Sparkles className="w-6 h-6 text-black stroke-[2.5]" />
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h3 className="text-lg font-bold font-space text-black">
                Vertex AI / Gemini SEO Meta & Keyword Recommendations
              </h3>
              <span className="bg-[#86efac] text-black text-[10px] font-bold px-2 py-0.5 rounded border border-black uppercase font-space">
                Live AI
              </span>
            </div>
            <p className="text-xs text-zinc-700 font-medium">
              High-converting titles, click-optimized descriptions, and search-intent keyword clusters generated for this page.
            </p>
          </div>
        </div>
      </div>

      {/* 1. Optimized Titles & Descriptions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recommended Titles */}
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b-2 border-zinc-200">
            <Target className="w-5 h-5 text-indigo-600" />
            <h4 className="font-bold text-base font-space text-black">High-CTR Title Recommendations</h4>
          </div>

          <div className="space-y-3">
            {optimizedTitles.map((item, idx) => (
              <div key={idx} className="p-3.5 bg-zinc-50 border-2 border-black rounded-lg relative group">
                <div className="flex items-start justify-between gap-3 mb-1.5">
                  <span className="text-xs font-bold font-mono text-zinc-500 uppercase tracking-wide">
                    Option #{idx + 1} ({item.charCount || item.title.length} chars)
                  </span>
                  <button
                    onClick={() => copyToClipboard(item.title, `title-${idx}`)}
                    className="p-1.5 bg-white hover:bg-zinc-100 border border-black rounded transition-all text-xs font-bold font-space flex items-center gap-1"
                    title="Copy Title"
                  >
                    {copiedIndex === `title-${idx}` ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span className="text-emerald-700 text-[11px]">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-black" />
                        <span className="text-[11px]">Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <p className="text-sm font-bold text-black font-space mb-1.5">{item.title}</p>
                {item.rationale && (
                  <p className="text-xs text-zinc-600 font-medium flex items-center gap-1">
                    <ArrowRight className="w-3 h-3 text-zinc-400" /> {item.rationale}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Recommended Meta Descriptions */}
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b-2 border-zinc-200">
            <Tag className="w-5 h-5 text-emerald-600" />
            <h4 className="font-bold text-base font-space text-black">Conversion Meta Descriptions</h4>
          </div>

          <div className="space-y-3">
            {optimizedDescriptions.map((item, idx) => (
              <div key={idx} className="p-3.5 bg-zinc-50 border-2 border-black rounded-lg relative group">
                <div className="flex items-start justify-between gap-3 mb-1.5">
                  <span className="text-xs font-bold font-mono text-zinc-500 uppercase tracking-wide">
                    Variant #{idx + 1} ({item.charCount || item.description.length} chars)
                  </span>
                  <button
                    onClick={() => copyToClipboard(item.description, `desc-${idx}`)}
                    className="p-1.5 bg-white hover:bg-zinc-100 border border-black rounded transition-all text-xs font-bold font-space flex items-center gap-1"
                    title="Copy Description"
                  >
                    {copiedIndex === `desc-${idx}` ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span className="text-emerald-700 text-[11px]">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-black" />
                        <span className="text-[11px]">Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <p className="text-xs text-zinc-800 leading-relaxed font-medium mb-1.5">{item.description}</p>
                {item.rationale && (
                  <p className="text-[11px] text-zinc-500 flex items-center gap-1">
                    <ArrowRight className="w-3 h-3 text-zinc-400" /> {item.rationale}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 2. Semantic Keywords & Search Intent */}
      <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-4">
        <div className="flex items-center gap-2 pb-3 border-b-2 border-zinc-200">
          <Tag className="w-5 h-5 text-purple-600" />
          <h4 className="font-bold text-base font-space text-black">Target & Semantic Keyword Clusters</h4>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Primary */}
          <div className="p-4 bg-purple-50 border-2 border-purple-300 rounded-lg">
            <span className="text-xs font-bold uppercase tracking-wider text-purple-900 font-space block mb-2">
              Primary Keywords
            </span>
            <div className="flex flex-wrap gap-1.5">
              {(richKeywords.primaryKeywords || []).map((k, i) => (
                <span key={i} className="px-2.5 py-1 bg-white border border-purple-400 text-purple-900 text-xs font-bold rounded font-mono">
                  {k}
                </span>
              ))}
            </div>
          </div>

          {/* Secondary */}
          <div className="p-4 bg-blue-50 border-2 border-blue-300 rounded-lg">
            <span className="text-xs font-bold uppercase tracking-wider text-blue-900 font-space block mb-2">
              Secondary Keywords
            </span>
            <div className="flex flex-wrap gap-1.5">
              {(richKeywords.secondaryKeywords || []).map((k, i) => (
                <span key={i} className="px-2.5 py-1 bg-white border border-blue-400 text-blue-900 text-xs font-bold rounded font-mono">
                  {k}
                </span>
              ))}
            </div>
          </div>

          {/* Long-Tail */}
          <div className="p-4 bg-emerald-50 border-2 border-emerald-300 rounded-lg">
            <span className="text-xs font-bold uppercase tracking-wider text-emerald-900 font-space block mb-2">
              Long-Tail Search Intent
            </span>
            <div className="flex flex-wrap gap-1.5">
              {(richKeywords.longTailKeywords || []).map((k, i) => (
                <span key={i} className="px-2.5 py-1 bg-white border border-emerald-400 text-emerald-900 text-xs font-bold rounded font-mono">
                  {k}
                </span>
              ))}
            </div>
          </div>

          {/* LSI Semantic */}
          <div className="p-4 bg-amber-50 border-2 border-amber-300 rounded-lg">
            <span className="text-xs font-bold uppercase tracking-wider text-amber-900 font-space block mb-2">
              LSI Semantic Entities
            </span>
            <div className="flex flex-wrap gap-1.5">
              {(richKeywords.lsiSemanticKeywords || []).map((k, i) => (
                <span key={i} className="px-2.5 py-1 bg-white border border-amber-400 text-amber-900 text-xs font-bold rounded font-mono">
                  {k}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Action Items & Schema.org JSON-LD */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Content Action Items */}
        <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b-2 border-zinc-200">
            <Lightbulb className="w-5 h-5 text-amber-500" />
            <h4 className="font-bold text-base font-space text-black">AI Content & Hierarchy Action Items</h4>
          </div>
          <ul className="space-y-2.5">
            {contentActionItems.map((item, idx) => (
              <li key={idx} className="flex items-start gap-2.5 text-xs text-zinc-800 font-medium">
                <span className="w-5 h-5 rounded-full bg-[#fde047] border border-black flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5">
                  {idx + 1}
                </span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Schema.org JSON-LD */}
        {schemaJsonLd && (
          <div className="bg-white border-2 border-black rounded-xl p-6 brutal-shadow space-y-3">
            <div className="flex items-center justify-between pb-2 border-b-2 border-zinc-200">
              <div className="flex items-center gap-2">
                <Code className="w-5 h-5 text-blue-600" />
                <h4 className="font-bold text-base font-space text-black">Recommended Schema.org JSON-LD</h4>
              </div>
              <button
                onClick={() => copyToClipboard(JSON.stringify(schemaJsonLd, null, 2), 'schema')}
                className="px-2.5 py-1 bg-white hover:bg-zinc-100 border border-black rounded text-xs font-bold font-space flex items-center gap-1"
              >
                {copiedIndex === 'schema' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                    <span className="text-emerald-700">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-black" />
                    <span>Copy JSON-LD</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 bg-zinc-900 text-emerald-400 rounded-lg text-[11px] font-mono overflow-x-auto max-h-48 border border-black">
              {JSON.stringify(schemaJsonLd, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
