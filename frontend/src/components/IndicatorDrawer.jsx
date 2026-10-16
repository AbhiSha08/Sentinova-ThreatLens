import React, { useState, useEffect } from 'react';
import {
  X,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Clock,
  Globe,
  Radio,
  Tag,
  Code,
  Flame,
  FileText,
  Layers,
  ChevronRight,
} from 'lucide-react';
import { lookupIndicator } from '../services/api';

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
};

const IOC_TYPE_COLORS = {
  cve: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  ip: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  url: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  domain: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30',
  hash: 'bg-pink-500/15 text-pink-400 border-pink-500/30',
};

export default function IndicatorDrawer({ indicator, onClose, onSelectIndicator }) {
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [enrichedData, setEnrichedData] = useState(null);
  const [showRawJson, setShowRawJson] = useState(false);

  useEffect(() => {
    if (!indicator) return;
    loadEnrichment(indicator.value);
  }, [indicator]);

  const loadEnrichment = async (val) => {
    setLoading(true);
    try {
      const data = await lookupIndicator(val);
      setEnrichedData(data);
    } catch (err) {
      console.error('Failed to load indicator enrichment:', err);
      setEnrichedData(null);
    } finally {
      setLoading(false);
    }
  };

  if (!indicator) return null;

  const currentItem = enrichedData?.indicator || indicator;
  const breakdown = enrichedData?.score_breakdown;
  const relatedItems = enrichedData?.related_indicators || [];

  const handleCopy = () => {
    navigator.clipboard.writeText(currentItem.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isRansomware =
    (currentItem.tags && currentItem.tags.toLowerCase().includes('ransomware')) ||
    (currentItem.threat_type && currentItem.threat_type.toLowerCase().includes('ransomware'));

  const isKev =
    currentItem.source === 'CISA_KEV' ||
    (currentItem.tags && currentItem.tags.toLowerCase().includes('kev'));

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="absolute inset-0" onClick={onClose} />

      <div className="fixed inset-y-0 right-0 max-w-full flex pl-0 sm:pl-10">
        <div className="w-screen max-w-full sm:max-w-2xl bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col h-full">
          
          {/* Header */}
          <div className="p-4 sm:p-6 border-b border-slate-800 bg-slate-900/95 flex items-start justify-between gap-3 shrink-0">
            <div className="space-y-2 max-w-[85%]">
              <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                <span
                  className={`px-2.5 py-0.5 rounded text-[11px] sm:text-xs font-semibold uppercase tracking-wider border ${
                    SEVERITY_STYLES[currentItem.severity_label] || SEVERITY_STYLES.LOW
                  }`}
                >
                  {currentItem.severity_label} • {currentItem.severity_score?.toFixed(1)}/100
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[11px] sm:text-xs font-mono uppercase font-semibold border ${
                    IOC_TYPE_COLORS[currentItem.ioc_type] || 'bg-slate-800 text-slate-300 border-slate-700'
                  }`}
                >
                  {currentItem.ioc_type}
                </span>
                {isRansomware && (
                  <span className="px-2 py-0.5 rounded text-[10px] sm:text-[11px] font-semibold bg-red-950/70 text-red-300 border border-red-700/60 flex items-center gap-1">
                    <Flame className="w-3 h-3 text-red-400" />
                    Ransomware Link
                  </span>
                )}
                {isKev && (
                  <span className="px-2 py-0.5 rounded text-[10px] sm:text-[11px] font-semibold bg-amber-950/70 text-amber-300 border border-amber-700/60">
                    CISA KEV
                  </span>
                )}
              </div>

              {/* Indicator Value */}
              <div className="flex items-center gap-2">
                <span className="text-sm sm:text-lg font-mono font-bold text-white break-all select-all">
                  {currentItem.value}
                </span>
                <button
                  onClick={handleCopy}
                  title="Copy indicator value"
                  className="p-1.5 min-h-[36px] min-w-[36px] flex items-center justify-center rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 active:scale-95 transition-all shrink-0"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close drawer"
              className="p-2 min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white active:scale-95 transition-all shrink-0"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-5 sm:space-y-6">
            
            {/* 1. Dynamic Risk Score Breakdown */}
            <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-1">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Explainable Risk Engine Breakdown
                  </h4>
                </div>
                <span className="text-xs font-mono font-bold text-cyan-400">
                  Total: {breakdown ? breakdown.total : currentItem.severity_score}/100
                </span>
              </div>

              {breakdown ? (
                <div className="space-y-3">
                  {/* Source Base Weight: 40% max */}
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-400">Source Reliability Weight (40% max)</span>
                      <span className="font-mono text-slate-200">{breakdown.source_component} pts</span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-blue-500 rounded-full transition-all"
                        style={{ width: `${(breakdown.source_component / 40) * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Context & Threat Multiplier: 35% max */}
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-400">Threat Context & Exploit Bonus (35% max)</span>
                      <span className="font-mono text-slate-200">{breakdown.context_component} pts</span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-amber-500 rounded-full transition-all"
                        style={{ width: `${(breakdown.context_component / 35) * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Recency Decay: 25% max */}
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-400">Recency & Observation Factor (25% max)</span>
                      <span className="font-mono text-slate-200">{breakdown.recency_component} pts</span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-cyan-400 rounded-full transition-all"
                        style={{ width: `${(breakdown.recency_component / 25) * 100}%` }}
                      />
                    </div>
                  </div>

                  {breakdown.explanation && (
                    <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 leading-relaxed">
                      {breakdown.explanation}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-slate-400">Composite Score: {currentItem.severity_score}/100 ({currentItem.severity_label})</p>
              )}
            </div>

            {/* 2. Core Telemetry Grid (1 col on mobile, 2 col on sm:) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
              <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Radio className="w-3.5 h-3.5 text-slate-500" />
                  Originating Source
                </div>
                <div className="text-sm font-semibold text-white font-mono">{currentItem.source}</div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Globe className="w-3.5 h-3.5 text-slate-500" />
                  Geo / Network
                </div>
                <div className="text-sm font-semibold text-white font-mono break-all">
                  {currentItem.country_code ? `${currentItem.country_code} ` : 'Global '}
                  {currentItem.asn && <span className="text-xs text-slate-400 font-normal">({currentItem.asn})</span>}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  Last Seen Telemetry
                </div>
                <div className="text-xs font-mono text-slate-200">
                  {currentItem.last_seen ? new Date(currentItem.last_seen).toLocaleString() : 'N/A'}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <FileText className="w-3.5 h-3.5 text-slate-500" />
                  Threat Classification
                </div>
                <div className="text-xs font-semibold text-slate-200 capitalize">
                  {currentItem.threat_type || 'Known Malicious'}
                </div>
              </div>
            </div>

            {/* 3. MITRE ATT&CK Techniques */}
            {currentItem.mitre_techniques && (
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  Mapped MITRE ATT&CK Techniques
                </h4>
                <div className="flex flex-wrap gap-2">
                  {currentItem.mitre_techniques.split(',').map((tid) => {
                    const cleanId = tid.trim();
                    if (!cleanId) return null;
                    return (
                      <a
                        key={cleanId}
                        href={`https://attack.mitre.org/techniques/${cleanId.replace('.', '/')}`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-300 border border-slate-700 hover:border-cyan-500/50 active:scale-95 transition-all"
                      >
                        <span>{cleanId}</span>
                        <ExternalLink className="w-3 h-3 text-slate-400" />
                      </a>
                    );
                  })}
                </div>
              </div>
            )}

            {/* 4. Tags */}
            {currentItem.tags && (
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Tag className="w-3.5 h-3.5 text-slate-400" />
                  Associated Tags
                </h4>
                <div className="flex flex-wrap gap-1.5">
                  {currentItem.tags.split(',').map((tag) => {
                    const cleanTag = tag.trim();
                    if (!cleanTag) return null;
                    return (
                      <span
                        key={cleanTag}
                        className="px-2.5 py-1 rounded-lg text-xs bg-slate-800 text-slate-300 border border-slate-700 font-mono"
                      >
                        #{cleanTag}
                      </span>
                    );
                  })}
                </div>
              </div>
            )}

            {/* 5. Related Threat Indicators */}
            {relatedItems.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
                  Related IOCs in Campaign / Source
                </h4>
                <div className="space-y-1.5">
                  {relatedItems.map((rel) => (
                    <button
                      key={rel.id}
                      onClick={() => onSelectIndicator && onSelectIndicator(rel)}
                      className="w-full flex items-center justify-between p-3 min-h-[44px] rounded-xl bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 text-left active:scale-98 transition-all group"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={`w-2 h-2 rounded-full shrink-0 ${
                            rel.severity_label === 'CRITICAL'
                              ? 'bg-red-400'
                              : rel.severity_label === 'HIGH'
                              ? 'bg-orange-400'
                              : rel.severity_label === 'MEDIUM'
                              ? 'bg-amber-400'
                              : 'bg-emerald-400'
                          }`}
                        />
                        <span className="font-mono text-xs text-slate-200 truncate group-hover:text-cyan-300">
                          {rel.value}
                        </span>
                        <span className="text-[10px] uppercase font-mono text-slate-400 bg-slate-900 px-1 py-0.5 rounded shrink-0">
                          {rel.ioc_type}
                        </span>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-slate-300 shrink-0 ml-2" />
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* 6. Raw Data Payload Inspector */}
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setShowRawJson(!showRawJson)}
                className="flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-slate-200 py-1 transition-colors"
              >
                <Code className="w-3.5 h-3.5 text-slate-500" />
                <span>{showRawJson ? 'Hide Raw Ingested JSON' : 'Inspect Raw Ingested JSON'}</span>
              </button>

              {showRawJson && (
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 overflow-x-auto -webkit-overflow-scrolling-touch">
                  <pre className="text-[11px] font-mono text-cyan-300 whitespace-pre-wrap leading-relaxed">
                    {currentItem.raw_data
                      ? (() => {
                          try {
                            return JSON.stringify(JSON.parse(currentItem.raw_data), null, 2);
                          } catch {
                            return currentItem.raw_data;
                          }
                        })()
                      : JSON.stringify(currentItem, null, 2)}
                  </pre>
                </div>
              )}
            </div>

          </div>
        </div>
      </div>
    </div>
  );
}
