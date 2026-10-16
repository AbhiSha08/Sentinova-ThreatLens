import React, { useState } from 'react';
import { X, Search, ShieldCheck, ShieldAlert, Copy, Check, ExternalLink } from 'lucide-react';
import { bulkLookupIndicators } from '../services/api';

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
};

export default function BulkLookupModal({ isOpen, onClose, onInspectIndicator }) {
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [results, setResults] = useState(null);
  const [copiedUnmatched, setCopiedUnmatched] = useState(false);

  if (!isOpen) return null;

  const handleTriage = async () => {
    setError(null);
    const tokens = inputText
      .split(/[\n,;]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    if (tokens.length === 0) {
      setError('Please enter at least one IP, CVE, domain, or URL to triage.');
      return;
    }

    if (tokens.length > 50) {
      setError(`Found ${tokens.length} IOCs. Maximum allowed is 50 per bulk query.`);
      return;
    }

    setLoading(true);
    try {
      const data = await bulkLookupIndicators(tokens);
      setResults(data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Bulk lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyUnmatched = () => {
    if (!results || !results.unmatched) return;
    navigator.clipboard.writeText(results.unmatched.join('\n'));
    setCopiedUnmatched(true);
    setTimeout(() => setCopiedUnmatched(false), 2000);
  };

  const handleSampleData = () => {
    setInputText(`185.220.101.47
193.142.146.35
CVE-2024-21887
lockbit3-decryptor-portal.top
8.8.8.8
192.168.1.1
http://194.165.16.29:8080/mirai.arm7`);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        
        {/* Header */}
        <div className="p-4 sm:p-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/95 gap-3 shrink-0">
          <div className="flex items-center gap-2.5 sm:gap-3 min-w-0">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
              <Search className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm sm:text-base font-bold text-white font-mono tracking-tight truncate">
                Bulk IOC Triage & Matching
              </h3>
              <p className="text-[11px] sm:text-xs text-slate-400 truncate">
                Paste up to 50 mixed IPs, CVEs, URLs, or domains for instant SOC threat matching
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="p-2 min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white active:scale-95 transition-all shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-4 sm:space-y-5">
          {/* Input Box */}
          <div className="space-y-2">
            <div className="flex items-center justify-between flex-wrap gap-1">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Input IOC List (Newline or comma separated)
              </label>
              <button
                type="button"
                onClick={handleSampleData}
                className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono py-1"
              >
                Insert Sample Batch
              </button>
            </div>
            <textarea
              rows={4}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="185.220.101.47&#10;CVE-2024-21887&#10;lockbit3-decryptor-portal.top&#10;http://evil-c2.net/payload.bin"
              className="w-full rounded-xl bg-slate-950 border border-slate-800 p-3.5 text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/60 transition-all resize-none"
            />
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-red-950/60 border border-red-800 text-xs text-red-200">
              {error}
            </div>
          )}

          <div className="flex items-center justify-end gap-2.5">
            <button
              onClick={() => {
                setInputText('');
                setResults(null);
                setError(null);
              }}
              className="px-4 py-2.5 min-h-[42px] rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 active:scale-95 transition-all"
            >
              Clear
            </button>
            <button
              onClick={handleTriage}
              disabled={loading}
              className={`flex items-center justify-center gap-2 px-5 py-2.5 min-h-[42px] rounded-xl text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 active:scale-95 transition-all ${
                loading ? 'opacity-60 cursor-not-allowed' : 'shadow-lg shadow-cyan-950/50'
              }`}
            >
              {loading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  Triaging Threat Intelligence...
                </>
              ) : (
                <>
                  <Search className="w-3.5 h-3.5" />
                  Run Bulk Triage
                </>
              )}
            </button>
          </div>

          {/* Results View */}
          {results && (
            <div className="space-y-4 sm:space-y-5 pt-4 border-t border-slate-800 animate-in fade-in duration-200">
              {/* Summary KPIs: 1 col on mobile, 3 col on sm: */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 sm:gap-3">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-center">
                  <div className="text-lg font-bold font-mono text-white">{results.total_queried}</div>
                  <div className="text-[11px] text-slate-400">Total Queried</div>
                </div>
                <div className="p-3 rounded-xl bg-red-950/30 border border-red-900/50 text-center">
                  <div className="text-lg font-bold font-mono text-red-400">{results.matched_count}</div>
                  <div className="text-[11px] text-red-300 flex items-center justify-center gap-1">
                    <ShieldAlert className="w-3.5 h-3.5" /> Matched Threats
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-900/50 text-center">
                  <div className="text-lg font-bold font-mono text-emerald-400">{results.unmatched_count}</div>
                  <div className="text-[11px] text-emerald-300 flex items-center justify-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5" /> Clean / Unmatched
                  </div>
                </div>
              </div>

              {/* Matched Threats List */}
              {results.matched_count > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    Identified Threats in Database ({results.matched_count})
                  </h4>
                  <div className="rounded-xl border border-slate-800 bg-slate-950/70 overflow-hidden divide-y divide-slate-800/60 max-h-56 overflow-y-auto">
                    {results.matched.map((m) => (
                      <div key={m.id} className="p-2.5 sm:p-3 flex items-center justify-between hover:bg-slate-900/80 transition-colors gap-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border shrink-0 ${
                              SEVERITY_STYLES[m.severity_label]
                            }`}
                          >
                            {m.severity_label}
                          </span>
                          <span className="font-mono text-xs font-semibold text-slate-100 truncate">
                            {m.value}
                          </span>
                          <span className="text-[10px] uppercase font-mono text-slate-400 bg-slate-900 px-1 py-0.5 rounded shrink-0">
                            {m.ioc_type}
                          </span>
                        </div>
                        <button
                          onClick={() => {
                            onClose();
                            onInspectIndicator(m);
                          }}
                          className="px-2.5 py-1.5 min-h-[32px] rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-cyan-400 hover:text-cyan-300 active:scale-95 transition-all flex items-center gap-1 shrink-0 font-medium"
                        >
                          <span>Inspect</span>
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Unmatched / Clean List */}
              {results.unmatched_count > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Clean / Unmatched IOCs ({results.unmatched_count})
                    </h4>
                    <button
                      onClick={handleCopyUnmatched}
                      className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 py-1 active:scale-95 transition-all"
                    >
                      {copiedUnmatched ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy List</span>
                        </>
                      )}
                    </button>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-400 max-h-32 overflow-y-auto space-y-1">
                    {results.unmatched.map((u, i) => (
                      <div key={i} className="truncate select-all">{u}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
