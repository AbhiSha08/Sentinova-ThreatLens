import React, { useState, useEffect } from 'react';
import { X, Radio, CheckCircle2, AlertCircle, RefreshCw, Server, ExternalLink } from 'lucide-react';
import { fetchFeedsStatus, triggerFeedSync } from '../services/api';

export default function FeedStatusModal({ isOpen, onClose, onSyncCompleted }) {
  const [feeds, setFeeds] = useState([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen) {
      loadFeeds();
    }
  }, [isOpen]);

  const loadFeeds = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchFeedsStatus();
      setFeeds(data);
    } catch (err) {
      setError(err.message || 'Failed to fetch feeds status');
    } finally {
      setLoading(false);
    }
  };

  const handleSyncNow = async () => {
    setSyncing(true);
    try {
      await triggerFeedSync();
      await loadFeeds();
      if (onSyncCompleted) onSyncCompleted();
    } catch (err) {
      setError(err.message || 'Sync failed');
    } finally {
      setSyncing(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        
        {/* Header */}
        <div className="p-4 sm:p-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/95 gap-3 shrink-0">
          <div className="flex items-center gap-2.5 sm:gap-3 min-w-0">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
              <Radio className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm sm:text-base font-bold text-white font-mono tracking-tight truncate">
                Threat Intelligence Feed Registry
              </h3>
              <p className="text-[11px] sm:text-xs text-slate-400 truncate">
                Continuous ingestion pipelines and telemetry health status
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

        {/* Feed List */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-4">
          {error && (
            <div className="p-3 rounded-xl bg-red-950/60 border border-red-800 text-xs text-red-200">
              {error}
            </div>
          )}

          {loading ? (
            <div className="py-12 flex flex-col items-center justify-center gap-3 text-slate-400">
              <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              <span className="text-xs font-mono">Loading feed telemetry...</span>
            </div>
          ) : (
            <div className="space-y-3">
              {feeds.map((feed) => {
                const isHealthy = feed.last_fetch_status === 'success';
                return (
                  <div
                    key={feed.id}
                    className="p-3.5 sm:p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 transition-colors space-y-2.5"
                  >
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        {isHealthy ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                        )}
                        <span className="text-xs sm:text-sm font-bold text-white font-mono truncate">{feed.name}</span>
                        <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 shrink-0">
                          {feed.feed_type}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold border ${
                            isHealthy
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          }`}
                        >
                          {feed.last_fetch_status || 'PENDING'}
                        </span>
                        <span className="text-xs font-mono font-bold text-cyan-400">
                          {feed.indicators_ingested} IOCs
                        </span>
                      </div>
                    </div>

                    <div className="text-[11px] sm:text-xs text-slate-400 font-mono truncate select-all flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      <span className="truncate">{feed.url}</span>
                    </div>

                    <div className="flex flex-col sm:flex-row sm:items-center justify-between text-[11px] text-slate-500 font-mono pt-1 border-t border-slate-900 gap-1">
                      <span>Last Ingested: {feed.last_fetched_at ? new Date(feed.last_fetched_at).toLocaleString() : 'Never'}</span>
                      <span className={feed.is_enabled ? 'text-emerald-400' : 'text-slate-500'}>
                        {feed.is_enabled ? 'Active Pipeline' : 'Disabled'}
                      </span>
                    </div>

                    {feed.last_error_message && (
                      <div className="p-2 rounded-lg bg-amber-950/40 border border-amber-800/40 text-[11px] font-mono text-amber-300">
                        Notice: {feed.last_error_message}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Footer Controls (Stacks on mobile) */}
          <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
            <span className="text-[11px] sm:text-xs text-slate-500 font-mono text-center sm:text-left">
              Auto-polled every 60m via APScheduler
            </span>
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <button
                onClick={loadFeeds}
                className="flex-1 sm:flex-initial px-4 py-2 min-h-[42px] rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 active:scale-95 transition-all text-center"
              >
                Refresh
              </button>
              <button
                onClick={handleSyncNow}
                disabled={syncing}
                className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-4 py-2 min-h-[42px] rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-xs font-medium text-cyan-400 active:scale-95 transition-all disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
                <span>{syncing ? 'Ingesting...' : 'Sync All Feeds'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
