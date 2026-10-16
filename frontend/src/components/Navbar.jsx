import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  BarChart3, 
  Terminal, 
  RefreshCw, 
  Radio, 
  CheckCircle2,
  AlertTriangle,
  Menu,
  X,
} from 'lucide-react';
import { fetchBackendHealth, triggerFeedSync } from '../services/api';

export default function Navbar({ activeView, setActiveView, onSyncCompleted, onOpenFeedsModal }) {
  const [backendStatus, setBackendStatus] = useState({ online: false, version: '1.0.0' });
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncToast, setSyncToast] = useState(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const checkHealth = async () => {
    try {
      const data = await fetchBackendHealth();
      setBackendStatus({ online: true, version: data.version || '1.0.0' });
    } catch (err) {
      setBackendStatus({ online: false, version: 'offline' });
    }
  };

  const handleSync = async () => {
    if (isSyncing) return;
    setIsSyncing(true);
    setSyncToast({ type: 'info', message: 'Triggering global threat feed sync...' });
    try {
      const results = await triggerFeedSync();
      const totalNew = results.reduce((sum, r) => sum + (r.inserted || 0), 0);
      const totalUpdated = results.reduce((sum, r) => sum + (r.updated || 0), 0);
      setSyncToast({
        type: 'success',
        message: `Sync complete: +${totalNew} new, ${totalUpdated} updated indicators across ${results.length} feeds.`,
      });
      if (onSyncCompleted) onSyncCompleted();
    } catch (err) {
      setSyncToast({
        type: 'error',
        message: 'Feed sync failed: ' + (err.response?.data?.detail || err.message),
      });
    } finally {
      setIsSyncing(false);
      setTimeout(() => setSyncToast(null), 6000);
    }
  };

  const selectView = (view) => {
    setActiveView(view);
    setMobileMenuOpen(false);
  };

  const openFeeds = () => {
    setMobileMenuOpen(false);
    onOpenFeedsModal();
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-2">
          
          {/* Logo & Brand Header */}
          <div className="flex items-center gap-2.5 sm:gap-3 min-w-0">
            <div className="relative flex items-center justify-center w-9 h-9 sm:w-10 sm:h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400 shadow-lg shadow-cyan-950/50 shrink-0">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              <span className="absolute -top-1 -right-1 flex h-2 w-2 sm:h-2.5 sm:w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-full w-full bg-cyan-500"></span>
              </span>
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                <span className="text-base sm:text-lg font-bold tracking-tight text-white font-mono truncate flex items-center gap-1.5">
                  <span className="text-cyan-400 font-extrabold tracking-wide">SENTINOVA</span>
                  <span className="text-white">THREAT<span className="text-cyan-400">LENS</span></span>
                </span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-semibold tracking-wider shrink-0">
                  CTI v{backendStatus.version}
                </span>
              </div>
              <p className="text-[10px] sm:text-[11px] text-slate-400 hidden sm:block truncate">
                Cyber Threat Intelligence & Telemetry Fusion
              </p>
            </div>
          </div>

          {/* Desktop View Switcher Toggle */}
          <div className="hidden md:flex items-center p-1 bg-slate-900 border border-slate-800 rounded-lg shadow-inner">
            <button
              id="nav-btn-soc"
              onClick={() => setActiveView('analyst')}
              className={`flex items-center gap-2 px-3.5 py-1.5 min-h-[36px] rounded-md text-xs font-medium transition-all active:scale-95 ${
                activeView === 'analyst'
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>SOC Analyst</span>
              <span className="text-[10px] text-slate-500 hidden lg:inline">(Tactical)</span>
            </button>

            <button
              id="nav-btn-exec"
              onClick={() => setActiveView('executive')}
              className={`flex items-center gap-2 px-3.5 py-1.5 min-h-[36px] rounded-md text-xs font-medium transition-all active:scale-95 ${
                activeView === 'executive'
                  ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span>Executive</span>
              <span className="text-[10px] text-slate-500 hidden lg:inline">(Strategic)</span>
            </button>
          </div>

          {/* Desktop Actions & Health Status */}
          <div className="hidden md:flex items-center gap-3">
            {/* Feed Status Button */}
            <button
              onClick={onOpenFeedsModal}
              title="View Threat Feed Telemetry & Status"
              className="flex items-center gap-1.5 px-3 py-1.5 min-h-[38px] text-xs font-medium text-slate-300 bg-slate-900/80 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 rounded-lg transition-all active:scale-95"
            >
              <Radio className="w-3.5 h-3.5 text-cyan-400" />
              <span>Feeds</span>
            </button>

            {/* Sync Feeds Now */}
            <button
              onClick={handleSync}
              disabled={isSyncing}
              className={`flex items-center gap-2 px-3.5 py-1.5 min-h-[38px] text-xs font-medium rounded-lg border transition-all active:scale-95 ${
                isSyncing
                  ? 'bg-slate-800 border-slate-700 text-slate-400 cursor-not-allowed'
                  : 'bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border-cyan-500/30 shadow-sm hover:border-cyan-500/50'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin text-cyan-400' : ''}`} />
              <span>{isSyncing ? 'Syncing...' : 'Sync Feeds Now'}</span>
            </button>

            {/* Backend Health Indicator */}
            <div 
              className="flex items-center gap-1.5 px-2.5 py-1.5 min-h-[38px] rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] font-mono shrink-0"
              title={backendStatus.online ? 'Backend API connection healthy' : 'Backend API connection lost'}
            >
              <span className="relative flex h-2 w-2">
                {backendStatus.online ? (
                  <>
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </>
                ) : (
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                )}
              </span>
              <span className={backendStatus.online ? 'text-slate-300' : 'text-red-400'}>
                {backendStatus.online ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>
          </div>

          {/* Mobile Right Bar: Health badge + Hamburger Toggle */}
          <div className="flex md:hidden items-center gap-2">
            {/* Compact Health Dot */}
            <div 
              className="flex items-center gap-1 px-2 py-1.5 rounded-lg bg-slate-900/60 border border-slate-800 text-[10px] font-mono"
              title={backendStatus.online ? 'API Online' : 'API Offline'}
            >
              <span className={`h-2 w-2 rounded-full ${backendStatus.online ? 'bg-emerald-400' : 'bg-red-500'}`} />
              <span className={backendStatus.online ? 'text-slate-300' : 'text-red-400'}>
                {backendStatus.online ? 'ONLINE' : 'ERR'}
              </span>
            </div>

            {/* Hamburger Button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label={mobileMenuOpen ? 'Close Menu' : 'Open Navigation Menu'}
              className="flex items-center justify-center p-2 min-h-[40px] min-w-[40px] rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 active:scale-95 transition-all"
            >
              {mobileMenuOpen ? <X className="w-5 h-5 text-cyan-400" /> : <Menu className="w-5 h-5 text-slate-200" />}
            </button>
          </div>

        </div>
      </div>

      {/* ── Mobile Collapsible Menu Drawer ─────────────────────────────────── */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-slate-800/80 bg-slate-950/98 px-4 py-4 space-y-4 shadow-2xl animate-in slide-in-from-top-2 duration-200">
          
          {/* View Switcher on Mobile */}
          <div className="space-y-1.5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold px-1">
              Select Operational Mode
            </span>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => selectView('analyst')}
                className={`flex items-center justify-center gap-2 py-2.5 px-3 min-h-[44px] rounded-xl text-xs font-semibold border transition-all active:scale-95 ${
                  activeView === 'analyst'
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-sm'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:bg-slate-800'
                }`}
              >
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>SOC Analyst</span>
              </button>

              <button
                onClick={() => selectView('executive')}
                className={`flex items-center justify-center gap-2 py-2.5 px-3 min-h-[44px] rounded-xl text-xs font-semibold border transition-all active:scale-95 ${
                  activeView === 'executive'
                    ? 'bg-blue-500/20 text-blue-300 border-blue-500/50 shadow-sm'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:bg-slate-800'
                }`}
              >
                <BarChart3 className="w-4 h-4 text-blue-400" />
                <span>Executive</span>
              </button>
            </div>
          </div>

          {/* Quick Actions on Mobile */}
          <div className="pt-2 border-t border-slate-900 space-y-2">
            <button
              onClick={openFeeds}
              className="w-full flex items-center justify-between p-3 min-h-[44px] rounded-xl bg-slate-900 border border-slate-800 text-xs font-medium text-slate-200 hover:bg-slate-800/90 active:scale-95 transition-all"
            >
              <div className="flex items-center gap-2.5">
                <Radio className="w-4 h-4 text-cyan-400" />
                <span>Threat Feed Health & Telemetry</span>
              </div>
              <span className="text-[10px] font-mono uppercase text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/50">
                View Status
              </span>
            </button>

            <button
              onClick={() => {
                setMobileMenuOpen(false);
                handleSync();
              }}
              disabled={isSyncing}
              className="w-full flex items-center justify-center gap-2 p-3 min-h-[44px] rounded-xl bg-cyan-500/15 border border-cyan-500/40 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/25 active:scale-95 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
              <span>{isSyncing ? 'Synchronizing Ingestion...' : 'Sync All Feeds Now'}</span>
            </button>
          </div>

        </div>
      )}

      {/* Floating Sync Notification Toast */}
      {syncToast && (
        <div className="fixed top-16 right-4 left-4 sm:left-auto sm:right-8 z-50 sm:max-w-md animate-in fade-in slide-in-from-top-2 duration-200">
          <div className={`flex items-start gap-3 p-3.5 rounded-xl shadow-2xl border backdrop-blur-md ${
            syncToast.type === 'success' 
              ? 'bg-slate-900/98 border-emerald-500/50 text-emerald-200' 
              : syncToast.type === 'error'
              ? 'bg-slate-900/98 border-red-500/50 text-red-200'
              : 'bg-slate-900/98 border-cyan-500/50 text-cyan-200'
          }`}>
            {syncToast.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : syncToast.type === 'error' ? (
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            ) : (
              <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin shrink-0 mt-0.5" />
            )}
            <p className="text-xs font-medium leading-relaxed">{syncToast.message}</p>
          </div>
        </div>
      )}
    </header>
  );
}
