import React, { useState, useEffect, useCallback } from 'react';
import {
  Search,
  Filter,
  Download,
  Copy,
  Check,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  RefreshCw,
  SlidersHorizontal,
  FileSpreadsheet,
  FileCode,
  Layers,
  Terminal,
} from 'lucide-react';
import { fetchIndicators, exportIndicatorsUrl } from '../services/api';

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

// Relative time formatter
function formatRelativeTime(dateStr) {
  if (!dateStr) return 'N/A';
  const now = new Date();
  const past = new Date(dateStr);
  const diffSec = Math.floor((now - past) / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  const diffDay = Math.floor(diffHour / 24);
  return `${diffDay}d ago`;
}

export default function AnalystView({ initialFilters, onInspectIndicator, onOpenBulkModal }) {
  const [indicators, setIndicators] = useState([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Filter criteria
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [severity, setSeverity] = useState(initialFilters?.severity || 'ALL');
  const [iocType, setIocType] = useState(initialFilters?.ioc_type || 'ALL');
  const [mitreTechnique, setMitreTechnique] = useState(initialFilters?.mitre_technique || 'ALL');
  const [sortBy, setSortBy] = useState('severity_score');
  const [sortOrder, setSortOrder] = useState('desc');

  // Copy feedback state
  const [copiedId, setCopiedId] = useState(null);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 350);
    return () => clearTimeout(timer);
  }, [search]);

  // Update filters if initialFilters changes (e.g., clicked from Executive dashboard)
  useEffect(() => {
    if (initialFilters) {
      if (initialFilters.severity) setSeverity(initialFilters.severity);
      if (initialFilters.ioc_type) setIocType(initialFilters.ioc_type);
      if (initialFilters.mitre_technique) setMitreTechnique(initialFilters.mitre_technique);
      setPage(1);
    }
  }, [initialFilters]);

  // Load indicators from backend
  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchIndicators({
        page,
        page_size: pageSize,
        search: debouncedSearch,
        severity,
        ioc_type: iocType,
        mitre_technique: mitreTechnique,
        sort_by: sortBy,
        sort_order: sortOrder,
        active_only: true,
      });
      setIndicators(data.items || []);
      setTotal(data.total || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to fetch indicators');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, debouncedSearch, severity, iocType, mitreTechnique, sortBy, sortOrder]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Sort toggle handler
  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
    setPage(1);
  };

  const handleCopy = (id, text, e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const currentFilterParams = {
    search: debouncedSearch,
    severity,
    ioc_type: iocType,
    mitre_technique: mitreTechnique,
    active_only: true,
  };

  return (
    <div className="space-y-5 sm:space-y-6 animate-in fade-in duration-300">
      
      {/* Page Title & SIEM Export Actions (Stacks vertically on mobile) */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h1 className="text-lg sm:text-xl md:text-2xl font-bold font-mono text-white tracking-tight flex items-center gap-2 flex-wrap">
            <span>SOC Telemetry & Threat Hunting Workbench</span>
            <span className="px-2 py-0.5 rounded text-[10px] sm:text-[11px] font-mono uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold shrink-0">
              Tactical Operations
            </span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Search, filter, inspect, and export atomic Indicators of Compromise (IOCs) across normalized threat feeds.
          </p>
        </div>

        {/* Action Buttons: Full width grid on mobile, flex row on sm: */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 w-full md:w-auto">
          {/* Bulk Triage Modal Trigger */}
          <button
            onClick={onOpenBulkModal}
            className="flex items-center justify-center gap-2 px-3.5 py-2.5 min-h-[42px] rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-cyan-500/40 text-xs font-semibold text-slate-200 active:scale-95 transition-all"
          >
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>Bulk IOC Triage</span>
          </button>

          {/* Export CSV */}
          <a
            href={exportIndicatorsUrl(currentFilterParams, 'csv')}
            download="threatlens_indicators.csv"
            className="flex items-center justify-center gap-1.5 px-3.5 py-2.5 min-h-[42px] rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-slate-600 text-xs font-medium text-slate-300 active:scale-95 transition-all"
          >
            <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
            <span>Export CSV</span>
          </a>

          {/* Export JSON */}
          <a
            href={exportIndicatorsUrl(currentFilterParams, 'json')}
            download="threatlens_indicators.json"
            className="flex items-center justify-center gap-1.5 px-3.5 py-2.5 min-h-[42px] rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-slate-600 text-xs font-medium text-slate-300 active:scale-95 transition-all"
          >
            <FileCode className="w-4 h-4 text-blue-400" />
            <span>Export JSON</span>
          </a>
        </div>
      </div>

      {/* ── Multi-Filter Control Bar (Fully Responsive Stack on Mobile) ──────── */}
      <div className="p-4 sm:p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-3 items-center">
          
          {/* Search Input (Full width on mobile) */}
          <div className="sm:col-span-2 lg:col-span-5 relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IP, CVE, domain, URL, tag..."
              className="w-full pl-10 pr-4 py-2.5 min-h-[42px] rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/60 transition-all"
            />
          </div>

          {/* Severity Dropdown */}
          <div className="sm:col-span-1 lg:col-span-2">
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2.5 min-h-[42px] rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
            >
              <option value="ALL">Severity: ALL</option>
              <option value="CRITICAL">CRITICAL (≥ 85)</option>
              <option value="HIGH">HIGH (65 – 84.9)</option>
              <option value="MEDIUM">MEDIUM (40 – 64.9)</option>
              <option value="LOW">LOW (&lt; 40)</option>
            </select>
          </div>

          {/* IOC Type Dropdown */}
          <div className="sm:col-span-1 lg:col-span-2">
            <select
              value={iocType}
              onChange={(e) => {
                setIocType(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2.5 min-h-[42px] rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
            >
              <option value="ALL">IOC Type: ALL</option>
              <option value="cve">cve (Vulnerability)</option>
              <option value="ip">ip (Network)</option>
              <option value="url">url (Web Delivery)</option>
              <option value="domain">domain (Infrastructure)</option>
            </select>
          </div>

          {/* MITRE Technique Filter */}
          <div className="sm:col-span-2 lg:col-span-3">
            <select
              value={mitreTechnique}
              onChange={(e) => {
                setMitreTechnique(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2.5 min-h-[42px] rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
            >
              <option value="ALL">MITRE Technique: ALL</option>
              <option value="T1190">T1190 - Exploit Public-Facing App</option>
              <option value="T1105">T1105 - Ingress Tool Transfer</option>
              <option value="T1486">T1486 - Data Encrypted for Impact</option>
              <option value="T1490">T1490 - Inhibit System Recovery</option>
              <option value="T1071.001">T1071.001 - Web Protocols (C2)</option>
              <option value="T1110">T1110 - Brute Force</option>
              <option value="T1566">T1566 - Phishing</option>
            </select>
          </div>

        </div>

        {/* Active Filters Bar (Wraps cleanly on mobile) */}
        {(severity !== 'ALL' || iocType !== 'ALL' || mitreTechnique !== 'ALL' || debouncedSearch) && (
          <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 text-xs font-mono flex-wrap">
            <span className="text-slate-500 text-[11px]">Active Filters:</span>
            {severity !== 'ALL' && (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1">
                Severity: {severity}
                <button onClick={() => setSeverity('ALL')} className="hover:text-red-400 p-0.5">×</button>
              </span>
            )}
            {iocType !== 'ALL' && (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1">
                Type: {iocType}
                <button onClick={() => setIocType('ALL')} className="hover:text-red-400 p-0.5">×</button>
              </span>
            )}
            {mitreTechnique !== 'ALL' && (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1">
                MITRE: {mitreTechnique}
                <button onClick={() => setMitreTechnique('ALL')} className="hover:text-red-400 p-0.5">×</button>
              </span>
            )}
            {debouncedSearch && (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1">
                Query: "{debouncedSearch}"
                <button onClick={() => setSearch('')} className="hover:text-red-400 p-0.5">×</button>
              </span>
            )}
            <button
              onClick={() => {
                setSeverity('ALL');
                setIocType('ALL');
                setMitreTechnique('ALL');
                setSearch('');
              }}
              className="text-cyan-400 hover:text-cyan-300 underline ml-auto text-[11px] py-1"
            >
              Reset All Filters
            </button>
          </div>
        )}
      </div>

      {/* ── IOC Telemetry Table ─────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/90 shadow-xl overflow-hidden">
        
        {/* Table Top Controls & Record Count */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between flex-wrap gap-3 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Matched IOCs:</span>
            <span className="text-white font-bold">{total}</span>
            <span className="text-slate-500">records</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400 hidden sm:inline">Rows:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                className="px-2 py-1.5 min-h-[36px] rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <button
              onClick={loadData}
              title="Refresh table"
              className="p-2 min-h-[36px] min-w-[36px] rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 active:scale-95 transition-all flex items-center justify-center"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Table Container with Smooth Horizontal Scroll for Mobile */}
        <div className="overflow-x-auto -webkit-overflow-scrolling-touch">
          <table className="w-full text-left text-xs min-w-[760px]">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono tracking-wider text-[11px] border-b border-slate-800 select-none">
              <tr>
                {/* Severity Score Header (Sortable) */}
                <th
                  onClick={() => handleSort('severity_score')}
                  className="py-3 px-3.5 cursor-pointer hover:text-white transition-colors"
                >
                  <div className="flex items-center gap-1.5">
                    <span>Severity</span>
                    {sortBy === 'severity_score' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-cyan-400" /> : <ArrowDown className="w-3 h-3 text-cyan-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 opacity-40" />
                    )}
                  </div>
                </th>

                <th className="py-3 px-3.5">Indicator Value</th>
                <th className="py-3 px-3.5">Type</th>
                <th className="py-3 px-3.5">Feed Source</th>
                <th className="py-3 px-3.5">MITRE ATT&CK</th>
                <th className="py-3 px-3.5">Tags</th>

                {/* Last Seen Header (Sortable) */}
                <th
                  onClick={() => handleSort('last_seen')}
                  className="py-3 px-3.5 cursor-pointer hover:text-white transition-colors"
                >
                  <div className="flex items-center gap-1.5">
                    <span>Last Seen</span>
                    {sortBy === 'last_seen' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-cyan-400" /> : <ArrowDown className="w-3 h-3 text-cyan-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 opacity-40" />
                    )}
                  </div>
                </th>

                <th className="py-3 px-3.5 text-right">Actions</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-slate-800/80 bg-slate-900/60 font-mono">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-slate-400">
                    <RefreshCw className="w-6 h-6 animate-spin text-cyan-400 mx-auto mb-2" />
                    <span>Loading threat telemetry records...</span>
                  </td>
                </tr>
              ) : indicators.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-slate-500">
                    No threat indicators matched the selected criteria.
                  </td>
                </tr>
              ) : (
                indicators.map((ind) => (
                  <tr
                    key={ind.id}
                    onClick={() => onInspectIndicator(ind)}
                    className="hover:bg-slate-800/60 transition-colors cursor-pointer group"
                  >
                    {/* Severity Badge + Score */}
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                          SEVERITY_STYLES[ind.severity_label] || SEVERITY_STYLES.LOW
                        }`}
                      >
                        {ind.severity_label} • {ind.severity_score?.toFixed(1)}
                      </span>
                    </td>

                    {/* Indicator Value + 1-Click Copy */}
                    <td className="py-3 px-3.5 max-w-xs sm:max-w-sm truncate">
                      <div className="flex items-center gap-1.5 group-hover:text-cyan-300">
                        <span className="font-semibold text-slate-100 truncate" title={ind.value}>
                          {ind.value}
                        </span>
                        <button
                          onClick={(e) => handleCopy(ind.id, ind.value, e)}
                          title="Copy IOC value"
                          className="opacity-0 group-hover:opacity-100 p-1.5 min-h-[30px] min-w-[30px] flex items-center justify-center rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-all shrink-0 active:scale-95"
                        >
                          {copiedId === ind.id ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>

                    {/* IOC Type */}
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-semibold border ${
                          IOC_TYPE_COLORS[ind.ioc_type] || 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                      >
                        {ind.ioc_type}
                      </span>
                    </td>

                    {/* Source */}
                    <td className="py-3 px-3.5 whitespace-nowrap text-slate-300">
                      {ind.source}
                    </td>

                    {/* MITRE Techniques */}
                    <td className="py-3 px-3.5 max-w-[180px] truncate">
                      {ind.mitre_techniques ? (
                        <div className="flex items-center gap-1 flex-wrap">
                          {ind.mitre_techniques.split(',').slice(0, 2).map((tid) => (
                            <span
                              key={tid}
                              className="px-1.5 py-0.5 rounded bg-slate-950 text-[10px] text-cyan-400 border border-slate-800"
                            >
                              {tid.trim()}
                            </span>
                          ))}
                          {ind.mitre_techniques.split(',').length > 2 && (
                            <span className="text-[10px] text-slate-500">
                              +{ind.mitre_techniques.split(',').length - 2}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>

                    {/* Tags */}
                    <td className="py-3 px-3.5 max-w-[150px] truncate text-slate-400">
                      {ind.tags || '—'}
                    </td>

                    {/* Last Seen Relative */}
                    <td className="py-3 px-3.5 whitespace-nowrap text-slate-400 text-[11px]" title={ind.last_seen}>
                      {formatRelativeTime(ind.last_seen)}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-3.5 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onInspectIndicator(ind);
                        }}
                        className="inline-flex items-center gap-1 px-3 py-1.5 min-h-[36px] rounded-lg bg-slate-800/80 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 transition-all font-sans text-xs active:scale-95"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* ── Pagination Footer (Stacks on Mobile) ───────────────────────────── */}
        <div className="p-4 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
          <div className="text-slate-400 text-center sm:text-left">
            Showing <span className="text-white">{indicators.length > 0 ? (page - 1) * pageSize + 1 : 0}</span> to{' '}
            <span className="text-white">{Math.min(page * pageSize, total)}</span> of{' '}
            <span className="text-white font-bold">{total}</span> entries
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page <= 1 || loading}
              className="p-2 min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed active:scale-95 transition-all"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>

            <span className="px-3 py-2 min-h-[40px] flex items-center justify-center rounded-xl bg-slate-950 border border-slate-800 text-slate-200">
              Page {page} / {totalPages}
            </span>

            <button
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page >= totalPages || loading}
              className="p-2 min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed active:scale-95 transition-all"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>

      </div>

    </div>
  );
}
