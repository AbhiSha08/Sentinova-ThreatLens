import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Flame,
  Radio,
  TrendingUp,
  AlertTriangle,
  Building,
  Globe2,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Layers,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { fetchExecutiveSummary } from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

const IOC_TYPE_COLORS = {
  cve: '#a855f7',
  url: '#3b82f6',
  ip: '#06b6d4',
  domain: '#6366f1',
};

// Custom dark-mode tooltip for Recharts
const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-700 shadow-xl font-mono text-xs text-white space-y-1">
        <p className="font-semibold text-slate-300">{label || data.name}</p>
        <p className="text-cyan-400 font-bold">
          Count: <span className="text-white">{data.value}</span>
        </p>
      </div>
    );
  }
  return null;
};

export default function ExecutiveView({ onNavigateToAnalyst, onInspectIndicator }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadSummary();
  }, []);

  const loadSummary = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchExecutiveSummary();
      setData(result);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to load executive summary');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="py-24 flex flex-col items-center justify-center gap-4 text-slate-400 px-4 text-center">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
        <span className="text-xs sm:text-sm font-mono tracking-wider">
          Aggregating Global Threat Landscape Telemetry...
        </span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto my-12 p-6 rounded-2xl bg-red-950/40 border border-red-800 text-center space-y-3">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto" />
        <h3 className="text-base font-bold text-white font-mono">Failed to Load Executive Intelligence</h3>
        <p className="text-xs text-red-200">{error}</p>
        <button
          onClick={loadSummary}
          className="px-4 py-2 min-h-[40px] rounded-lg bg-red-900/60 hover:bg-red-800 text-xs font-semibold text-white transition-colors active:scale-95"
        >
          Retry Fetch
        </button>
      </div>
    );
  }

  // Prepare chart datasets
  const severityChartData = data?.severity_distribution
    ? Object.entries(data.severity_distribution).map(([name, value]) => ({
        name,
        value,
        color: SEVERITY_COLORS[name] || '#94a3b8',
      }))
    : [];

  const iocTypeChartData = data?.ioc_type_distribution
    ? Object.entries(data.ioc_type_distribution).map(([name, value]) => ({
        name: name.toUpperCase(),
        value,
        rawType: name,
        color: IOC_TYPE_COLORS[name] || '#64748b',
      }))
    : [];

  const mitreChartData = data?.top_mitre_techniques
    ? data.top_mitre_techniques.map((t) => ({
        id: t.id,
        name: t.name,
        shortName: t.id,
        count: t.count,
      }))
    : [];

  return (
    <div className="space-y-6 sm:space-y-8 animate-in fade-in duration-300">
      
      {/* Executive Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h1 className="text-lg sm:text-xl md:text-2xl font-bold font-mono text-white tracking-tight flex items-center gap-2 flex-wrap">
            <span>Threat Landscape & Executive Posture</span>
            <span className="px-2 py-0.5 rounded text-[10px] sm:text-[11px] font-mono uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold shrink-0">
              Strategic View
            </span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Real-time Cyber Threat Intelligence (CTI) aggregation, vulnerability exploitation, and attack surface analytics.
          </p>
        </div>

        <button
          onClick={loadSummary}
          className="flex items-center justify-center gap-2 w-full sm:w-auto px-4 py-2 min-h-[40px] rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 active:scale-95 transition-all shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
          <span>Refresh Analytics (300s Cache)</span>
        </button>
      </div>

      {/* ── Top KPI Row (5 Cards) ───────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5 sm:gap-4">
        
        {/* Total Active IOCs */}
        <div className="p-4 sm:p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Active IOCs</span>
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5 sm:mt-3 text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight">
            {data.total_indicators}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Normalized across all feeds</p>
        </div>

        {/* Critical Severity Alerts */}
        <div className="p-4 sm:p-5 rounded-2xl bg-gradient-to-br from-red-950/40 to-slate-900/90 border border-red-900/40 shadow-lg shadow-red-950/20 relative overflow-hidden group hover:border-red-700/60 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-red-300">Critical Alerts</span>
            <div className="p-2 rounded-lg bg-red-500/20 text-red-400 animate-pulse">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5 sm:mt-3 text-2xl sm:text-3xl font-extrabold font-mono text-red-400 tracking-tight">
            {data.critical_count}
          </div>
          <p className="text-[11px] text-red-300/70 mt-1">Require immediate containment</p>
        </div>

        {/* Ransomware Linked */}
        <div className="p-4 sm:p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Ransomware Links</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5 sm:mt-3 text-2xl sm:text-3xl font-extrabold font-mono text-amber-400 tracking-tight">
            {data.ransomware_linked_count}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Known extortion campaigns</p>
        </div>

        {/* Average Risk Score */}
        <div className="p-4 sm:p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Platform Risk Score</span>
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5 sm:mt-3 text-2xl sm:text-3xl font-extrabold font-mono text-cyan-400 tracking-tight">
            {data.average_risk_score} <span className="text-xs text-slate-500 font-normal">/ 100</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Multi-factor composite weighted</p>
        </div>

        {/* Active Feeds Online */}
        <div className="p-4 sm:p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg relative overflow-hidden group hover:border-slate-700 transition-all sm:col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Active Feeds</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <Radio className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5 sm:mt-3 text-2xl sm:text-3xl font-extrabold font-mono text-emerald-400 tracking-tight">
            {data.active_feeds_count}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">CISA KEV, URLhaus, AbuseIPDB</p>
        </div>

      </div>

      {/* ── Visualizations Grid ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 sm:gap-6">
        
        {/* 1. Severity Distribution Donut */}
        <div className="p-4 sm:p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-1">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              IOC Severity Distribution
            </h3>
            <span className="text-[11px] text-slate-400">Tap slice to filter in SOC View</span>
          </div>

          <div className="h-60 sm:h-64 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityChartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={4}
                  dataKey="value"
                  onClick={(entry) => onNavigateToAnalyst && onNavigateToAnalyst({ severity: entry.name })}
                  className="cursor-pointer focus:outline-none"
                >
                  {severityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* 2-col on mobile, 4-col on sm: */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800">
            {severityChartData.map((s) => (
              <button
                key={s.name}
                onClick={() => onNavigateToAnalyst && onNavigateToAnalyst({ severity: s.name })}
                className="p-2 sm:p-2.5 rounded-xl bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800 text-center transition-all active:scale-95 group min-h-[44px]"
              >
                <div className="text-[10px] sm:text-[11px] font-semibold font-mono" style={{ color: s.color }}>
                  {s.name}
                </div>
                <div className="text-xs sm:text-sm font-bold font-mono text-white group-hover:text-cyan-300">{s.value}</div>
              </button>
            ))}
          </div>
        </div>

        {/* 2. IOC Type Breakdown */}
        <div className="p-4 sm:p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-1">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-400" />
              Telemetry Breakdown by IOC Type
            </h3>
            <span className="text-[11px] text-slate-400">Multi-source categorization</span>
          </div>

          <div className="h-60 sm:h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={iocTypeChartData} margin={{ top: 15, right: 10, left: -15, bottom: 5 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} fontFamily="monospace" />
                <YAxis stroke="#64748b" fontSize={10} fontFamily="monospace" />
                <Tooltip content={<CustomTooltip />} />
                <Bar
                  dataKey="value"
                  radius={[6, 6, 0, 0]}
                  onClick={(entry) => onNavigateToAnalyst && onNavigateToAnalyst({ ioc_type: entry.rawType })}
                  className="cursor-pointer"
                >
                  {iocTypeChartData.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* 2-col on mobile, 4-col on sm: */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800">
            {iocTypeChartData.map((t) => (
              <button
                key={t.name}
                onClick={() => onNavigateToAnalyst && onNavigateToAnalyst({ ioc_type: t.rawType })}
                className="p-2 sm:p-2.5 rounded-xl bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800 text-center transition-all active:scale-95 group min-h-[44px]"
              >
                <div className="text-[10px] sm:text-[11px] font-semibold font-mono" style={{ color: t.color }}>
                  {t.name}
                </div>
                <div className="text-xs sm:text-sm font-bold font-mono text-white group-hover:text-cyan-300">{t.value}</div>
              </button>
            ))}
          </div>
        </div>

        {/* 3. Top MITRE ATT&CK Techniques */}
        <div className="p-4 sm:p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-1">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              Top MITRE ATT&CK Techniques
            </h3>
            <span className="text-[11px] text-slate-400">By observed IOC volume</span>
          </div>

          <div className="space-y-2.5">
            {mitreChartData.map((tech) => (
              <div
                key={tech.id}
                onClick={() => onNavigateToAnalyst && onNavigateToAnalyst({ mitre_technique: tech.id })}
                className="p-2.5 rounded-xl bg-slate-950/60 hover:bg-slate-800/70 border border-slate-800/80 hover:border-purple-500/40 transition-all cursor-pointer group active:scale-98"
              >
                <div className="flex items-center justify-between text-xs mb-1.5 gap-2">
                  <span className="font-mono font-bold text-purple-300 group-hover:text-purple-200 truncate">
                    {tech.name}
                  </span>
                  <span className="font-mono text-[11px] font-semibold text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800 shrink-0">
                    {tech.count} IOCs
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-purple-500 to-indigo-500 rounded-full transition-all"
                    style={{ width: `${Math.min(100, (tech.count / (data.total_indicators || 1)) * 100 * 2)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 4. Vendors & Origin Countries Split Panel (Stacks cleanly on mobile) */}
        <div className="p-4 sm:p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-5">
          {/* Top Vendors */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <Building className="w-4 h-4 text-amber-400" />
              Most Targeted Vendors (CISA KEV)
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {data.top_targeted_vendors?.map((v) => (
                <div key={v.vendor} className="p-2 rounded-xl bg-slate-950/70 border border-slate-800 text-center">
                  <div className="text-[11px] font-semibold text-slate-300 truncate" title={v.vendor}>
                    {v.vendor}
                  </div>
                  <div className="text-xs sm:text-sm font-bold font-mono text-amber-400 mt-0.5">
                    {v.count} <span className="text-[9px] text-slate-500 font-normal">CVEs</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Top Origin Countries */}
          <div className="space-y-3 pt-3 border-t border-slate-800">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <Globe2 className="w-4 h-4 text-emerald-400" />
              Observed Threat Origin Countries
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {data.top_origin_countries?.map((c) => (
                <div key={c.country_code} className="p-2 rounded-xl bg-slate-950/70 border border-slate-800 text-center">
                  <div className="text-xs font-mono font-bold text-slate-200">
                    {c.country_code}
                  </div>
                  <div className="text-xs sm:text-sm font-bold font-mono text-emerald-400 mt-0.5">
                    {c.count} <span className="text-[9px] text-slate-500 font-normal">IOCs</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

      {/* ── Recent Critical Alerts Table (Horizontal Scroll on Mobile) ──────── */}
      <div className="p-4 sm:p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-base font-bold font-mono text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              Recent High-Risk Critical Alerts
            </h3>
            <p className="text-xs text-slate-400">
              Top 5 highest-scoring indicators requiring urgent containment
            </p>
          </div>
          <button
            onClick={() => onNavigateToAnalyst && onNavigateToAnalyst({ severity: 'CRITICAL' })}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors self-start sm:self-auto py-1"
          >
            <span>View All Critical IOCs</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800 -webkit-overflow-scrolling-touch">
          <table className="w-full text-left text-xs min-w-[640px]">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Severity & Score</th>
                <th className="py-3 px-4">Indicator Value</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Feed Source</th>
                <th className="py-3 px-4">MITRE Techniques</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/60 font-mono">
              {data.recent_critical_alerts?.map((alert) => (
                <tr key={alert.id} className="hover:bg-slate-800/60 transition-colors">
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-red-500/15 text-red-400 border border-red-500/30">
                      CRITICAL • {alert.severity_score?.toFixed(1)}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-semibold text-slate-100 max-w-xs truncate" title={alert.value}>
                    {alert.value}
                  </td>
                  <td className="py-3 px-4 uppercase text-slate-400 font-semibold">
                    {alert.ioc_type}
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    {alert.source}
                  </td>
                  <td className="py-3 px-4 text-cyan-400">
                    {alert.mitre_techniques || 'N/A'}
                  </td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <button
                      onClick={() => onInspectIndicator && onInspectIndicator(alert)}
                      className="inline-flex items-center gap-1 px-3 py-1.5 min-h-[36px] rounded-lg bg-slate-800 hover:bg-cyan-500/20 text-cyan-400 border border-slate-700 hover:border-cyan-500/50 transition-all font-sans text-xs font-medium active:scale-95"
                    >
                      <span>Deep Inspect</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
