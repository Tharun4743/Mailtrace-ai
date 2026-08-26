import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Flame,
  Inbox,
  ArrowUpRight,
  RefreshCw,
  Mail,
  ExternalLink,
  Plus
} from 'lucide-react';
import {
  AreaChart, Area, PieChart, Pie, Cell, ResponsiveContainer,
  XAxis, YAxis, Tooltip
} from 'recharts';
import { DashboardStats } from '../types';
import { api } from '../services/api';

export const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchTelemetry = async () => {
    try {
      const res = await api.get('/stats/dashboard');
      setStats(res.data);
    } catch (err) {
      console.error('Failed to load dashboard metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh] text-slate-500 font-mono text-xs gap-3">
        <RefreshCw className="w-5 h-5 animate-spin text-blue-700" />
        <span>Loading Threat Dashboard...</span>
      </div>
    );
  }

  const safeCount = stats?.safe_count || 0;
  const suspiciousCount = stats?.suspicious_count || 0;
  const maliciousCount = (stats?.high_risk_count || 0) + (stats?.critical_count || 0);
  const totalCount = stats?.total_analyzed || 0;

  const verdictCards = [
    {
      label: 'Total Ingested',
      value: totalCount,
      sub: 'All parsed messages',
      color: 'text-slate-900',
      border: 'border-slate-200',
      badge: 'All Emails'
    },
    {
      label: 'SAFE (Allow)',
      value: safeCount,
      sub: 'Risk Score 0 – 29',
      color: 'text-emerald-700',
      border: 'border-emerald-200',
      badge: 'Allowed'
    },
    {
      label: 'SUSPICIOUS (Warn User)',
      value: suspiciousCount,
      sub: 'Risk Score 30 – 69',
      color: 'text-amber-700',
      border: 'border-amber-200',
      badge: 'Warning'
    },
    {
      label: 'MALICIOUS (Quarantine)',
      value: maliciousCount,
      sub: 'Risk Score 70 – 100',
      color: 'text-red-700',
      border: 'border-red-200',
      badge: 'Quarantine'
    },
  ];

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-lg cyber-card bg-white">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">
            AI Threat Engine Dashboard
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time email ingestion, 6-pillar forensic analysis, and risk verdict tracking
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchTelemetry}
            className="px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <a
            href="/accounts"
            className="px-3.5 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors"
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Connect Mailbox</span>
          </a>
        </div>
      </div>

      {/* 4 Verdict Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {verdictCards.map((c, idx) => (
          <div key={idx} className={`p-4 rounded-lg cyber-card border ${c.border} bg-white space-y-2`}>
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-600">{c.label}</span>
              <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-700">
                {c.badge}
              </span>
            </div>
            <div className={`text-2xl font-bold font-mono ${c.color}`}>{c.value}</div>
            <div className="text-xs text-slate-400 font-mono">{c.sub}</div>
          </div>
        ))}
      </div>

      {/* Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <div className="lg:col-span-2 p-5 rounded-lg cyber-card bg-white space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-900">Analytics: Ingestion & Threat Trends</h2>
              <p className="text-xs text-slate-500">Timeline of allowed vs quarantined messages</p>
            </div>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.threat_trends || []}>
                <defs>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#dc2626" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#dc2626" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorSafe" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#16a34a" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#16a34a" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '8px', fontSize: '12px', color: '#0f172a' }}
                />
                <Area type="monotone" dataKey="threats" stroke="#dc2626" strokeWidth={2} fillOpacity={1} fill="url(#colorThreats)" name="Threats" />
                <Area type="monotone" dataKey="safe" stroke="#16a34a" strokeWidth={2} fillOpacity={1} fill="url(#colorSafe)" name="Safe" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Verdict Distribution */}
        <div className="p-5 rounded-lg cyber-card bg-white space-y-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900">Verdict Distribution</h2>
            <p className="text-xs text-slate-500">Safe vs Suspicious vs Malicious</p>
          </div>

          <div className="h-40 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={[
                    { name: 'Safe', count: safeCount, color: '#16a34a' },
                    { name: 'Suspicious', count: suspiciousCount, color: '#d97706' },
                    { name: 'Malicious', count: maliciousCount, color: '#dc2626' },
                  ]}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={65}
                  paddingAngle={4}
                  dataKey="count"
                >
                  <Cell fill="#16a34a" />
                  <Cell fill="#d97706" />
                  <Cell fill="#dc2626" />
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="space-y-1.5 pt-2 border-t border-slate-100 text-xs">
            <div className="flex justify-between">
              <span className="text-emerald-700 font-semibold">● Safe (Allow):</span>
              <span className="font-mono font-bold">{safeCount}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-amber-700 font-semibold">● Suspicious (Warn):</span>
              <span className="font-mono font-bold">{suspiciousCount}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-red-700 font-semibold">● Malicious (Quarantine):</span>
              <span className="font-mono font-bold">{maliciousCount}</span>
            </div>
          </div>
        </div>
      </div>

      {/* History / Recent Alerts Feed */}
      <div className="p-5 rounded-lg cyber-card bg-white space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900">Recent Threats & Alerts History</h3>
            <p className="text-xs text-slate-500">Latest flagged email events</p>
          </div>
          <a href="/emails" className="text-xs text-blue-700 font-semibold hover:underline flex items-center gap-1">
            <span>View All Emails</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </a>
        </div>

        <div className="space-y-2">
          {(stats?.recent_alerts || []).length > 0 ? (
            stats?.recent_alerts.map((alert) => (
              <div
                key={alert.id}
                className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-0.5 truncate">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-red-700">Risk {alert.risk_score}/100</span>
                    <span className="font-bold text-slate-900 truncate">{alert.title}</span>
                  </div>
                  <p className="text-slate-500 truncate">{alert.message}</p>
                </div>
                <a
                  href={`/emails/${alert.email_id}`}
                  className="px-2.5 py-1 rounded bg-blue-50 text-blue-700 font-semibold hover:bg-blue-100 text-xs shrink-0"
                >
                  Investigate
                </a>
              </div>
            ))
          ) : (
            <div className="text-xs text-slate-400 py-6 text-center">
              No recent threats detected.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
