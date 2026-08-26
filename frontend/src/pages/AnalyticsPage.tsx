import React, { useEffect, useState } from 'react';
import { AreaChart, Area, PieChart, Pie, Cell, ResponsiveContainer, XAxis, YAxis, Tooltip } from 'recharts';
import { DashboardStats } from '../types';
import { api } from '../services/api';
import { RefreshCw } from 'lucide-react';

export const AnalyticsPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await api.get('/stats/dashboard');
        setStats(res.data);
      } catch (err) {
        console.error('Failed to load analytics:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  const total = stats?.total_analyzed || 0;
  const safe = stats?.safe_count || 0;
  const suspicious = stats?.suspicious_count || 0;
  const highRisk = (stats?.high_risk_count || 0) + (stats?.critical_count || 0);

  const safePct = total > 0 ? Math.round((safe / total) * 100) : 0;
  const suspPct = total > 0 ? Math.round((suspicious / total) * 100) : 0;
  const highPct = total > 0 ? Math.round((highRisk / total) * 100) : 0;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto font-sans">
      {/* Header */}
      <div className="flex items-center justify-between p-5 rounded-lg cyber-card bg-white">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Threat Analytics</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Statistical breakdown of multi-signal threat detection metrics
          </p>
        </div>
      </div>

      {/* Top Threat Detection Overview Bar */}
      <div className="p-6 rounded-lg cyber-card bg-white space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-900">Threat Detection Overview</h2>
          <span className="text-xs text-slate-400 font-mono">Total: {total} emails</span>
        </div>

        {/* Visual Multi-Segment Bar */}
        <div className="h-4 w-full rounded-full bg-slate-100 flex overflow-hidden">
          <div style={{ width: `${safePct || 80}%` }} className="bg-emerald-500 transition-all duration-500" title={`Safe: ${safePct}%`} />
          <div style={{ width: `${suspPct || 14}%` }} className="bg-amber-500 transition-all duration-500" title={`Suspicious: ${suspPct}%`} />
          <div style={{ width: `${highPct || 6}%` }} className="bg-red-500 transition-all duration-500" title={`High Risk: ${highPct}%`} />
        </div>

        <div className="grid grid-cols-3 gap-4 pt-2 text-center text-xs font-mono">
          <div className="p-3 rounded bg-emerald-50 border border-emerald-200">
            <div className="font-bold text-emerald-800 text-lg">{safePct}%</div>
            <div className="text-emerald-700 font-sans mt-0.5">Safe (Allow)</div>
          </div>
          <div className="p-3 rounded bg-amber-50 border border-amber-200">
            <div className="font-bold text-amber-800 text-lg">{suspPct}%</div>
            <div className="text-amber-700 font-sans mt-0.5">Suspicious (Warn)</div>
          </div>
          <div className="p-3 rounded bg-red-50 border border-red-200">
            <div className="font-bold text-red-800 text-lg">{highPct}%</div>
            <div className="text-red-700 font-sans mt-0.5">High Risk (Quarantine)</div>
          </div>
        </div>
      </div>

      {/* Analytics Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-5 rounded-lg cyber-card bg-white space-y-3">
          <h3 className="text-xs font-bold text-slate-900">Threat Detection Velocity</h3>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.threat_trends || []}>
                <XAxis dataKey="date" fontSize={11} stroke="#94a3b8" />
                <YAxis fontSize={11} stroke="#94a3b8" />
                <Tooltip />
                <Area type="monotone" dataKey="threats" stroke="#dc2626" fill="#fecaca" name="Threats" />
                <Area type="monotone" dataKey="safe" stroke="#16a34a" fill="#bbf7d0" name="Safe" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-5 rounded-lg cyber-card bg-white space-y-3">
          <h3 className="text-xs font-bold text-slate-900">5-Layer Risk Weight Distribution</h3>
          <div className="space-y-2 text-xs font-mono pt-2">
            <div className="flex justify-between p-2 rounded bg-slate-50 border border-slate-200">
              <span className="text-slate-600">Sender Reputation:</span>
              <span className="font-bold text-slate-900">Max 20 pts</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50 border border-slate-200">
              <span className="text-slate-600">Authentication (SPF/DKIM/DMARC):</span>
              <span className="font-bold text-slate-900">Max 15 pts</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50 border border-slate-200">
              <span className="text-slate-600">Content / NLP Analysis:</span>
              <span className="font-bold text-slate-900">Max 25 pts</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50 border border-slate-200">
              <span className="text-slate-600">URL Analysis & Deceptive Links:</span>
              <span className="font-bold text-slate-900">Max 20 pts</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50 border border-slate-200">
              <span className="text-slate-600">Attachment Analysis:</span>
              <span className="font-bold text-slate-900">Max 20 pts</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
