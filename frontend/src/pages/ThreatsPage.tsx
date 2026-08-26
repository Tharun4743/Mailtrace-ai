import React, { useEffect, useState } from 'react';
import { Flame, AlertTriangle, ExternalLink, RefreshCw, Ban, CheckCircle } from 'lucide-react';
import { EmailListItem } from '../types';
import { api } from '../services/api';

export const ThreatsPage: React.FC = () => {
  const [threats, setThreats] = useState<EmailListItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchThreats = async () => {
    setLoading(true);
    try {
      const res = await api.get('/emails?limit=100');
      // Filter only threats (risk score >= 30)
      const flagged = res.data.filter((e: any) => e.risk_score >= 30);
      setThreats(flagged);
    } catch (err) {
      console.error('Failed to load threats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  const handleAction = async (emailId: number, action: 'QUARANTINE' | 'MARK_SAFE') => {
    try {
      await api.post(`/emails/${emailId}/action`, { action });
      fetchThreats();
    } catch (err) {
      console.error('Action failed:', err);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto font-sans">
      <div className="flex items-center justify-between p-5 rounded-lg cyber-card bg-white">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Threats Quarantine Queue</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Flagged suspicious and high-risk emails requiring immediate SOC triage
          </p>
        </div>

        <button
          onClick={fetchThreats}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold hover:bg-slate-100"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="space-y-3">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            Scanning quarantined threat pool...
          </div>
        ) : threats.length > 0 ? (
          threats.map((threat) => {
            const isHigh = threat.risk_score >= 70;
            return (
              <div
                key={threat.id}
                className={`p-4 rounded-lg cyber-card bg-white flex flex-col md:flex-row md:items-center justify-between gap-4 border-l-4 ${
                  isHigh ? 'border-l-red-600' : 'border-l-amber-500'
                }`}
              >
                <div className="space-y-1 min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      isHigh ? 'bg-red-50 text-red-700 border border-red-200' : 'bg-amber-50 text-amber-700 border border-amber-200'
                    }`}>
                      {isHigh ? 'HIGH RISK' : 'SUSPICIOUS'}
                    </span>
                    <span className="font-mono font-bold text-xs text-slate-900">
                      Score: {threat.risk_score}/100
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      {threat.date_received ? new Date(threat.date_received).toLocaleDateString() : 'Today'}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-slate-900 truncate">
                    <a href={`/emails/${threat.id}`} className="hover:text-blue-700">
                      {threat.subject || '(No Subject)'}
                    </a>
                  </h3>

                  <div className="text-xs font-mono text-slate-600 truncate">
                    From: {threat.sender_display_name} &lt;{threat.sender_email}&gt;
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end md:self-auto">
                  <button
                    onClick={() => handleAction(threat.id, 'QUARANTINE')}
                    className="px-3 py-1 rounded bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 text-xs font-semibold flex items-center gap-1"
                  >
                    <Ban className="w-3.5 h-3.5" />
                    <span>Quarantine</span>
                  </button>
                  <button
                    onClick={() => handleAction(threat.id, 'MARK_SAFE')}
                    className="px-3 py-1 rounded bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 text-xs font-semibold flex items-center gap-1"
                  >
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Allow</span>
                  </button>
                  <a
                    href={`/emails/${threat.id}`}
                    className="px-3 py-1 rounded bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold flex items-center gap-1"
                  >
                    <span>Inspect</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              </div>
            );
          })
        ) : (
          <div className="p-12 text-center text-slate-400 text-xs cyber-card bg-white rounded-lg">
            No active threats in quarantine. Mailbox is clean.
          </div>
        )}
      </div>
    </div>
  );
};
