import React, { useEffect, useState } from 'react';
import { Settings, Shield, Mail, Key, ExternalLink, RefreshCw, Trash2, Bell, CheckCircle2, Save } from 'lucide-react';
import { api } from '../services/api';
import { ConnectedAccount } from '../types';

export const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'mailboxes' | 'api_keys' | 'notifications'>('mailboxes');
  
  // Mailbox Accounts state
  const [accounts, setAccounts] = useState<ConnectedAccount[]>([]);
  const [syncingId, setSyncingId] = useState<number | null>(null);
  
  // API Keys state
  const [vtKey, setVtKey] = useState('');
  const [abuseKey, setAbuseKey] = useState('');
  const [otxKey, setOtxKey] = useState('');
  const [googleClientId, setGoogleClientId] = useState('');
  const [googleSecret, setGoogleSecret] = useState('');
  const [msClientId, setMsClientId] = useState('');
  const [msSecret, setMsSecret] = useState('');
  
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [notificationPermission, setNotificationPermission] = useState<string>(
    'Notification' in window ? Notification.permission : 'unsupported'
  );

  const fetchAccounts = async () => {
    try {
      const res = await api.get('/oauth/accounts');
      setAccounts(res.data);
    } catch (err) {
      console.error('Failed to load accounts:', err);
    }
  };

  const fetchSettings = async () => {
    try {
      const res = await api.get('/settings');
      if (res.data) {
        setVtKey(res.data.virustotal_api_key || '');
        setAbuseKey(res.data.abuseipdb_api_key || '');
        setOtxKey(res.data.alienvault_otx_key || '');
        setGoogleClientId(res.data.google_client_id || '');
        setGoogleSecret(res.data.google_client_secret || '');
        setMsClientId(res.data.microsoft_client_id || '');
        setMsSecret(res.data.microsoft_client_secret || '');
      }
    } catch (err) {
      console.error('Failed to load settings:', err);
    }
  };

  useEffect(() => {
    fetchAccounts();
    fetchSettings();

    // Check for OAuth callback code in URL params
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const isGoogle = window.location.pathname.includes('google') || window.location.search.includes('google') || urlParams.get('scope')?.includes('google');
    const isMicrosoft = window.location.pathname.includes('microsoft');

    if (code) {
      const handleCallback = async () => {
        setMessage('Authenticating and linking mailbox...');
        try {
          if (isMicrosoft) {
            await api.post('/oauth/microsoft/callback', { code, state });
          } else {
            await api.post('/oauth/google/callback', { code, state });
          }
          setMessage('✅ Mailbox successfully connected and active!');
          window.history.replaceState({}, document.title, '/settings');
          await fetchAccounts();
        } catch (err: any) {
          setMessage(`OAuth connection failed: ${err.response?.data?.detail || err.message}`);
        }
      };
      handleCallback();
    }
  }, []);

  const handleConnectGoogle = async () => {
    try {
      const res = await api.get('/oauth/google/init');
      if (res.data.authorization_url) {
        window.location.href = res.data.authorization_url;
      }
    } catch (err: any) {
      setMessage('Google OAuth requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET configured in environment.');
    }
  };

  const handleConnectMicrosoft = async () => {
    try {
      const res = await api.get('/oauth/microsoft/init');
      if (res.data.authorization_url) {
        window.location.href = res.data.authorization_url;
      }
    } catch (err: any) {
      setMessage('Microsoft OAuth requires MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET configured in environment.');
    }
  };

  const handleSyncAccount = async (accId: number) => {
    setSyncingId(accId);
    try {
      const mailboxesRes = await api.get('/mailboxes');
      const mailbox = mailboxesRes.data.find((m: any) => m.oauth_account_id === accId || m.id === accId);
      if (mailbox) {
        await api.post(`/mailboxes/${mailbox.id}/sync`);
      }
      await fetchAccounts();
      setMessage('Mailbox synchronized successfully.');
    } catch (err: any) {
      setMessage(`Sync failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setSyncingId(null);
    }
  };

  const handleDisconnect = async (accId: number) => {
    if (!confirm('Are you sure you want to disconnect this mailbox?')) return;
    try {
      await api.delete(`/oauth/disconnect/${accId}`);
      await fetchAccounts();
      setMessage('Mailbox disconnected.');
    } catch (err) {
      console.error('Failed to disconnect account:', err);
    }
  };

  const handleSaveKeys = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setMessage(null);
    try {
      await api.post('/settings/update', {
        virustotal_api_key: vtKey || undefined,
        abuseipdb_api_key: abuseKey || undefined,
        alienvault_otx_key: otxKey || undefined,
        google_client_id: googleClientId || undefined,
        google_client_secret: googleSecret || undefined,
        microsoft_client_id: msClientId || undefined,
        microsoft_client_secret: msSecret || undefined,
      });
      setMessage('Settings updated successfully.');
      fetchSettings();
    } catch (err: any) {
      setMessage(`Save failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const requestNotificationPermission = async () => {
    if ('Notification' in window) {
      const perm = await Notification.requestPermission();
      setNotificationPermission(perm);
      if (perm === 'granted') {
        new Notification('🔔 MAILTRACE AI Notifications Enabled', {
          body: 'You will receive immediate alerts when high-risk emails arrive.'
        });
      }
    }
  };

  const isGoogleConnected = accounts.some(a => a.provider === 'google' && a.is_active);
  const isMicrosoftConnected = accounts.some(a => a.provider === 'microsoft' && a.is_active);

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto font-sans">
      {/* Header */}
      <div className="p-5 rounded-lg cyber-card bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">System Settings</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Manage mailbox OAuth connections, security keys, and real-time alert preferences
          </p>
        </div>
      </div>

      {message && (
        <div className="p-3.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-900 text-xs flex items-center justify-between font-mono">
          <span>{message}</span>
          <button onClick={() => setMessage(null)} className="text-slate-400 hover:text-slate-700">✕</button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-slate-200 gap-4 text-xs font-semibold">
        <button
          onClick={() => setActiveTab('mailboxes')}
          className={`pb-2.5 flex items-center gap-1.5 transition-colors border-b-2 ${
            activeTab === 'mailboxes'
              ? 'border-blue-700 text-blue-700 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <Mail className="w-4 h-4" />
          <span>Connected Mailboxes ({accounts.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('notifications')}
          className={`pb-2.5 flex items-center gap-1.5 transition-colors border-b-2 ${
            activeTab === 'notifications'
              ? 'border-blue-700 text-blue-700 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <Bell className="w-4 h-4" />
          <span>Real-Time Notifications</span>
        </button>

        <button
          onClick={() => setActiveTab('api_keys')}
          className={`pb-2.5 flex items-center gap-1.5 transition-colors border-b-2 ${
            activeTab === 'api_keys'
              ? 'border-blue-700 text-blue-700 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-900'
          }`}
        >
          <Key className="w-4 h-4" />
          <span>API Credentials</span>
        </button>
      </div>

      {/* Tab 1: Mailboxes */}
      {activeTab === 'mailboxes' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Google Workspace */}
            <div className="p-5 rounded-lg cyber-card bg-white space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-lg bg-red-50 border border-red-200 flex items-center justify-center">
                    <Mail className="w-5 h-5 text-red-600" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">Google Workspace / Gmail</h3>
                    <p className="text-xs text-slate-500">OAuth 2.0 Ingestion</p>
                  </div>
                </div>
                {isGoogleConnected && <span className="badge-safe text-[10px]">Connected</span>}
              </div>
              <button
                onClick={handleConnectGoogle}
                className="w-full py-2 rounded-lg bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
              >
                <span>{isGoogleConnected ? 'Reconnect Google Account' : 'Connect Google Workspace'}</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Microsoft 365 */}
            <div className="p-5 rounded-lg cyber-card bg-white space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center">
                    <Mail className="w-5 h-5 text-blue-600" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">Microsoft 365</h3>
                    <p className="text-xs text-slate-500">Graph API Ingestion</p>
                  </div>
                </div>
                {isMicrosoftConnected && <span className="badge-safe text-[10px]">Connected</span>}
              </div>
              <button
                onClick={handleConnectMicrosoft}
                className="w-full py-2 rounded-lg bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
              >
                <span>{isMicrosoftConnected ? 'Reconnect Microsoft 365' : 'Connect Microsoft 365'}</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Active Accounts Table */}
          <div className="p-5 rounded-lg cyber-card bg-white space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-900">Monitored Mailbox Connections</h2>
              <button
                onClick={fetchAccounts}
                className="p-1.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-600 hover:text-slate-900 text-xs transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500 uppercase text-[11px] font-semibold">
                    <th className="pb-2.5">Mailbox Email</th>
                    <th className="pb-2.5">Provider</th>
                    <th className="pb-2.5">Status</th>
                    <th className="pb-2.5">Analyzed</th>
                    <th className="pb-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono">
                  {accounts.length > 0 ? (
                    accounts.map((acc) => (
                      <tr key={acc.id} className="hover:bg-slate-50">
                        <td className="py-3 font-semibold text-slate-900">{acc.email}</td>
                        <td className="py-3 uppercase text-slate-600">{acc.provider}</td>
                        <td className="py-3">
                          <span className="badge-safe">{acc.sync_status}</span>
                        </td>
                        <td className="py-3 text-slate-800">{acc.total_emails_analyzed}</td>
                        <td className="py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => handleSyncAccount(acc.id)}
                              disabled={syncingId === acc.id}
                              className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-sans font-semibold transition-colors"
                            >
                              {syncingId === acc.id ? 'Syncing...' : 'Sync'}
                            </button>
                            <button
                              onClick={() => handleDisconnect(acc.id)}
                              className="p-1 rounded bg-red-50 hover:bg-red-100 text-red-600 text-xs transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-slate-400 font-sans text-xs">
                        No active mailbox connections. Click Connect above to start automated monitoring.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Notifications */}
      {activeTab === 'notifications' && (
        <div className="p-5 rounded-lg cyber-card bg-white space-y-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900">Real-Time Threat Notifications</h2>
            <p className="text-xs text-slate-500">Configure instant laptop desktop alerts and mobile push delivery</p>
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-bold text-slate-900">Desktop / Laptop Notifications</div>
                <div className="text-slate-500 text-[11px]">Instant popup alert when suspicious or malicious emails arrive</div>
              </div>

              <div className="flex items-center gap-2">
                <span className="font-mono uppercase font-bold text-[10px] px-2 py-0.5 rounded bg-slate-200 text-slate-700">
                  {notificationPermission}
                </span>
                {notificationPermission !== 'granted' && (
                  <button
                    onClick={requestNotificationPermission}
                    className="px-3 py-1.5 rounded bg-blue-700 hover:bg-blue-800 text-white font-semibold text-xs"
                  >
                    Enable Notifications
                  </button>
                )}
              </div>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs">
            <div className="font-bold text-slate-900">Default Notification Policy</div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-[11px]">
              <div className="p-2.5 rounded bg-white border border-slate-200">
                <span className="text-emerald-700 font-bold">● SAFE (0–29):</span>
                <p className="text-slate-500 font-sans text-xs mt-0.5">Silent / No alert</p>
              </div>
              <div className="p-2.5 rounded bg-white border border-slate-200">
                <span className="text-amber-700 font-bold">● SUSPICIOUS (30–69):</span>
                <p className="text-slate-500 font-sans text-xs mt-0.5">Warning notification</p>
              </div>
              <div className="p-2.5 rounded bg-white border border-slate-200">
                <span className="text-red-700 font-bold">● HIGH RISK (70–100):</span>
                <p className="text-slate-500 font-sans text-xs mt-0.5">Immediate priority alert</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: API Credentials */}
      {activeTab === 'api_keys' && (
        <form onSubmit={handleSaveKeys} className="p-5 rounded-lg cyber-card bg-white space-y-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900">API Credentials</h2>
            <p className="text-xs text-slate-500">Threat intelligence and OAuth service keys</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="font-semibold text-slate-700">VirusTotal API Key</label>
              <input
                type="password"
                value={vtKey}
                onChange={(e) => setVtKey(e.target.value)}
                placeholder="vt_api_key_..."
                className="w-full mt-1 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 font-mono text-xs"
              />
            </div>

            <div>
              <label className="font-semibold text-slate-700">AbuseIPDB API Key</label>
              <input
                type="password"
                value={abuseKey}
                onChange={(e) => setAbuseKey(e.target.value)}
                placeholder="abuseipdb_api_key_..."
                className="w-full mt-1 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 font-mono text-xs"
              />
            </div>

            <div>
              <label className="font-semibold text-slate-700">Google OAuth Client ID</label>
              <input
                type="text"
                value={googleClientId}
                onChange={(e) => setGoogleClientId(e.target.value)}
                placeholder="xxxx.apps.googleusercontent.com"
                className="w-full mt-1 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 font-mono text-xs"
              />
            </div>

            <div>
              <label className="font-semibold text-slate-700">Microsoft OAuth Client ID</label>
              <input
                type="text"
                value={msClientId}
                onChange={(e) => setMsClientId(e.target.value)}
                placeholder="Azure App Client ID"
                className="w-full mt-1 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 font-mono text-xs"
              />
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 rounded-lg bg-blue-700 hover:bg-blue-800 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
