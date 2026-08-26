import React, { useEffect, useState } from 'react';
import { Shield, Bell, User, LogOut, Radio, AlertTriangle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const [liveAlert, setLiveAlert] = useState<any | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  useEffect(() => {
    // Request Desktop Notification Permission
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }

    // Connect WebSocket
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.hostname}:8000/api/v1/ws`;
    
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connectWs = () => {
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => {
          setWsConnected(true);
        };
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'NEW_THREAT_DETECTED') {
              const threat = msg.data;
              setLiveAlert(threat);

              // 1. Laptop / Desktop Notification
              if ('Notification' in window && Notification.permission === 'granted') {
                new Notification(`🚨 ${threat.severity} Threat Detected: ${threat.subject || 'Security Alert'}`, {
                  body: `Risk Score: ${threat.risk_score}/100 | ${threat.threat_type}\nFrom: ${threat.sender}\n${threat.reasoning || ''}`
                });
              }
            }
          } catch (e) {
            // parse error fallback
          }
        };
        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWs, 5000);
        };
        ws.onerror = () => {
          ws?.close();
        };
      } catch (err) {
        reconnectTimeout = setTimeout(connectWs, 5000);
      }
    };

    connectWs();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  return (
    <>
      <header className="h-16 border-b border-slate-200 bg-white sticky top-0 z-50 flex items-center justify-between px-6 select-none shadow-xs">
        {/* Brand & Engine Status */}
        <div className="flex items-center gap-3">
          <a href="/dashboard" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-blue-700 flex items-center justify-center text-white font-bold text-sm shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <span className="font-bold text-sm text-slate-900 tracking-tight">MAILTRACE AI</span>
              <span className="text-[10px] text-blue-700 font-bold ml-1.5 px-1.5 py-0.5 rounded bg-blue-50 border border-blue-200">
                THREAT PLATFORM
              </span>
            </div>
          </a>

          <div className="hidden sm:flex items-center gap-1.5 pl-4 border-l border-slate-200 text-xs">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-amber-400'}`} />
            <span className="text-slate-500 font-mono text-[11px]">
              {wsConnected ? 'Real-Time Ingestion Active' : 'Connecting Engine...'}
            </span>
          </div>
        </div>

        {/* User Profile & Actions */}
        <div className="flex items-center gap-3">
          {/* Notification Permission Prompt if default */}
          {'Notification' in window && Notification.permission === 'default' && (
            <button
              onClick={() => Notification.requestPermission()}
              className="hidden sm:flex items-center gap-1 px-2.5 py-1 rounded bg-blue-50 text-blue-700 border border-blue-200 text-[11px] font-semibold hover:bg-blue-100"
            >
              <Bell className="w-3.5 h-3.5" />
              <span>Enable Notifications</span>
            </button>
          )}

          {user && (
            <div className="flex items-center gap-3 pl-3 border-l border-slate-200">
              <div className="text-right hidden sm:block">
                <div className="text-xs font-semibold text-slate-900 leading-tight">
                  {user.full_name || user.username}
                </div>
                <div className="text-[10px] text-emerald-600 font-mono font-medium">
                  Protected Account
                </div>
              </div>

              <button
                onClick={logout}
                title="Logout"
                className="p-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 text-slate-500 hover:text-slate-900 border border-slate-200 transition-colors"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Live Threat Notification Toast */}
      {liveAlert && (
        <div className="fixed bottom-5 right-5 z-50 max-w-md p-4 rounded-xl bg-red-900 text-white shadow-2xl border border-red-700 space-y-2 animate-bounce">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-red-200">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <span>🚨 {liveAlert.risk_score >= 70 ? 'DANGEROUS: DO NOT OPEN' : 'SUSPICIOUS: OPEN WITH CAUTION'}</span>
            </div>
            <button onClick={() => setLiveAlert(null)} className="text-red-300 hover:text-white text-xs">
              ✕
            </button>
          </div>

          <div className="text-xs font-semibold">{liveAlert.subject}</div>
          <div className="text-[11px] opacity-90 text-red-100">
            From: <span className="font-mono">{liveAlert.sender}</span>
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-red-800">
            <span className="font-mono text-xs font-bold text-amber-300">
              Score: {liveAlert.risk_score}/100 ({liveAlert.risk_score >= 70 ? '🚫 DO NOT OPEN' : '⚠️ BE CAREFUL'})
            </span>
            <a
              href={`/emails/${liveAlert.email_id}`}
              className="px-2.5 py-1 rounded bg-white text-red-900 font-bold text-xs hover:bg-red-50 transition-colors"
            >
              View Analysis →
            </a>
          </div>
        </div>
      )}
    </>
  );
};
