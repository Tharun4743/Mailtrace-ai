import React from 'react';
import {
  LayoutDashboard,
  Inbox,
  Flame,
  BarChart3,
  Bell,
  Settings,
  Shield
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface SidebarProps {
  currentPath: string;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentPath }) => {
  const { user } = useAuth();
  const isSecurityStaff = user?.role === 'ADMIN' || user?.role === 'ANALYST';

  // Navigation tailored to User vs Security Team
  const userNav = [
    { label: 'Overview', path: '/dashboard', icon: LayoutDashboard },
    { label: 'Inbox', path: '/emails', icon: Inbox },
    { label: 'Threats', path: '/threats', icon: Flame },
    { label: 'Analytics', path: '/analytics', icon: BarChart3 },
  ];

  return (
    <aside className="w-56 border-r border-slate-200 bg-white flex flex-col justify-between shrink-0 select-none sticky top-16 h-[calc(100vh-4rem)] font-sans">
      <div className="p-3 space-y-4">
        {/* Brand Header */}
        <div className="px-3 py-1 flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-900 font-bold text-sm">
            <Shield className="w-4 h-4 text-blue-700" />
            <span>MAILTRACE AI</span>
          </div>
        </div>

        {/* Core Navigation Items */}
        <div className="space-y-1">
          {userNav.map((item) => {
            const Icon = item.icon;
            const isActive = currentPath === item.path || (item.path === '/emails' && currentPath.startsWith('/emails'));

            return (
              <a
                key={item.path}
                href={item.path}
                className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-semibold transition-colors ${
                  isActive
                    ? 'bg-blue-50 text-blue-700 font-bold border border-blue-200'
                    : 'text-slate-700 hover:text-slate-900 hover:bg-slate-50'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-700' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </a>
            );
          })}
        </div>

        {/* Settings & Mailbox Connection */}
        <div className="border-t border-slate-100 pt-3 space-y-1">
          <a
            href="/settings"
            className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-semibold transition-colors ${
              currentPath === '/settings' || currentPath === '/accounts'
                ? 'bg-blue-50 text-blue-700 font-bold border border-blue-200'
                : 'text-slate-700 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Settings className="w-4 h-4 text-slate-400" />
            <span>Settings</span>
          </a>
        </div>
      </div>

      {/* Live Protection Status */}
      <div className="p-3 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between font-mono">
        <span className="flex items-center gap-1.5 text-emerald-700 font-bold text-[11px]">
          <span className="w-2 h-2 rounded-full bg-emerald-600 animate-pulse" />
          PROTECTION ON
        </span>
        <span className="text-[11px] text-slate-400">v2.0</span>
      </div>
    </aside>
  );
};
