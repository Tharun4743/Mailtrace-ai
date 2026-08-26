import React, { useEffect, useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';

// 5 Core Workflow Pages
import { DashboardPage } from './pages/DashboardPage';
import { EmailsPage } from './pages/EmailsPage';
import { InvestigationDetailPage } from './pages/InvestigationDetailPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { SettingsPage } from './pages/SettingsPage';
import { LoginPage } from './pages/LoginPage';

function AppContent() {
  const { user, loading } = useAuth();
  const [currentPath, setCurrentPath] = useState<string>(window.location.pathname);

  useEffect(() => {
    const handleLocationChange = () => {
      setCurrentPath(window.location.pathname);
    };
    window.addEventListener('popstate', handleLocationChange);
    return () => window.removeEventListener('popstate', handleLocationChange);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#f8fafc] text-slate-500 font-mono text-xs">
        Initializing MailTrace Platform...
      </div>
    );
  }

  // Allow login page access if unauthenticated
  if (!user && currentPath !== '/login') {
    window.location.href = '/login';
    return null;
  }

  if (currentPath === '/login') {
    return <LoginPage />;
  }

  const renderRoute = () => {
    if (currentPath === '/' || currentPath === '/dashboard') {
      return <DashboardPage />;
    }
    if (currentPath === '/emails') {
      return <EmailsPage />;
    }
    if (currentPath.startsWith('/emails/')) {
      const emailId = currentPath.split('/')[2];
      return <InvestigationDetailPage emailId={emailId} />;
    }
    if (currentPath === '/threats') {
      return <ThreatsPage />;
    }
    if (currentPath === '/analytics') {
      return <AnalyticsPage />;
    }
    if (currentPath === '/settings' || currentPath === '/accounts' || currentPath.startsWith('/auth/')) {
      return <SettingsPage />;
    }

    // Default fallback
    return <DashboardPage />;
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#f8fafc]">
      <Navbar />
      <div className="flex flex-1">
        <Sidebar currentPath={currentPath} />
        <main className="flex-1 overflow-y-auto bg-[#f8fafc]">
          {renderRoute()}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
