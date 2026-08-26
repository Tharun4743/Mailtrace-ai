import React, { useEffect, useState } from 'react';
import { Search, RefreshCw, UploadCloud, X, Send, Plus } from 'lucide-react';
import { EmailListItem } from '../types';
import { api } from '../services/api';

export const EmailsPage: React.FC = () => {
  const [emails, setEmails] = useState<EmailListItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');

  // Analyze Modal
  const [showAnalyzeModal, setShowAnalyzeModal] = useState<boolean>(false);
  const [testSender, setTestSender] = useState<string>('support@paypa1-security.com');
  const [testSubject, setTestSubject] = useState<string>('URGENT: Your account will be suspended');
  const [testBody, setTestBody] = useState<string>('Dear Customer, unusual activity detected. Click here immediately to verify your account: https://paypa1-security.xyz/login');
  const [testUrls, setTestUrls] = useState<string>('https://paypa1-security.xyz/login');
  const [analyzing, setAnalyzing] = useState<boolean>(false);

  // File Upload
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);

  const fetchEmails = async () => {
    setLoading(true);
    try {
      let url = '/emails?limit=100';
      if (search) url += `&search=${encodeURIComponent(search)}`;
      const res = await api.get(url);
      setEmails(res.data);
    } catch (err) {
      console.error('Failed to load inbox emails:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEmails();
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchEmails();
  };

  const handleAnalyzeDirect = async (e: React.FormEvent) => {
    e.preventDefault();
    setAnalyzing(true);
    try {
      const urlsArray = testUrls.split(',').map(u => u.trim()).filter(Boolean);
      const res = await api.post('/emails/analyze', {
        sender: testSender,
        subject: testSubject,
        body: testBody,
        urls: urlsArray
      });
      window.location.href = `/emails/${res.data.email_id}`;
    } catch (err) {
      console.error('Analysis failed:', err);
      setAnalyzing(false);
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadFile) return;
    setUploading(true);
    const formData = new FormData();
    formData.append('file', uploadFile);
    try {
      const res = await api.post('/emails/upload-eml', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      window.location.href = `/emails/${res.data.id}`;
    } catch (err) {
      console.error('Upload failed:', err);
      setUploading(false);
    }
  };

  const getRiskIndicator = (score: number) => {
    if (score >= 70) {
      return { dot: '🔴', text: 'text-red-700', bg: 'bg-red-50', border: 'border-red-200' };
    } else if (score >= 30) {
      return { dot: '🟠', text: 'text-amber-700', bg: 'bg-amber-50', border: 'border-amber-200' };
    } else {
      return { dot: '🟢', text: 'text-emerald-700', bg: 'bg-emerald-50', border: 'border-emerald-200' };
    }
  };

  return (
    <div className="p-6 space-y-5 max-w-5xl mx-auto font-sans">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-lg cyber-card bg-white">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Inbox</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Analyzed email threat stream with instant risk indicators
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAnalyzeModal(true)}
            className="px-3.5 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Analyze Custom Email</span>
          </button>
        </div>
      </div>

      {/* Direct Analyze Modal */}
      {showAnalyzeModal && (
        <div className="p-5 rounded-lg bg-white border border-blue-300 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-2">
            <h2 className="text-sm font-bold text-slate-900">Direct Real-Time Email Threat Analysis</h2>
            <button onClick={() => setShowAnalyzeModal(false)} className="text-slate-400 hover:text-slate-700">
              <X className="w-4 h-4" />
            </button>
          </div>

          <form onSubmit={handleAnalyzeDirect} className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-semibold text-slate-700">Sender Email</label>
                <input
                  type="text"
                  required
                  value={testSender}
                  onChange={(e) => setTestSender(e.target.value)}
                  className="w-full mt-1 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 text-xs font-mono"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-700">Subject</label>
                <input
                  type="text"
                  required
                  value={testSubject}
                  onChange={(e) => setTestSubject(e.target.value)}
                  className="w-full mt-1 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 text-xs"
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-700">Message Body</label>
              <textarea
                rows={3}
                required
                value={testBody}
                onChange={(e) => setTestBody(e.target.value)}
                className="w-full mt-1 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 text-xs"
              />
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-700">Embedded URLs (comma separated)</label>
              <input
                type="text"
                value={testUrls}
                onChange={(e) => setTestUrls(e.target.value)}
                className="w-full mt-1 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 text-xs font-mono"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowAnalyzeModal(false)}
                className="px-3 py-1.5 rounded bg-slate-100 text-slate-600 text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={analyzing}
                className="px-4 py-1.5 rounded bg-blue-700 text-white text-xs font-semibold"
              >
                {analyzing ? 'Analyzing Threat Signals...' : 'Execute Threat Analysis'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Search & Actions */}
      <div className="p-3 rounded-lg cyber-card bg-white flex flex-col sm:flex-row items-center justify-between gap-3">
        <form onSubmit={handleSearch} className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search email by sender, subject..."
            className="w-full pl-9 pr-4 py-1.5 rounded bg-slate-50 border border-slate-200 text-xs font-mono"
          />
        </form>

        <button
          onClick={fetchEmails}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold hover:bg-slate-100"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Clean Email List with Quick Risk Indicators */}
      <div className="rounded-lg border border-slate-200 bg-white overflow-hidden shadow-xs">
        <div className="p-3 border-b border-slate-100 text-[11px] font-bold text-slate-400 uppercase tracking-wider flex justify-between">
          <span>Email Message & Sender</span>
          <span>Risk Score</span>
        </div>

        <div className="divide-y divide-slate-100">
          {loading ? (
            <div className="p-12 text-center text-slate-400 text-xs font-mono">
              Loading inbox stream...
            </div>
          ) : emails.length > 0 ? (
            emails.map((email) => {
              const risk = getRiskIndicator(email.risk_score);
              return (
                <a
                  key={email.id}
                  href={`/emails/${email.id}`}
                  className="p-3.5 flex items-center justify-between hover:bg-slate-50 transition-colors group"
                >
                  <div className="min-w-0 pr-4">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-900 text-xs group-hover:text-blue-700 transition-colors">
                        {email.sender_display_name || email.sender_email}
                      </span>
                      <span className="text-slate-400 text-xs">—</span>
                      <span className="text-slate-600 text-xs truncate">
                        {email.subject || '(No Subject)'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                      {email.sender_email}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="font-mono font-bold text-xs text-slate-900">
                      {String(email.risk_score).padStart(2, '0')}
                    </span>
                    <span>{risk.dot}</span>
                  </div>
                </a>
              );
            })
          ) : (
            <div className="p-12 text-center text-slate-400 text-xs">
              No emails in inbox. Click "Analyze Custom Email" above or connect a mailbox.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
