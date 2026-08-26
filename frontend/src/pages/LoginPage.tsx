import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  Shield,
  Lock,
  User,
  Mail,
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  HelpCircle
} from 'lucide-react';
import { api } from '../services/api';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const [isRegister, setIsRegister] = useState(false);
  const [showForgotPassword, setShowForgotPassword] = useState(false);

  // Form State
  const [username, setUsername] = useState(localStorage.getItem('mailtrace_remembered_user') || '');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(!!localStorage.getItem('mailtrace_remembered_user'));

  // Password Visibility
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  // Forgot Password State
  const [resetIdentifier, setResetIdentifier] = useState('');
  const [newResetPassword, setNewResetPassword] = useState('');
  const [resetStep, setResetStep] = useState<'request' | 'set_new'>('request');
  const [resetMessage, setResetMessage] = useState<string | null>(null);
  const [resetError, setResetError] = useState<string | null>(null);

  // Status
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validation
    if (isRegister) {
      if (password !== confirmPassword) {
        setError('Passwords do not match.');
        return;
      }
      if (password.length < 6) {
        setError('Password must be at least 6 characters long.');
        return;
      }
    }

    setLoading(true);

    try {
      if (isRegister) {
        // Register new user
        await api.post('/auth/register', {
          username: username.trim(),
          email: email.trim(),
          full_name: fullName.trim(),
          password,
          role: 'USER'
        });
        setSuccess('Account created successfully! Signing you in...');
      }

      // Remember me handling
      if (rememberMe) {
        localStorage.setItem('mailtrace_remembered_user', username.trim());
      } else {
        localStorage.removeItem('mailtrace_remembered_user');
      }

      // Login
      const res = await api.post('/auth/login', { username: username.trim(), password });
      login(res.data.access_token, {
        id: res.data.user_id,
        username: res.data.username,
        role: res.data.role,
        full_name: res.data.full_name || username,
        email: email || `${username}@mailtrace.ai`,
        is_active: true,
        created_at: new Date().toISOString()
      });
      window.location.href = '/dashboard';
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setResetError(null);
    setResetMessage(null);
    setLoading(true);

    try {
      if (resetStep === 'request') {
        const res = await api.post('/auth/forgot-password', {
          email_or_username: resetIdentifier.trim()
        });
        setResetMessage(res.data.message);
        setResetStep('set_new');
      } else {
        const res = await api.post('/auth/reset-password', {
          email_or_username: resetIdentifier.trim(),
          new_password: newResetPassword
        });
        setResetMessage(res.data.message);
        setTimeout(() => {
          setShowForgotPassword(false);
          setResetStep('request');
          setResetMessage(null);
        }, 2000);
      }
    } catch (err: any) {
      setResetError(err.response?.data?.detail || 'Password reset request failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-[#f8fafc] font-sans">
      <div className="w-full max-w-md p-8 rounded-2xl bg-white border border-slate-300 shadow-sm space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 mx-auto rounded-xl bg-blue-700 flex items-center justify-center shadow-xs text-white">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900">
            MAILTRACE<span className="text-blue-700">.AI</span>
          </h1>
          <p className="text-xs text-slate-500 font-medium">
            AI Email Threat Detection & Real-Time Security
          </p>
        </div>

        {/* Tab Toggle: Sign In vs Sign Up */}
        <div className="flex rounded-lg bg-slate-100 p-1 text-xs font-semibold">
          <button
            type="button"
            onClick={() => { setIsRegister(false); setError(''); setSuccess(''); }}
            className={`flex-1 py-1.5 rounded-md transition-all ${!isRegister ? 'bg-white text-slate-900 shadow-xs font-bold' : 'text-slate-500 hover:text-slate-900'}`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setIsRegister(true); setError(''); setSuccess(''); }}
            className={`flex-1 py-1.5 rounded-md transition-all ${isRegister ? 'bg-white text-slate-900 shadow-xs font-bold' : 'text-slate-500 hover:text-slate-900'}`}
          >
            Create Account
          </button>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs flex items-center gap-2 font-mono">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{success}</span>
          </div>
        )}

        {/* Main Authentication Form */}
        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div className="space-y-1">
            <label className="text-xs font-semibold text-slate-700">Username</label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-50 border border-slate-300 focus:border-blue-700 focus:outline-none text-xs text-slate-900 font-mono"
              />
            </div>
          </div>

          {isRegister && (
            <>
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-700">Full Name</label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Full name"
                  className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-300 focus:border-blue-700 focus:outline-none text-xs text-slate-900"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-700">Email Address</label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@domain.com"
                    className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-50 border border-slate-300 focus:border-blue-700 focus:outline-none text-xs text-slate-900 font-mono"
                  />
                </div>
              </div>
            </>
          )}

          {/* Password Field with Show/Hide Toggle */}
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-700">Password</label>
              {!isRegister && (
                <button
                  type="button"
                  onClick={() => { setShowForgotPassword(true); setResetError(null); setResetMessage(null); }}
                  className="text-[11px] text-blue-700 hover:underline font-semibold"
                >
                  Forgot password?
                </button>
              )}
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-10 py-2 rounded-lg bg-slate-50 border border-slate-300 focus:border-blue-700 focus:outline-none text-xs text-slate-900 font-mono"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600"
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Confirm Password Field (Only on Register) */}
          {isRegister && (
            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-700">Confirm Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter password"
                  className="w-full pl-9 pr-10 py-2 rounded-lg bg-slate-50 border border-slate-300 focus:border-blue-700 focus:outline-none text-xs text-slate-900 font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600"
                  title={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
          )}

          {/* Remember Me Checkbox */}
          {!isRegister && (
            <div className="flex items-center gap-2 pt-1">
              <input
                type="checkbox"
                id="rememberMe"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="w-3.5 h-3.5 rounded border-slate-300 text-blue-700 focus:ring-blue-500"
              />
              <label htmlFor="rememberMe" className="text-xs text-slate-600 cursor-pointer">
                Remember username
              </label>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 mt-2 rounded-lg bg-blue-700 hover:bg-blue-800 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-xs flex items-center justify-center gap-2"
          >
            <span>{loading ? 'Processing...' : isRegister ? 'Create Account' : 'Sign In'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>
      </div>

      {/* Forgot Password Modal */}
      {showForgotPassword && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="w-full max-w-sm bg-white rounded-xl border border-slate-200 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-900 font-bold text-sm">
                <KeyRound className="w-4 h-4 text-blue-700" />
                <span>Reset Password</span>
              </div>
              <button
                onClick={() => setShowForgotPassword(false)}
                className="text-slate-400 hover:text-slate-700 text-xs font-bold"
              >
                ✕
              </button>
            </div>

            {resetError && (
              <div className="p-2.5 rounded bg-red-50 border border-red-200 text-red-700 text-xs font-mono">
                {resetError}
              </div>
            )}

            {resetMessage && (
              <div className="p-2.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-mono">
                {resetMessage}
              </div>
            )}

            <form onSubmit={handleForgotPasswordSubmit} className="space-y-3">
              {resetStep === 'request' ? (
                <div>
                  <label className="text-xs font-semibold text-slate-700">Account Username or Email</label>
                  <input
                    type="text"
                    required
                    value={resetIdentifier}
                    onChange={(e) => setResetIdentifier(e.target.value)}
                    placeholder="Username or email"
                    className="w-full mt-1 px-3 py-2 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono"
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Enter your username or registered email to verify identity.
                  </p>
                </div>
              ) : (
                <div>
                  <label className="text-xs font-semibold text-slate-700">New Password</label>
                  <input
                    type="password"
                    required
                    value={newResetPassword}
                    onChange={(e) => setNewResetPassword(e.target.value)}
                    placeholder="Enter new password (min 6 characters)"
                    className="w-full mt-1 px-3 py-2 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono"
                  />
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowForgotPassword(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 text-slate-600 text-xs hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-800 text-white font-semibold text-xs"
                >
                  {loading ? 'Processing...' : resetStep === 'request' ? 'Next →' : 'Update Password'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
