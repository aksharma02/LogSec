'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { signIn } from 'next-auth/react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Shield, Lock, Mail, AlertTriangle } from 'lucide-react';

function SignInForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  
  // Retrieve NextAuth parameters
  const callbackUrl = searchParams.get('callbackUrl') || '/';
  const errorParam = searchParams.get('error');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load stored credentials on mount
  useEffect(() => {
    if (errorParam) {
      if (errorParam === 'CredentialsSignin') {
        setError('Invalid operator email or security password.');
      } else {
        setError('An authentication error occurred. Please try again.');
      }
    }

    try {
      const savedEmail = localStorage.getItem('logsec_saved_email');
      const savedPassword = localStorage.getItem('logsec_saved_password');
      const savedRemember = localStorage.getItem('logsec_remember_me');

      if (savedEmail) setEmail(savedEmail);
      if (savedPassword) setPassword(savedPassword);
      if (savedRemember !== null) {
        setRememberMe(savedRemember === 'true');
      }
    } catch (e) {
      console.warn('Failed to read credentials from localStorage:', e);
    }
  }, [errorParam]);

  // Handle credentials form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please fill in all authorization fields.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Store credentials if "Remember Me" is active
      if (rememberMe) {
        localStorage.setItem('logsec_saved_email', email);
        localStorage.setItem('logsec_saved_password', password);
        localStorage.setItem('logsec_remember_me', 'true');
      } else {
        localStorage.removeItem('logsec_saved_email');
        localStorage.removeItem('logsec_saved_password');
        localStorage.setItem('logsec_remember_me', 'false');
      }

      const res = await signIn('credentials', {
        email,
        password,
        redirect: false,
        callbackUrl,
      });

      if (res?.error) {
        setError('Invalid operator email or security password.');
        setLoading(false);
      } else {
        router.push(callbackUrl);
      }
    } catch (err) {
      console.error('Login submit crash:', err);
      setError('Connection refused or authentication timeout.');
      setLoading(false);
    }
  };

  // Handle Google OAuth trigger
  const handleGoogleSignIn = async () => {
    setGoogleLoading(true);
    setError(null);
    try {
      await signIn('google', { callbackUrl });
    } catch (err) {
      console.error('Google Sign-in failed:', err);
      setError('Google Authentication services are currently unconfigured.');
      setGoogleLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md relative z-10 space-y-6">
      
      {/* Branding header */}
      <div className="text-center space-y-2">
        <div className="flex flex-col items-center justify-center space-y-1 mb-2">
          <img 
            src="/logo.png" 
            alt="LogSec Logo" 
            className="h-14 w-auto object-contain glow-red rounded-lg p-1 bg-slate-900/50 border border-slate-800/80" 
          />
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white font-mono">
          Log<span className="text-red-400">Sec</span>
        </h1>
        <p className="text-slate-400 text-xs sm:text-sm uppercase tracking-wider font-mono">
          Operator Access Portal
        </p>
      </div>

      {/* Credentials Form */}
      <div className="bg-slate-900/55 backdrop-blur-xl border border-slate-800/80 rounded-xl p-6 sm:p-8 shadow-2xl space-y-6">
        
        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-md font-mono flex items-start gap-2 animate-fadeIn">
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-mono">
              Operator Email
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-md pl-10 pr-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-red-500/80 font-mono placeholder:text-slate-700"
                placeholder="operator@company.com"
                required
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-mono">
              Security Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-md pl-10 pr-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-red-500/80 font-mono placeholder:text-slate-700"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          {/* Remember Me Checkbox */}
          <div className="flex items-center justify-between pt-1">
            <label className="flex items-center space-x-2 cursor-pointer group">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="rounded border-slate-800 text-red-500 focus:ring-red-500/50 bg-slate-950 h-4 w-4 cursor-pointer"
              />
              <span className="text-xs text-slate-400 group-hover:text-slate-300 font-mono transition-colors">
                Remember my credentials
              </span>
            </label>
          </div>

          {/* Submit Credentials */}
          <button
            type="submit"
            disabled={loading}
            className={`w-full font-mono text-xs uppercase tracking-widest bg-red-600 hover:bg-red-500 active:bg-red-700 text-white rounded-md py-2.5 font-bold transition-all duration-200 shadow-lg shadow-red-950/20 glow-red border border-red-500/30 flex items-center justify-center gap-2 ${
              loading ? 'opacity-70 cursor-not-allowed' : ''
            }`}
          >
            {loading ? (
              <>
                <div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                AUTHENTICATING...
              </>
            ) : (
              <>
                <Shield className="h-4 w-4" />
                Sign In with Operator Portal
              </>
            )}
          </button>
        </form>

        {/* OR Divider */}
        <div className="relative flex py-2 items-center">
          <div className="flex-grow border-t border-slate-800/80"></div>
          <span className="flex-shrink mx-4 text-[10px] text-slate-500 font-mono uppercase tracking-wider">or</span>
          <div className="flex-grow border-t border-slate-800/80"></div>
        </div>

        {/* Google SSO Button */}
        <button
          onClick={handleGoogleSignIn}
          disabled={googleLoading}
          className={`w-full font-mono text-xs uppercase tracking-widest bg-slate-950 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 rounded-md py-2.5 font-bold transition-all duration-200 flex items-center justify-center gap-2 ${
            googleLoading ? 'opacity-70 cursor-not-allowed' : ''
          }`}
        >
          {googleLoading ? (
            <div className="h-4 w-4 border-2 border-slate-300 border-t-transparent rounded-full animate-spin" />
          ) : (
            <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="currentColor">
              <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
              <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
              <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" fill="#FBBC05"/>
              <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
            </svg>
          )}
          Sign In with Google SSO
        </button>

      </div>

      {/* Informative Help Footer */}
      <p className="text-center text-[10px] font-mono text-slate-600">
        SECURE CONNECTION ENFORCED • LOGSEC PLATFORM V0.1.0
      </p>
    </div>
  );
}

export default function CustomSignIn() {
  return (
    <main className="min-h-screen text-slate-100 flex flex-col justify-center items-center p-4 sm:p-8 relative bg-slate-950">
      {/* Background ambient grid design */}
      <div 
        className="absolute inset-0 bg-cover bg-center bg-no-repeat pointer-events-none z-0" 
        style={{ backgroundImage: "url('/securityLog.jpg')", opacity: 0.15 }}
      />
      <div className="absolute inset-0 bg-gradient-to-b from-slate-950/40 to-slate-950/80 pointer-events-none z-0" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(239,68,68,0.06),transparent_60%)] pointer-events-none z-0" />

      <Suspense fallback={
        <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center font-mono text-xs uppercase tracking-widest space-y-4">
          <div className="h-8 w-8 border-4 border-red-500 border-t-transparent rounded-full animate-spin" />
          <span className="animate-pulse">LOADING SECURITY GATEWAY...</span>
        </div>
      }>
        <SignInForm />
      </Suspense>
    </main>
  );
}
