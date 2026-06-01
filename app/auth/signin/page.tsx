'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { signIn, useSession } from 'next-auth/react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Shield, Lock, Mail, AlertTriangle, UserPlus, KeyRound } from 'lucide-react';

function SignInForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { status } = useSession();
  
  // Retrieve NextAuth parameters
  const callbackUrl = searchParams.get('callbackUrl') || '/';
  const errorParam = searchParams.get('error');

  // Fast-track redirect if already authenticated
  useEffect(() => {
    if (status === 'authenticated') {
      window.location.href = callbackUrl;
    }
  }, [status, callbackUrl]);

  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load stored credentials on mount
  useEffect(() => {
    if (errorParam) {
      if (errorParam === 'CredentialsSignin') {
        setError('Invalid operator email or security password.');
      } else if (errorParam.includes('AccountAlreadyExists')) {
        setError('An operator account already exists with this email. Please sign in instead.');
        setIsSignUp(false);
      } else if (errorParam.includes('AccountDoesNotExist')) {
        setError('This operator account does not exist. Please sign up to register.');
        setIsSignUp(true);
      } else if (errorParam.includes('IncorrectPassword')) {
        setError('Incorrect security password for this operator account.');
        setIsSignUp(false);
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

    // Password match check in Sign Up mode
    if (isSignUp && password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const normalizedEmail = email.toLowerCase().trim();
      const isDevAdmin = normalizedEmail === 'admin@sec.company';

      // 1. Perform pre-flight account existence check
      let exists = false;
      if (isDevAdmin) {
        exists = true;
      } else {
        try {
          const checkRes = await fetch('/api/auth/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: normalizedEmail }),
          });

          if (!checkRes.ok) {
            throw new Error('PreFlightFailed');
          }

          const data = await checkRes.json();
          exists = !!data.exists;
        } catch (dbErr) {
          console.warn('Pre-flight check query error (falling back to standard NextAuth callback):', dbErr);
          // If the DB check fails, we fall back to standard NextAuth to avoid blocking logins
          exists = true;
        }
      }

      // Dynamic toggle feedback based on exist state
      if (isSignUp && exists) {
        setError('An operator account already exists with this email. Please sign in instead.');
        setIsSignUp(false);
        setLoading(false);
        return;
      }

      if (!isSignUp && !exists) {
        setError('This operator account does not exist. Please sign up to create a password.');
        setIsSignUp(true);
        setLoading(false);
        return;
      }

      // Store credentials if "Remember Me" is active (and not signing up)
      if (rememberMe && !isSignUp) {
        localStorage.setItem('logsec_saved_email', email);
        localStorage.setItem('logsec_saved_password', password);
        localStorage.setItem('logsec_remember_me', 'true');
      } else if (!isSignUp) {
        localStorage.removeItem('logsec_saved_email');
        localStorage.removeItem('logsec_saved_password');
        localStorage.setItem('logsec_remember_me', 'false');
      }

      // 2. Submit to NextAuth Provider
      const res = await signIn('credentials', {
        email: normalizedEmail,
        password,
        isSignUp: isSignUp ? 'true' : 'false',
        redirect: false,
        callbackUrl,
      });

      if (res?.error) {
        setError('Incorrect security password for this operator account.');
        setLoading(false);
      } else {
        // Perform a hard reload/navigation to callbackUrl to force cookie synchronization
        window.location.href = callbackUrl;
      }
    } catch (err: any) {
      console.error('Login submit crash:', err);
      setError('Connection refused or database migration timeout.');
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md relative z-10 space-y-6">
      
      {/* Branding header */}
      <div className="text-center space-y-2 animate-fadeIn">
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
          {isSignUp ? 'Operator Registration' : 'Operator Access Portal'}
        </p>
      </div>

      {/* Form Container */}
      <div className="bg-slate-900/55 backdrop-blur-xl border border-slate-800/80 rounded-xl p-6 sm:p-8 shadow-2xl space-y-6">
        
        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-md font-mono flex items-start gap-2 animate-fadeIn">
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          
          {/* Operator Email */}
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-mono">
              Operator Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-md pl-10 pr-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-red-500/80 font-mono placeholder:text-slate-700"
                placeholder="analyst@company.com"
                required
              />
            </div>
          </div>

          {/* Security Password */}
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

          {/* Confirm Password (only shown in Sign Up mode) */}
          {isSignUp && (
            <div className="space-y-1.5 animate-fadeIn">
              <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-mono">
                Confirm Security Password
              </label>
              <div className="relative">
                <KeyRound className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-md pl-10 pr-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-red-500/80 font-mono placeholder:text-slate-700"
                  placeholder="••••••••"
                  required={isSignUp}
                />
              </div>
            </div>
          )}

          {/* Remember Me Checkbox (only shown in Sign In mode) */}
          {!isSignUp && (
            <div className="flex items-center justify-between pt-1 animate-fadeIn">
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
          )}

          {/* Submit Action Button */}
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
                PROCESSING...
              </>
            ) : isSignUp ? (
              <>
                <UserPlus className="h-4 w-4" />
                Create Account & Sign In
              </>
            ) : (
              <>
                <Shield className="h-4 w-4" />
                Sign In with Operator Portal
              </>
            )}
          </button>
        </form>

        {/* Dynamic Mode Switcher */}
        <div className="text-center pt-2 border-t border-slate-800/80">
          <button
            onClick={() => {
              setIsSignUp(!isSignUp);
              setError(null);
            }}
            className="text-xs font-mono text-slate-400 hover:text-red-400 transition-colors"
          >
            {isSignUp 
              ? 'Already have an operator account? Sign in here' 
              : "Don't have an operator account? Sign up / Create password"
            }
          </button>
        </div>

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
