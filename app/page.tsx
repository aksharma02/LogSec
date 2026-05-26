'use client';

import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { useRouter } from 'next/navigation';
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui';
import { Shield, Upload, FileText, CheckCircle2, AlertTriangle } from 'lucide-react';

import { useSession } from 'next-auth/react';

/**
 * Sniffs the format based on file naming patterns or header strings.
 */
function sniffFormat(fileName: string, firstLine: string): 'syslog' | 'apache' | 'cloudtrail' | 'generic' {
  const nameLower = fileName.toLowerCase();
  if (nameLower.endsWith('.json') || firstLine.startsWith('{') || firstLine.includes('"Events":')) {
    return 'cloudtrail';
  }
  if (firstLine.match(/^<\d+>/) || firstLine.includes('syslog') || firstLine.includes('sshd[')) {
    return 'syslog';
  }
  if (firstLine.includes('GET ') || firstLine.includes('POST ') || firstLine.includes('HTTP/1.')) {
    return 'apache';
  }
  return 'generic';
}

export default function IngestionLandingPage() {
  const router = useRouter();
  const { data: sessionData, status } = useSession();
  const [file, setFile] = useState<File | null>(null);
  const [sessionName, setSessionName] = useState('');
  const [detectedFormat, setDetectedFormat] = useState<'syslog' | 'apache' | 'cloudtrail' | 'generic'>('generic');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Authenticated operators enforcement check
  React.useEffect(() => {
    if (status === 'unauthenticated') {
      router.push('/api/auth/signin');
    }
  }, [status, router]);

  // File Drop handler
  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;

    const selectedFile = acceptedFiles[0];
    setFile(selectedFile);
    
    // Set default session name based on file name without extension
    const baseName = selectedFile.name.replace(/\.[^/.]+$/, '');
    setSessionName(baseName.replace(/[-_]/g, ' ') + ' Analysis');

    // Read the first line of the file to auto-sniff the format
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      const firstLine = text.split('\n')[0] || '';
      const sniffed = sniffFormat(selectedFile.name, firstLine);
      setDetectedFormat(sniffed);
    };
    // Read only a small chunk for high performance
    reader.readAsText(selectedFile.slice(0, 1024));
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxFiles: 1,
    accept: {
      'text/plain': ['.log', '.txt'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
    },
  });

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-[#0f172a] text-slate-100 flex flex-col justify-center items-center font-mono text-xs uppercase tracking-widest space-y-4">
        <div className="h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <span className="animate-pulse">VERIFYING OPERATOR ACCESS CREDENTIALS...</span>
      </div>
    );
  }

  // Upload and process handler
  const handleAnalyze = async () => {
    if (!file || !sessionName) return;
    setLoading(true);
    setError(null);

    try {
      // Step 1: Create session
      const sessionRes = await fetch('/api/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: sessionName,
          logSource: detectedFormat,
        }),
      });

      if (!sessionRes.ok) {
        throw new Error('Failed to create a security analysis session.');
      }

      const session = await sessionRes.json();
      const sessionId = session.id;

      // Step 2: Upload file and trigger BullMQ
      const formData = new FormData();
      formData.append('file', file);
      formData.append('sessionId', sessionId);

      const uploadRes = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!uploadRes.ok) {
        throw new Error('Failed to upload raw logs file.');
      }

      const uploadData = await uploadRes.json();
      const jobId = uploadData.jobId;

      // Redirect directly to the dynamic session dashboard, carrying the background jobId for processing tabs
      router.push(`/sessions/${sessionId}?jobId=${jobId}`);
    } catch (err: any) {
      console.error('Fatal upload error:', err);
      setError(err.message || 'Ingestion pipeline failed.');
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-[#0f172a] text-slate-100 flex flex-col justify-center items-center p-4 sm:p-8">
      {/* Background radial ambient styling */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(6,182,212,0.06),transparent_60%)] pointer-events-none" />

      <div className="w-full max-w-2xl relative space-y-8 z-10">
        
        {/* Header Branding */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center p-3 bg-cyan-500/10 rounded-xl border border-cyan-500/25 mb-2 glow-cyan">
            <Shield className="h-10 w-10 text-cyan-400" />
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white font-mono">
            AI SEC <span className="text-cyan-400">ANALYZER</span>
          </h1>
          <p className="text-slate-400 text-sm sm:text-base max-w-md mx-auto">
            Decentralized log ingestion and real-time semantic compromise scanner.
          </p>
        </div>

        {/* Upload Container */}
        <Card className="border-slate-800/80 bg-slate-900/50 backdrop-blur-xl shadow-2xl">
          <CardHeader>
            <CardTitle className="font-mono text-base tracking-wider text-cyan-400 uppercase">
              Ingest Logs File
            </CardTitle>
            <CardDescription className="text-slate-400 text-xs">
              Upload Linux Syslog, Apache Access Logs, or AWS CloudTrail logs below.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            
            {/* Drag & Drop Area */}
            <div
              {...getRootProps()}
              className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all duration-350 ${
                isDragActive
                  ? 'border-cyan-500 bg-cyan-500/5 shadow-[0_0_15px_rgba(6,182,212,0.1)]'
                  : file
                  ? 'border-cyan-500/40 bg-slate-900/80'
                  : 'border-slate-800 hover:border-slate-700 bg-slate-950/20'
              }`}
            >
              <input {...getInputProps()} />
              <div className="flex flex-col items-center space-y-3">
                <div className={`p-3 rounded-full ${file ? 'bg-cyan-500/15' : 'bg-slate-800'} transition-colors`}>
                  {file ? (
                    <FileText className="h-8 w-8 text-cyan-400" />
                  ) : (
                    <Upload className="h-8 w-8 text-slate-400" />
                  )}
                </div>
                {file ? (
                  <div className="space-y-1">
                    <p className="text-sm font-mono text-cyan-300 font-semibold">{file.name}</p>
                    <p className="text-xs text-slate-500">
                      {(file.size / 1024).toFixed(2)} KB • Sniffed: <span className="text-cyan-400 uppercase font-bold">{detectedFormat}</span>
                    </p>
                  </div>
                ) : (
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-slate-300">
                      {isDragActive ? 'Drop your logs file here...' : 'Drag & drop log files here'}
                    </p>
                    <p className="text-xs text-slate-500">
                      Supports .log, .txt, .json, .csv (Max 1 file)
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Ingestion Fields */}
            {file && (
              <div className="space-y-4 animate-fadeIn">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-slate-400 uppercase font-mono tracking-wider">
                      Analysis Session Name
                    </label>
                    <input
                      type="text"
                      value={sessionName}
                      onChange={(e) => setSessionName(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                      placeholder="Operator logs audit"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-slate-400 uppercase font-mono tracking-wider">
                      Format Parser overrides
                    </label>
                    <select
                      value={detectedFormat}
                      onChange={(e) => setDetectedFormat(e.target.value as any)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                    >
                      <option value="syslog">Syslog (RFC 5424/BSD)</option>
                      <option value="apache">Apache/Nginx Combined</option>
                      <option value="cloudtrail">AWS CloudTrail JSON</option>
                      <option value="generic">Generic Fallback (key=value)</option>
                    </select>
                  </div>
                </div>

                {/* Error Banner */}
                {error && (
                  <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-md font-mono flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    <span>{error}</span>
                  </div>
                )}

                {/* Trigger Button */}
                <Button
                  onClick={handleAnalyze}
                  loading={loading}
                  className="w-full glow-cyan"
                  size="lg"
                >
                  <CheckCircle2 className="h-4 w-4 mr-2" />
                  INITIATE SEC-SCAN PIPELINE
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Footer Terminal Indicators */}
        <div className="text-center text-xs font-mono text-slate-600 flex justify-center items-center gap-4">
          <span>● ENGINE ACTIVE</span>
          <span>● PGVECTOR READY</span>
          <span>● BULLMQ RUNNING</span>
        </div>
      </div>
    </main>
  );
}
