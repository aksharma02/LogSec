'use client';

import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, Progress } from './ui';
import { Shield, RefreshCw } from 'lucide-react';

interface JobProgressProps {
  jobId: string;
  onComplete: () => void;
}

/**
 * JobProgress listens to background BullMQ SSE status streams,
 * rendering rich security stage notifications and smooth progress transitions.
 */
export default function JobProgress({ jobId, onComplete }: JobProgressProps) {
  const [progress, setProgress] = useState(0);
  const [step, setStep] = useState('queued');
  const [parsedCount, setParsedCount] = useState(0);
  const [embeddedCount, setEmbeddedCount] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!jobId) return;

    console.log(`Establishing EventSource listener for Job #${jobId}...`);
    const eventSource = new EventSource(`/api/jobs/${jobId}/stream`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setProgress(data.progress || 0);
        setStep(data.step || 'processing');
        setParsedCount(data.parsedCount || 0);
        setEmbeddedCount(data.embeddedCount || 0);

        if (data.status === 'completed') {
          console.log(`Ingestion Job #${jobId} completed successfully!`);
          eventSource.close();
          onComplete();
        } else if (data.status === 'failed') {
          setError(data.error || 'The logs analysis background worker encountered a failure.');
          eventSource.close();
        }
      } catch (err) {
        console.error('Failed to parse SSE payload:', err);
      }
    };

    eventSource.onerror = (err) => {
      console.error('SSE pipeline stream error:', err);
      setError('Connection to background analysis stream lost.');
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [jobId, onComplete]);

  // Translate technical pipeline keys to beautiful terminal messages
  const getStepLabel = (stage: string) => {
    switch (stage) {
      case 'reading':
        return 'Reading raw security logs from disk...';
      case 'parsing':
        return `Sniffing format and parsing logs (${parsedCount} lines processed)...`;
      case 'inserting-logs':
        return 'Batch-inserting normalized log entries into database...';
      case 'scanning-rules':
        return 'Executing threat signature security rules engine...';
      case 'embeddings':
        return `Segmenting slide-windows and generating AI embeddings (${embeddedCount} chunks)...`;
      case 'completed':
        return 'Finalizing database session states...';
      case 'done':
        return 'Ingestion successful!';
      default:
        return 'Initializing security logs ingestion job...';
    }
  };

  return (
    <Card className="max-w-xl mx-auto border-red-500/20 bg-slate-900/80 backdrop-blur-xl shadow-2xl shadow-red-500/5">
      <CardHeader className="flex flex-col items-center text-center pb-2 pt-6">
        <div className="mb-3">
          <div className="p-3 bg-red-500/10 rounded-full border border-red-500/30 animate-pulse">
            <Shield className="h-8 w-8 text-red-400" />
          </div>
        </div>
        <CardTitle className="text-xl font-mono text-red-400 flex items-center justify-center gap-2">
          INGESTING SECURITY LOGS
        </CardTitle>
        <CardDescription className="text-slate-500 font-mono text-xs mt-1">
          SESSION JOB UUID: {jobId}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6 pt-4">
        {error ? (
          <div className="p-4 bg-red-500/15 border border-red-500/30 rounded-md text-red-400 font-mono text-sm text-center">
            [ERROR] {error}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex justify-between items-center text-xs font-mono mb-2 uppercase tracking-wide">
              <span className="text-red-400 text-xs sm:text-sm">{getStepLabel(step)}</span>
              <span className="text-red-300 font-bold">{progress}%</span>
            </div>
            <div className="w-full bg-slate-950 h-3 rounded-full overflow-hidden border border-slate-800 p-0.5">
              <div
                className="bg-gradient-to-r from-red-600 to-red-400 h-full rounded-full transition-all duration-300 shadow-[0_0_8px_rgba(239,68,68,0.5)]"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="flex items-center justify-center gap-1.5 text-[9px] text-slate-500 font-mono mt-3 uppercase tracking-widest">
              <RefreshCw className="h-3 w-3 animate-spin text-red-500" />
              <span>DO NOT CLOSE THIS PAGE. ANALYZING THREATS AND RETRIEVING EMBEDDINGS...</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
