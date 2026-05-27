'use client';

import React, { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, Badge, Tabs, TabsList, TabsTrigger, TabsContent, Button } from './ui';
import { Shield, ShieldAlert, Cpu, Search as SearchIcon, Layers, FileText, CheckCircle2, History, ArrowLeft, Terminal } from 'lucide-react';
import { Finding, LogEntry, QaHistory } from '@/types';
import OverviewTab from './OverviewTab';
import FindingsTab from './FindingsTab';
import SearchTab from './SearchTab';
import QATab from './QATab';
import JobProgress from './JobProgress';

import { useSession } from 'next-auth/react';

interface SessionDashboardProps {
  session: any;
  findings: Finding[];
  logEntries: LogEntry[];
  qaHistory: QaHistory[];
}

export default function SessionDashboard({
  session,
  findings: initialFindings = [],
  logEntries: initialLogEntries = [],
  qaHistory: initialQaHistory = [],
}: SessionDashboardProps) {
  const router = useRouter();
  const { data: sessionData, status } = useSession();
  const searchParams = useSearchParams();
  const jobId = searchParams.get('jobId') || '';

  // Authenticated operators enforcement check
  useEffect(() => {
    if (status === 'unauthenticated') {
      router.push('/api/auth/signin');
    }
  }, [status, router]);

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-[#0f172a] text-slate-100 flex flex-col justify-center items-center font-mono text-xs uppercase tracking-widest space-y-4">
        <div className="h-8 w-8 border-4 border-red-500 border-t-transparent rounded-full animate-spin" />
        <span className="animate-pulse">VERIFYING OPERATOR ACCESS CREDENTIALS...</span>
      </div>
    );
  }

  const [activeTab, setActiveTab] = useState('overview');
  const [currentStatus, setCurrentStatus] = useState(session.status);

  // Poll status occasionally if completed status has not arrived
  useEffect(() => {
    if (currentStatus === 'completed' || currentStatus === 'failed') return;

    const intervalId = setInterval(async () => {
      try {
        const res = await fetch(`/api/sessions?id=${session.id}`); // Wait, let's create a quick API check if needed, or rely on JobProgress onComplete
        // For simplicity, we can let JobProgress SSE trigger the refresh!
      } catch (err) {
        console.error('Failed to poll status:', err);
      }
    }, 5000);

    return () => clearInterval(intervalId);
  }, [currentStatus, session.id]);

  const handleJobComplete = () => {
    setCurrentStatus('completed');
    router.refresh();
  };

  // If the job is active ('processing' or 'pending') and a jobId parameter is present, force-gate behind JobProgress!
  const isJobRunning = currentStatus === 'processing' || currentStatus === 'pending';
  if (isJobRunning && jobId) {
    return (
      <div className="min-h-screen bg-[#0f172a] text-slate-100 flex items-center justify-center p-6">
        <div className="w-full max-w-xl">
          <JobProgress jobId={jobId} onComplete={handleJobComplete} />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-100 flex flex-col">
      
      {/* Dynamic Security Topbar Banner */}
      <header className="bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 p-4 sticky top-0 z-30">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => router.push('/')}
              className="p-1.5 bg-slate-900 border border-slate-800 rounded hover:bg-slate-800 transition-colors"
            >
              <ArrowLeft className="h-4 w-4 text-slate-400" />
            </button>
            <div className="flex items-center gap-2.5">
              <img src="/logo.png" alt="LogSec Logo" className="h-7 w-auto object-contain rounded" />
              <span className="font-mono font-bold tracking-wider text-sm sm:text-base">
                Log<span className="text-red-400">Sec</span>
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Badge variant={currentStatus === 'completed' ? 'success' : currentStatus === 'failed' ? 'critical' : 'medium'}>
              {currentStatus}
            </Badge>
            <span className="text-xs font-mono text-slate-500 hidden sm:inline">
              OPERATOR INTERFACE ACTIVE
            </span>
          </div>
        </div>
      </header>

      {/* Main Grid: Sidebar + Tabs */}
      <div className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 flex flex-col md:flex-row gap-6">
        
        {/* Sidebar Specifications */}
        <aside className="w-full md:w-64 space-y-6 shrink-0">
          <Card className="border-slate-800 bg-slate-900/30">
            <CardHeader className="pb-3">
              <CardTitle className="text-xs uppercase tracking-wider font-mono text-red-400">
                Session Audit specs
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 pt-1 text-xs">
              
              <div>
                <span className="text-slate-500 font-mono block">AUDIT NAME</span>
                <span className="text-white font-semibold font-mono block mt-0.5">{session.name}</span>
              </div>

              <div>
                <span className="text-slate-500 font-mono block">SESSION UUID</span>
                <span className="text-slate-400 font-mono block mt-0.5 break-all select-all">
                  {session.id}
                </span>
              </div>

              <div>
                <span className="text-slate-500 font-mono block">INGESTION FORMAT</span>
                <span className="text-red-400 font-bold uppercase font-mono block mt-0.5">
                  {session.logSource}
                </span>
              </div>

              <div>
                <span className="text-slate-500 font-mono block">AUDITED RECORD DATE</span>
                <span className="text-slate-400 font-mono block mt-0.5">
                  {new Date(session.createdAt).toLocaleDateString()}
                </span>
              </div>

              <div className="pt-4 border-t border-slate-800">
                <Button onClick={() => router.push('/')} variant="outline" className="w-full text-xs font-mono py-1.5">
                  INGEST NEW LOGS
                </Button>
              </div>

            </CardContent>
          </Card>
        </aside>

        {/* Dynamic content area */}
        <main className="flex-1 min-w-0">
          
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            
            {/* Nav Headers */}
            <TabsList className="w-full overflow-x-auto justify-start h-auto gap-1">
              <TabsTrigger value="overview" className="flex items-center gap-1.5 font-mono text-xs">
                <Layers className="h-3.5 w-3.5" />
                <span>OVERVIEW</span>
              </TabsTrigger>
              <TabsTrigger value="findings" className="flex items-center gap-1.5 font-mono text-xs">
                <ShieldAlert className="h-3.5 w-3.5" />
                <span>THREAT FINDINGS ({initialFindings.length})</span>
              </TabsTrigger>
              <TabsTrigger value="search" className="flex items-center gap-1.5 font-mono text-xs">
                <SearchIcon className="h-3.5 w-3.5" />
                <span>SEMANTIC SEARCH</span>
              </TabsTrigger>
              <TabsTrigger value="qa" className="flex items-center gap-1.5 font-mono text-xs">
                <Cpu className="h-3.5 w-3.5" />
                <span>AI THREAT Q&A</span>
              </TabsTrigger>
              <TabsTrigger value="history" className="flex items-center gap-1.5 font-mono text-xs">
                <History className="h-3.5 w-3.5" />
                <span>QA HISTORY ({initialQaHistory.length})</span>
              </TabsTrigger>
            </TabsList>

            {/* Overview Tab Content */}
            <TabsContent value="overview">
              <OverviewTab session={session} findings={initialFindings} logEntries={initialLogEntries} />
            </TabsContent>

            {/* Findings Tab Content */}
            <TabsContent value="findings">
              <FindingsTab sessionId={session.id} findings={initialFindings} />
            </TabsContent>

            {/* Search Tab Content */}
            <TabsContent value="search">
              <SearchTab sessionId={session.id} />
            </TabsContent>

            {/* AI Q&A Tab Content */}
            <TabsContent value="qa">
              <QATab sessionId={session.id} />
            </TabsContent>

            {/* Conversational History Tab Content */}
            <TabsContent value="history">
              <div className="space-y-4">
                {initialQaHistory.length === 0 ? (
                  <Card className="border-slate-800 bg-slate-900/10 p-12 text-center">
                    <History className="h-10 w-10 text-slate-700 mx-auto mb-4" />
                    <h3 className="text-slate-400 font-semibold font-mono text-sm uppercase">No Chat History</h3>
                    <p className="text-slate-600 text-xs mt-1">
                      Start asking security questions in the AI Threat Q&A tab to log histories.
                    </p>
                  </Card>
                ) : (
                  initialQaHistory.map((item) => (
                    <Card key={item.id} className="border-slate-800 bg-slate-900/20">
                      <CardHeader className="bg-slate-950/40 pb-2">
                        <CardTitle className="text-xs text-red-400 font-mono flex items-center gap-1.5">
                          <History className="h-3.5 w-3.5" />
                          <span>ANALYST QUESTION: "{item.question}"</span>
                        </CardTitle>
                        <CardDescription className="text-slate-500 font-mono text-[9px] mt-0.5">
                          TIMESTAMP: {new Date(item.createdAt).toUTCString()}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="pt-3 text-xs space-y-3">
                        
                        {/* Render simple Summary */}
                        <div>
                          <span className="text-[10px] text-slate-500 font-mono uppercase block">REPORT SUMMARY</span>
                          <p className="text-slate-300 mt-1 leading-relaxed">{item.answer.summary}</p>
                        </div>

                        {/* Mapped Severity */}
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-slate-500 font-mono uppercase">VERDICT RISK SEVERITY:</span>
                          <Badge variant={item.answer.severity}>{item.answer.severity}</Badge>
                        </div>

                        {/* List findings titles */}
                        {item.answer.findings && item.answer.findings.length > 0 && (
                          <div>
                            <span className="text-[10px] text-slate-500 font-mono uppercase block">IDENTIFIED COMPROMISES</span>
                            <ul className="list-disc pl-4 mt-1 text-red-300 space-y-0.5">
                              {item.answer.findings.map((f: any, i: number) => (
                                <li key={i}>{f.title}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                      </CardContent>
                    </Card>
                  ))
                )}
              </div>
            </TabsContent>

          </Tabs>

        </main>
      </div>

    </div>
  );
}
