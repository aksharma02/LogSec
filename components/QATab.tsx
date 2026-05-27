'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, Badge, Button } from './ui';
import { Terminal, Send, ShieldAlert, Cpu, CheckCircle2, User, AlertTriangle, Layers } from 'lucide-react';

interface FindingBlock {
  title: string;
  severity: string;
  affectedIps: string[];
  affectedUsers: string[];
  evidence: string[];
  iocs: {
    ips: string[];
    ports: number[];
    userAgents: string[];
    hashes: string[];
  };
}

interface ThreatAnalysis {
  summary: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  threatCategories: string[];
  findings: FindingBlock[];
  recommendations: string[];
}

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  parsedAnalysis?: ThreatAnalysis;
  error?: string;
}

interface QATabProps {
  sessionId: string;
}

export default function QATab({ sessionId }: QATabProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll chat window to bottom on new messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  // Command/Ctrl+Enter submission handler
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const userQuery = input.trim();
    setInput('');
    setLoading(true);

    // Append user question
    const updatedMessages = [
      ...messages,
      { role: 'user' as const, content: userQuery },
    ];
    setMessages([
      ...updatedMessages,
      { role: 'assistant' as const, content: '' }, // Placeholder for stream response
    ]);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId,
          question: userQuery,
        }),
      });

      if (response.status === 429) {
        // Rate limit hit
        setMessages([
          ...updatedMessages,
          {
            role: 'assistant',
            content: '',
            error: 'Rate limit exceeded (20 requests/hour). Please wait and try again later.',
          },
        ]);
        setLoading(false);
        return;
      }

      if (!response.ok) {
        throw new Error('Streaming analysis failed. Please verify configurations.');
      }

      // Stream Reader
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let accumulatedText = '';

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const token = decoder.decode(value, { stream: true });
          accumulatedText += token;

          // Incrementally update the streaming assistant message in state
          setMessages((prev) => {
            const next = [...prev];
            const lastIndex = next.length - 1;
            next[lastIndex] = {
              ...next[lastIndex],
              content: accumulatedText,
            };
            return next;
          });
        }
      }

      // Once streaming finishes, try to parse and serialize threat analysis JSON
      try {
        const parsed: ThreatAnalysis = JSON.parse(accumulatedText);
        setMessages((prev) => {
          const next = [...prev];
          const lastIndex = next.length - 1;
          next[lastIndex] = {
            ...next[lastIndex],
            parsedAnalysis: parsed,
          };
          return next;
        });
      } catch (parseErr) {
        console.warn('Completed stream was not parsable as valid ThreatAnalysis JSON:', parseErr);
      }

    } catch (err: any) {
      console.error('Fatal streaming chat error:', err);
      setMessages([
        ...updatedMessages,
        {
          role: 'assistant',
          content: '',
          error: err.message || 'A network error occurred while reaching the security worker.',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-[650px] border border-slate-800 rounded-lg bg-slate-900/30 overflow-hidden">
      
      {/* Tab Header banner */}
      <div className="bg-slate-950 p-4 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cpu className="h-5 w-5 text-red-400" />
          <div>
            <h3 className="text-sm font-mono text-red-400 font-bold uppercase tracking-wider">
              GPT-4o Threat Analysis Console
            </h3>
            <p className="text-[10px] text-slate-500 font-mono mt-0.5">
              RAG CONTEXT LIMIT: 6,000 TOKENS • RETRIEVAL ACTIVE
            </p>
          </div>
        </div>
      </div>

      {/* Message History Scroller */}
      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center max-w-md mx-auto space-y-4">
            <Cpu className="h-10 w-10 text-slate-700 animate-pulse" />
            <h4 className="text-slate-400 font-mono text-sm uppercase tracking-wider font-semibold">
              Ready for Security Log Inquiries
            </h4>
            <p className="text-slate-500 text-xs">
              Describe logs contexts or query specific indicators. Examples:
              <br />
              <span className="text-red-400/80 font-mono">"Summarize all authentication anomalies"</span> or 
              <br />
              <span className="text-red-400/80 font-mono">"List malicious IP forensics indicators"</span>.
            </p>
          </div>
        ) : (
          messages.map((msg, index) => {
            const isUser = msg.role === 'user';

            return (
              <div key={index} className={`flex ${isUser ? 'justify-end' : 'justify-start'} animate-fadeIn`}>
                <div
                  className={`w-full max-w-3xl flex gap-3 ${
                    isUser ? 'flex-row-reverse' : 'flex-row'
                  }`}
                >
                  {/* Avatar Icon */}
                  <div
                    className={`h-8 w-8 rounded-full flex items-center justify-center border shrink-0 ${
                      isUser
                        ? 'bg-slate-800 border-slate-700 text-slate-300'
                        : 'bg-red-500/10 border-red-500/30 text-red-400'
                    }`}
                  >
                    {isUser ? <User className="h-4 w-4" /> : <Cpu className="h-4 w-4" />}
                  </div>

                  {/* Bubble content */}
                  <div className="flex-1 space-y-2">
                    
                    {/* Raw Streaming logs fallback indicator */}
                    {!isUser && !msg.parsedAnalysis && !msg.error && (
                      <div className="bg-slate-950/60 p-4 border border-slate-800 rounded font-mono text-xs text-slate-400 leading-relaxed max-w-max whitespace-pre-wrap">
                        {msg.content || 'Retrieving vector contexts and initializing GPT stream...'}
                      </div>
                    )}

                    {/* Error Bubble */}
                    {msg.error && (
                      <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-md font-mono text-xs flex items-center gap-2 max-w-max">
                        <AlertTriangle className="h-4 w-4" />
                        <span>{msg.error}</span>
                      </div>
                    )}

                    {/* Serialized ThreatAnalysis Report */}
                    {msg.parsedAnalysis && (
                      <div className="space-y-4 animate-fadeIn">
                        
                        {/* Threat Analysis Summary Board */}
                        <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
                          <CardHeader className="flex flex-row items-center justify-between pb-2 bg-slate-950/40">
                            <div>
                              <CardTitle className="text-xs uppercase tracking-wider font-mono text-slate-400">
                                AI Summary report
                              </CardTitle>
                              <div className="flex items-center gap-2 mt-1.5">
                                <Badge variant={msg.parsedAnalysis.severity}>{msg.parsedAnalysis.severity}</Badge>
                                {msg.parsedAnalysis.threatCategories.map((cat, i) => (
                                  <span
                                    key={i}
                                    className="bg-slate-800 text-[10px] text-slate-400 font-mono px-2 py-0.5 border border-slate-700 rounded"
                                  >
                                    {cat}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </CardHeader>
                          <CardContent className="pt-3">
                            <p className="text-slate-300 text-xs leading-relaxed">{msg.parsedAnalysis.summary}</p>
                          </CardContent>
                        </Card>

                        {/* Detailed Findings Cards */}
                        {msg.parsedAnalysis.findings.length > 0 && (
                          <div className="space-y-3">
                            <h5 className="text-[10px] uppercase font-mono text-slate-500 tracking-widest pl-1 font-bold">
                              Suspicious Findings ({msg.parsedAnalysis.findings.length})
                            </h5>
                            
                            {msg.parsedAnalysis.findings.map((f, fIdx) => (
                              <Card key={fIdx} className="border-slate-800 bg-slate-950/30">
                                <CardHeader className="pb-2">
                                  <div className="flex items-center gap-2">
                                    <Badge variant={f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'high' : 'medium'}>
                                      {f.severity}
                                    </Badge>
                                    <CardTitle className="text-xs text-white font-mono">{f.title}</CardTitle>
                                  </div>
                                </CardHeader>
                                <CardContent className="space-y-3 text-xs">
                                  
                                  {/* Affected targets details */}
                                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[10px] font-mono">
                                    {f.affectedIps.length > 0 && (
                                      <div>
                                        <span className="text-slate-500 block uppercase">AFFECTED IPS</span>
                                        <span className="text-red-400 font-bold block mt-0.5">
                                          {f.affectedIps.join(', ')}
                                        </span>
                                      </div>
                                    )}
                                    {f.affectedUsers.length > 0 && (
                                      <div>
                                        <span className="text-slate-500 block uppercase">AFFECTED USERS</span>
                                        <span className="text-slate-300 font-bold block mt-0.5">
                                          {f.affectedUsers.join(', ')}
                                        </span>
                                      </div>
                                    )}
                                  </div>

                                  {/* Forensics Raw Evidence */}
                                  {f.evidence.length > 0 && (
                                    <div>
                                      <span className="text-[10px] text-slate-500 font-mono uppercase block">
                                        Forensics Evidence Samples
                                      </span>
                                      <div className="bg-slate-950 p-2.5 border border-slate-800 rounded font-mono text-[9px] text-slate-400 mt-1 space-y-1">
                                        {f.evidence.map((ev, evIdx) => (
                                          <div key={evIdx} className="whitespace-pre overflow-x-auto">
                                            {ev}
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {/* Indicators of Compromise IoCs */}
                                  {(f.iocs.ips.length > 0 || f.iocs.ports.length > 0 || f.iocs.userAgents.length > 0) && (
                                    <div>
                                      <span className="text-[10px] text-slate-500 font-mono uppercase block">
                                        COMPROMISE IOCS
                                      </span>
                                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mt-1 bg-slate-950/80 p-2 border border-slate-800 rounded text-[9px] font-mono">
                                        {f.iocs.ips.length > 0 && (
                                          <div>
                                            <span className="text-red-400 block font-semibold">MALICIOUS IPS</span>
                                            <span className="text-slate-400 block mt-0.5">{f.iocs.ips.join(', ')}</span>
                                          </div>
                                        )}
                                        {f.iocs.ports.length > 0 && (
                                          <div>
                                            <span className="text-orange-400 block font-semibold">TARGETED PORTS</span>
                                            <span className="text-slate-400 block mt-0.5">{f.iocs.ports.join(', ')}</span>
                                          </div>
                                        )}
                                        {f.iocs.userAgents.length > 0 && (
                                          <div className="col-span-1 sm:col-span-3 mt-1 pt-1 border-t border-slate-800">
                                            <span className="text-slate-500 block font-semibold">USER AGENTS</span>
                                            <span className="text-slate-400 block mt-0.5 leading-relaxed">
                                              {f.iocs.userAgents.join(' | ')}
                                            </span>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  )}

                                </CardContent>
                              </Card>
                            ))}
                          </div>
                        )}

                        {/* Recommendations */}
                        {msg.parsedAnalysis.recommendations.length > 0 && (
                          <Card className="border-slate-800 bg-slate-900/20">
                            <CardHeader className="pb-1.5">
                              <CardTitle className="text-xs uppercase tracking-wider font-mono text-red-400 flex items-center gap-1.5">
                                <CheckCircle2 className="h-3.5 w-3.5 text-red-400" />
                                <span>Remediation checklist</span>
                              </CardTitle>
                            </CardHeader>
                            <CardContent>
                              <ul className="list-decimal pl-4 space-y-1 text-xs text-slate-300">
                                {msg.parsedAnalysis.recommendations.map((rec, rIdx) => (
                                  <li key={rIdx}>{rec}</li>
                                ))}
                              </ul>
                            </CardContent>
                          </Card>
                        )}

                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}

        {/* Streaming Loader / Typing Indicator */}
        {loading && (
          <div className="flex justify-start items-center gap-2 animate-pulse text-xs font-mono text-slate-500">
            <Cpu className="h-4 w-4 animate-spin text-red-400" />
            <span>AI SEC scanner analyzing logs semantic vectors...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Message panel */}
      <div className="p-4 bg-slate-950 border-t border-slate-800/80">
        <div className="flex gap-4">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-slate-900 border border-slate-800 rounded-md p-3 text-xs text-slate-300 focus:outline-none focus:border-red-500 font-mono resize-none h-16"
            placeholder="Ask a logs-related security query (e.g. 'Identify privilege escalation vectors'). Press Cmd+Enter to send."
          />
          <Button
            onClick={handleSend}
            disabled={!input.trim() || loading}
            className="glow-red self-end px-4 py-3 h-10 flex items-center justify-center gap-2 font-mono text-xs uppercase"
          >
            <Send className="h-3.5 w-3.5" />
            <span>SEND</span>
          </Button>
        </div>
      </div>

    </div>
  );
}
