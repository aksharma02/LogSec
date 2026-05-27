'use client';

import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, Badge, Button } from './ui';
import { ChevronDown, ChevronUp, ShieldAlert, Download, Terminal, Search, Filter } from 'lucide-react';
import { Finding } from '@/types';

interface FindingsTabProps {
  sessionId: string;
  findings: Finding[];
}

export default function FindingsTab({ sessionId, findings = [] }: FindingsTabProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  // Filter logic
  const filteredFindings = findings.filter((finding) => {
    const matchesSeverity = severityFilter === 'all' || finding.severity === severityFilter;
    const searchLower = searchQuery.toLowerCase();
    const matchesSearch =
      finding.title.toLowerCase().includes(searchLower) ||
      finding.type.toLowerCase().includes(searchLower) ||
      finding.description.toLowerCase().includes(searchLower);

    return matchesSeverity && matchesSearch;
  });

  // Dynamic PDF report download handler
  const handleExportPDF = () => {
    window.open(`/api/sessions/${sessionId}/report`, '_blank');
  };

  return (
    <div className="space-y-6">
      
      {/* Action and Filter Controls Banner */}
      <div className="flex flex-col sm:flex-row gap-4 items-center justify-between bg-slate-900/40 p-4 rounded-lg border border-slate-800">
        
        {/* Search Input */}
        <div className="relative w-full sm:max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-md pl-9 pr-4 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-red-500 font-mono"
            placeholder="Search category or title..."
          />
        </div>

        {/* Filters */}
        <div className="flex items-center gap-4 w-full sm:w-auto justify-end">
          
          <div className="flex items-center gap-2">
            <Filter className="h-3 w-3 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-red-500 font-mono"
            >
              <option value="all">ALL SEVERITIES</option>
              <option value="critical">CRITICAL</option>
              <option value="high">HIGH</option>
              <option value="medium">MEDIUM</option>
              <option value="low">LOW</option>
              <option value="info">INFO</option>
            </select>
          </div>

          <Button onClick={handleExportPDF} size="sm" variant="outline" className="flex items-center gap-2">
            <Download className="h-3 w-3" />
            <span>EXPORT PDF</span>
          </Button>
        </div>

      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredFindings.length === 0 ? (
          <Card className="border-slate-800 bg-slate-900/10 p-12 text-center">
            <ShieldAlert className="h-10 w-10 text-slate-600 mx-auto mb-4" />
            <h3 className="text-slate-400 font-semibold font-mono text-sm">NO FINDINGS MATCH FILTERS</h3>
            <p className="text-slate-600 text-xs mt-1">Adjust your search query or severity parameters above.</p>
          </Card>
        ) : (
          filteredFindings.map((finding) => {
            const isExpanded = expandedId === finding.id;
            
            // Extract IP lists from evidence JSON structures
            const ips = finding.evidence?.ip
              ? [finding.evidence.ip]
              : finding.evidence?.affectedIps || [];

            // Extract recommendation stubs
            const recommendations = (finding.evidence as any)?.recommendations || [
              'Review logs details in search portal.',
              'Revoke unauthorized API credentials.',
              'Implement firewalls blocks on identified attacker IPs.',
            ];

            return (
              <Card
                key={finding.id}
                className={`border-slate-800 transition-all ${
                  isExpanded ? 'border-red-500/25 bg-slate-900/40' : 'bg-slate-900/20 hover:border-slate-800/80'
                }`}
              >
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="flex items-center justify-between p-4 cursor-pointer select-none"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                    <Badge variant={finding.severity as any}>{finding.severity}</Badge>
                    <span className="font-mono text-xs text-slate-500 font-bold">[{finding.type.toUpperCase()}]</span>
                    <span className="text-sm font-semibold text-white tracking-wide">{finding.title}</span>
                  </div>

                  <div className="flex items-center gap-3">
                    {ips.length > 0 && (
                      <span className="text-xs text-red-400 font-mono bg-red-500/5 px-2 py-0.5 border border-red-500/10 rounded">
                        {ips.length} IP Address
                      </span>
                    )}
                    {isExpanded ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
                  </div>
                </div>

                {isExpanded && (
                  <div className="p-4 border-t border-slate-800/80 bg-slate-950/20 space-y-4 animate-fadeIn">
                    
                    {/* Description */}
                    <div>
                      <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
                        Threat Summary
                      </h4>
                      <p className="text-slate-300 text-xs mt-1 leading-relaxed">{finding.description}</p>
                    </div>

                    {/* Evidence & Logs */}
                    {finding.evidence && (
                      <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-1.5">
                          <Terminal className="h-3 w-3 text-red-400" />
                          <span>Forensics Evidence Logs</span>
                        </h4>
                        
                        <div className="bg-slate-950/80 p-3 border border-slate-800 rounded mt-1.5 font-mono text-[10px] text-slate-400 overflow-x-auto space-y-1">
                          {finding.evidence.sampleLines ? (
                            finding.evidence.sampleLines.map((line: string, i: number) => (
                              <div key={i} className="whitespace-pre overflow-x-auto">
                                <span className="text-slate-600 mr-2">[{i + 1}]</span>
                                {line}
                              </div>
                            ))
                          ) : finding.evidence.rawLine ? (
                            <div className="whitespace-pre overflow-x-auto">{finding.evidence.rawLine}</div>
                          ) : (
                            <pre className="whitespace-pre overflow-x-auto text-[10px] text-red-500">
                              {JSON.stringify(finding.evidence, null, 2)}
                            </pre>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Recommendations */}
                    <div>
                      <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
                        Actionable Remediation Recommendations
                      </h4>
                      <ul className="list-disc pl-4 mt-1.5 space-y-1">
                        {recommendations.map((rec: string, i: number) => (
                          <li key={i} className="text-xs text-red-300/80">
                            {rec}
                          </li>
                        ))}
                      </ul>
                    </div>

                  </div>
                )}
              </Card>
            );
          })
        )}
      </div>

    </div>
  );
}
