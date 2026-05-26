'use client';

import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from './ui';
import { AlertCircle, Flame, Layers } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import { Finding, LogEntry } from '@/types';

interface OverviewTabProps {
  session: any;
  findings: Finding[];
  logEntries: LogEntry[];
}

export default function OverviewTab({ session, findings = [], logEntries = [] }: OverviewTabProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Compute counts
  const totalEvents = logEntries.length || session.logCount || 0;
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;
  const lowCount = findings.filter((f) => f.severity === 'low').length;
  const infoCount = findings.filter((f) => f.severity === 'info').length;

  // Severity Pie data
  const pieData = [
    { name: 'Critical', value: criticalCount, color: '#ef4444' }, // Red
    { name: 'High', value: highCount, color: '#f97316' },     // Orange
    { name: 'Medium', value: mediumCount, color: '#eab308' }, // Yellow
    { name: 'Low', value: lowCount, color: '#3b82f6' },       // Blue
    { name: 'Info', value: infoCount, color: '#64748b' },     // Gray
  ].filter((item) => item.value > 0);

  // Group events by hour
  const getTimelineData = () => {
    if (logEntries.length === 0) {
      // Fallback dummy chronology data if logs entries aren't pre-loaded yet
      return [
        { hour: '00:00', count: 12 },
        { hour: '04:00', count: 25 },
        { hour: '08:00', count: 48 },
        { hour: '12:00', count: 90 },
        { hour: '16:00', count: 140 },
        { hour: '20:00', count: 64 },
        { hour: '23:59', count: 28 },
      ];
    }

    const hoursBucket: Record<string, number> = {};
    logEntries.forEach((entry) => {
      if (!entry.ts) return;
      const date = new Date(entry.ts);
      const formattedHour = `${String(date.getUTCHours()).padStart(2, '0')}:00`;
      hoursBucket[formattedHour] = (hoursBucket[formattedHour] || 0) + 1;
    });

    return Object.entries(hoursBucket)
      .map(([hour, count]) => ({ hour, count }))
      .sort((a, b) => a.hour.localeCompare(b.hour));
  };

  const timelineData = getTimelineData();

  // Top 10 IPs with findings count
  const getTopIps = () => {
    const ipCounts: Record<string, number> = {};
    findings.forEach((finding) => {
      const ip = finding.evidence?.ip || (finding.evidence as any)?.userName;
      if (ip) {
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
      }
    });

    // If no findings contain IPs, fall back to parsing logs IP counts
    if (Object.keys(ipCounts).length === 0) {
      logEntries.forEach((entry) => {
        if (entry.ip) {
          ipCounts[entry.ip] = (ipCounts[entry.ip] || 0) + 1;
        }
      });
    }

    return Object.entries(ipCounts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  };

  const topIps = getTopIps();

  if (!mounted) return null;

  return (
    <div className="space-y-6">
      
      {/* 3 Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="border-slate-800 bg-slate-900/40 hover:border-slate-700/60 transition-colors">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase">
              Total Logs parsed
            </CardTitle>
            <Layers className="h-4 w-4 text-cyan-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-cyan-300">{totalEvents.toLocaleString()}</div>
            <p className="text-[10px] text-slate-500 font-mono mt-1">TOTAL PARSED EVENT ENTRIES</p>
          </CardContent>
        </Card>

        <Card className="border-slate-800 bg-slate-900/40 hover:border-slate-700/60 transition-colors">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase">
              Critical Findings
            </CardTitle>
            <Flame className="h-4 w-4 text-red-500 animate-pulse" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-red-400">{criticalCount}</div>
            <p className="text-[10px] text-slate-500 font-mono mt-1">IMMEDIATE ATTENTION REQUIRED</p>
          </CardContent>
        </Card>

        <Card className="border-slate-800 bg-slate-900/40 hover:border-slate-700/60 transition-colors">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase">
              High Findings
            </CardTitle>
            <AlertCircle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-orange-400">{highCount}</div>
            <p className="text-[10px] text-slate-500 font-mono mt-1">POTENTIAL SECURITY VIOLATIONS</p>
          </CardContent>
        </Card>
      </div>

      {/* Graphs Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* AreaChart: Logs frequency over time */}
        <Card className="border-slate-800 bg-slate-900/30">
          <CardHeader>
            <CardTitle className="text-xs uppercase tracking-wider font-mono text-cyan-400">
              Event Frequency Timeline
            </CardTitle>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData}>
                <defs>
                  <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="hour" stroke="#475569" fontSize={10} fontClassName="font-mono" />
                <YAxis stroke="#475569" fontSize={10} fontClassName="font-mono" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                  labelClassName="font-mono text-cyan-400 text-xs"
                />
                <Area type="monotone" dataKey="count" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorCount)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* PieChart: Findings severity */}
        <Card className="border-slate-800 bg-slate-900/30">
          <CardHeader>
            <CardTitle className="text-xs uppercase tracking-wider font-mono text-cyan-400">
              Findings Severity Matrix
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col sm:flex-row items-center justify-around h-64">
            {pieData.length === 0 ? (
              <div className="text-xs font-mono text-slate-500 py-12">No compromise findings detected.</div>
            ) : (
              <>
                <div className="w-40 h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={70}
                        paddingAngle={4}
                        dataKey="value"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-2 mt-4 sm:mt-0">
                  {pieData.map((item) => (
                    <div key={item.name} className="flex items-center gap-3 text-xs font-mono">
                      <span className="w-3 h-3 rounded-sm" style={{ backgroundColor: item.color }} />
                      <span className="text-slate-300 font-semibold">{item.name}:</span>
                      <span className="text-slate-400">{item.value} alerts</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Suspicious IPs */}
      <Card className="border-slate-800 bg-slate-900/30">
        <CardHeader>
          <CardTitle className="text-xs uppercase tracking-wider font-mono text-cyan-400">
            Top Distributed Threat Sources (IP / Nodes)
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {topIps.length === 0 ? (
            <div className="text-center text-xs font-mono text-slate-500 py-6">
              No distributed threat activity captured.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-1/2">IP Address / Account Source</TableHead>
                  <TableHead>Occurrences Count</TableHead>
                  <TableHead className="text-right">Risk Vector</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {topIps.map((item, idx) => (
                  <TableRow key={item.ip}>
                    <TableCell className="text-cyan-400 font-bold">{item.ip}</TableCell>
                    <TableCell>{item.count}</TableCell>
                    <TableCell className="text-right">
                      {idx === 0 ? (
                        <span className="text-red-400 font-semibold">Primary Target</span>
                      ) : idx < 3 ? (
                        <span className="text-orange-400 font-semibold">Suspicious Vector</span>
                      ) : (
                        <span className="text-slate-400">Moderate Interaction</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

    </div>
  );
}
