import { NextRequest } from 'next/server';
import { getSession } from '@/lib/db/sessions';
import { getFindingsBySession } from '@/lib/db/findings';
import { getEntriesBySession } from '@/lib/db/logEntries';
import { getQaHistoryBySession } from '@/lib/db/qaHistory';
import OpenAI from 'openai';
import React from 'react';
import { Document, Page, Text, View, StyleSheet, renderToBuffer } from '@react-pdf/renderer';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || 'mock-api-key',
});

// Configure highly readable PDF layout styles
const styles = StyleSheet.create({
  page: {
    padding: 40,
    backgroundColor: '#ffffff',
    fontFamily: 'Helvetica',
  },
  coverPage: {
    padding: 60,
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    height: '100%',
    backgroundColor: '#0f172a',
    color: '#ffffff',
  },
  coverTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#06b6d4',
    marginBottom: 10,
    textTransform: 'uppercase',
    letterSpacing: 2,
  },
  coverSubtitle: {
    fontSize: 16,
    color: '#94a3b8',
    marginBottom: 60,
  },
  metaGroup: {
    marginTop: 100,
    borderTopWidth: 1,
    borderTopColor: '#334155',
    paddingTop: 20,
  },
  metaText: {
    fontSize: 9,
    color: '#64748b',
    marginBottom: 6,
    fontFamily: 'Courier',
  },
  sectionTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#0f172a',
    borderBottomWidth: 1,
    borderBottomColor: '#cbd5e1',
    paddingBottom: 4,
    marginTop: 24,
    marginBottom: 10,
    textTransform: 'uppercase',
  },
  bodyText: {
    fontSize: 9,
    color: '#334155',
    lineHeight: 1.6,
    marginBottom: 10,
  },
  table: {
    display: 'flex',
    flexDirection: 'column',
    borderWidth: 1,
    borderColor: '#cbd5e1',
    marginBottom: 15,
  },
  tableRow: {
    flexDirection: 'row',
    borderBottomWidth: 1,
    borderBottomColor: '#e2e8f0',
    minHeight: 22,
    alignItems: 'center',
  },
  tableHeader: {
    backgroundColor: '#f8fafc',
    borderBottomWidth: 2,
    borderBottomColor: '#cbd5e1',
  },
  col1: { width: '15%', padding: 4, fontSize: 8, fontWeight: 'bold' },
  col2: { width: '30%', padding: 4, fontSize: 8 },
  col3: { width: '25%', padding: 4, fontSize: 8 },
  col4: { width: '30%', padding: 4, fontSize: 8 },
  // Timeline columns
  timeCol1: { width: '25%', padding: 4, fontSize: 7 },
  timeCol2: { width: '20%', padding: 4, fontSize: 7 },
  timeCol3: { width: '20%', padding: 4, fontSize: 7 },
  timeCol4: { width: '35%', padding: 4, fontSize: 7 },
});

interface PDFReportProps {
  session: any;
  summary: string;
  findings: any[];
  timeline: any[];
  iocs: { ips: string[]; ports: number[] };
}

// React-PDF component to build dynamic security layouts
const SecurityIncidentReportPDF = ({
  session,
  summary,
  findings,
  timeline,
  iocs,
}: PDFReportProps) => (
  <Document>
    {/* Page 1: COVER PAGE */}
    <Page size="A4" style={{ padding: 0 }}>
      <View style={styles.coverPage}>
        <Text style={styles.coverTitle}>Security Incident Report</Text>
        <Text style={styles.coverSubtitle}>Automated Threat Sniffer & Logs Compromise Analysis</Text>

        <View style={styles.metaGroup}>
          <Text style={styles.metaText}>TARGET AUDIT SESSION : {session.name}</Text>
          <Text style={styles.metaText}>SESSION UUID         : {session.id}</Text>
          <Text style={styles.metaText}>INGESTION PARSER     : {session.logSource.toUpperCase()}</Text>
          <Text style={styles.metaText}>AUDIT DATE           : {new Date(session.createdAt).toUTCString()}</Text>
          <Text style={styles.metaText}>OPERATOR EMAIL       : security-analyst@sec.company</Text>
        </View>
      </View>
    </Page>

    {/* Page 2: CONTENT REPORT */}
    <Page size="A4" style={styles.page}>
      
      {/* Executive Summary */}
      <Text style={styles.sectionTitle}>Executive Summary</Text>
      <Text style={styles.bodyText}>{summary}</Text>

      {/* Findings Table */}
      <Text style={styles.sectionTitle}>Identified Threat Findings</Text>
      {findings.length === 0 ? (
        <Text style={styles.bodyText}>No rules-based threat signatures captured in this session.</Text>
      ) : (
        <View style={styles.table}>
          <View style={[styles.tableRow, styles.tableHeader]}>
            <Text style={styles.col1}>SEVERITY</Text>
            <Text style={styles.col2}>TITLE / COMPROMISE</Text>
            <Text style={styles.col3}>AFFECTED IP / ASSET</Text>
            <Text style={styles.col4}>RECOMMENDATION</Text>
          </View>
          {findings.map((f, i) => {
            const affected = f.evidence?.ip || f.evidence?.affectedIps?.[0] || 'Unknown/Internal';
            const rec = f.evidence?.recommendations?.[0] || 'Review system logs configurations.';
            return (
              <View key={i} style={styles.tableRow}>
                <Text style={[styles.col1, { color: f.severity === 'critical' ? '#ef4444' : '#f97316' }]}>
                  {f.severity.toUpperCase()}
                </Text>
                <Text style={styles.col2}>{f.title}</Text>
                <Text style={styles.col3}>{affected}</Text>
                <Text style={styles.col4}>{rec}</Text>
              </View>
            );
          })}
        </View>
      )}

      {/* Incident Timeline */}
      <Text style={styles.sectionTitle}>Incident Chronology Timeline (Top 20 Events)</Text>
      {timeline.length === 0 ? (
        <Text style={styles.bodyText}>No chronologically sorted event datasets available.</Text>
      ) : (
        <View style={styles.table}>
          <View style={[styles.tableRow, styles.tableHeader]}>
            <Text style={styles.timeCol1}>TIMESTAMP (UTC)</Text>
            <Text style={styles.timeCol2}>SOURCE IP</Text>
            <Text style={styles.timeCol3}>ACTION / COMMAND</Text>
            <Text style={styles.timeCol4}>TARGETED PATH / RESOURCE</Text>
          </View>
          {timeline.map((e, i) => {
            const timeStr = e.ts ? new Date(e.ts).toISOString().replace('T', ' ').slice(0, 19) : 'Unknown';
            return (
              <View key={i} style={styles.tableRow}>
                <Text style={styles.timeCol1}>{timeStr}</Text>
                <Text style={styles.timeCol2}>{e.ip || '-'}</Text>
                <Text style={styles.timeCol3}>{e.action || '-'}</Text>
                <Text style={styles.timeCol4}>{e.resource || '-'}</Text>
              </View>
            );
          })}
        </View>
      )}

      {/* Appendix: IOCs */}
      <Text style={styles.sectionTitle}>Appendix: Indicators of Compromise (IOCs)</Text>
      <View style={{ marginBottom: 10 }}>
        <Text style={styles.bodyText}>
          <Text style={{ fontWeight: 'bold' }}>Flagged Attacker IPs: </Text>
          {iocs.ips.length === 0 ? 'None detected' : iocs.ips.join(', ')}
        </Text>
        <Text style={styles.bodyText}>
          <Text style={{ fontWeight: 'bold' }}>Targeted Firewall/App Ports: </Text>
          {iocs.ports.length === 0 ? 'None detected' : iocs.ports.join(', ')}
        </Text>
      </View>

    </Page>
  </Document>
);

export async function GET(req: NextRequest, { params }: { params: { id: string } }): Promise<Response> {
  const sessionId = params.id;

  try {
    // 1. Fetch Session details, findings, logs chronology, and Q&A history
    const [session, findings, logEntries] = await Promise.all([
      getSession(sessionId),
      getFindingsBySession(sessionId),
      getEntriesBySession(sessionId),
    ]);

    if (!session) {
      return new Response(JSON.stringify({ error: 'Audit session not found.' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 2. Draft non-technical executive summary using GPT-4o CISO prompt
    let aiSummary = 'No rules-based compromise alerts were triggered during analysis. Operational state is stable.';
    if (findings.length > 0) {
      try {
        const prompt = `Write a concise executive summary of the following security findings for a non-technical audience. Focus on business risk and urgency.\n\nFindings:\n${JSON.stringify(
          findings.map((f) => ({ title: f.title, severity: f.severity, description: f.description }))
        )}`;

        const completion = await openai.chat.completions.create({
          model: 'gpt-4o',
          messages: [
            {
              role: 'system',
              content:
                'You are an elite Chief Information Security Officer (CISO) writing an incident summary report.',
            },
            { role: 'user', content: prompt },
          ],
          max_tokens: 300,
        });
        aiSummary = completion.choices[0]?.message?.content || aiSummary;
      } catch (aiErr) {
        console.error('Failed to generate GPT-4o executive report summary:', aiErr);
      }
    }

    // 3. Slice timeline events (top 20 events sorted by timestamp)
    const timeline = [...logEntries]
      .filter((e) => e.ts !== null)
      .sort((a, b) => new Date(a.ts!).getTime() - new Date(b.ts!).getTime())
      .slice(0, 20);

    // 4. Group IOCs
    const iocsIps = new Set<string>();
    const iocsPorts = new Set<number>();

    findings.forEach((f) => {
      if (f.evidence?.ip) iocsIps.add(f.evidence.ip);
      if (f.evidence?.affectedIps) {
        f.evidence.affectedIps.forEach((ip: string) => iocsIps.add(ip));
      }
      if (f.evidence?.iocs?.ips) {
        f.evidence.iocs.ips.forEach((ip: string) => iocsIps.add(ip));
      }
      if (f.evidence?.iocs?.ports) {
        f.evidence.iocs.ports.forEach((port: number) => iocsPorts.add(port));
      }
    });

    const iocs = {
      ips: Array.from(iocsIps),
      ports: Array.from(iocsPorts),
    };

    // 5. Render dynamically to PDF buffer using React-PDF server tools
    const pdfBuffer = await renderToBuffer(
      <SecurityIncidentReportPDF
        session={session}
        summary={aiSummary}
        findings={findings}
        timeline={timeline}
        iocs={iocs}
      />
    );

    // Return application/pdf payload as attachment file
    const safeSessionName = session.name.replace(/[^a-zA-Z0-9]/g, '_');
    return new Response(pdfBuffer, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="Incident_Report_${safeSessionName}.pdf"`,
      },
    });

  } catch (err: any) {
    console.error('Fatal incident report PDF generation failure:', err);
    return new Response(JSON.stringify({ error: err.message || 'Server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
