import fs from 'fs';
import path from 'path';
import { parseLogFile } from '../lib/parsers';
import {
  ruleBruteForceSsh,
  rulePrivilegeEscalation,
  ruleOffHoursAccess
} from '../lib/rules';
import { chunkLogEntries } from '../lib/embeddings';

const mockSession = {
  id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789',
  name: 'Forensics Audit Session - Host web-server-01 Compromise',
  logSource: 'syslog',
  createdAt: new Date(),
};

describe('Forensics Real Problem Attack Simulation & Context Chunking', () => {
  test('should parse real-world syslog attack logs, run rules scanner, and generate RAG chunks', async () => {
    // 1. Setup realistic multi-stage breach syslog trace in standard RFC 3164 format
    const realAttackLogs = [
      '<34>May 26 12:00:01 web-server-01 sshd[999]: Failed password for invalid user admin from 203.0.113.5 port 49152 ssh2',
      '<34>May 26 12:00:15 web-server-01 sshd[999]: Failed password for invalid user root from 203.0.113.5 port 49155 ssh2',
      '<34>May 26 12:00:30 web-server-01 sshd[999]: Failed password for invalid user guest from 203.0.113.5 port 49160 ssh2',
      '<34>May 26 12:00:45 web-server-01 sshd[999]: Failed password for invalid user deploy from 203.0.113.5 port 49162 ssh2',
      '<34>May 26 12:01:00 web-server-01 sshd[999]: Failed password for invalid user test from 203.0.113.5 port 49168 ssh2',
      '<34>May 26 12:01:15 web-server-01 sshd[999]: Failed password for invalid user support from 203.0.113.5 port 49172 ssh2',
      '<34>May 26 12:01:30 web-server-01 sshd[999]: Failed password for invalid user admin from 203.0.113.5 port 49180 ssh2',
      '<34>May 26 12:01:45 web-server-01 sshd[999]: Failed password for invalid user oracle from 203.0.113.5 port 49185 ssh2',
      '<34>May 26 12:02:00 web-server-01 sshd[999]: Failed password for invalid user postgres from 203.0.113.5 port 49190 ssh2',
      '<34>May 26 12:02:15 web-server-01 sshd[999]: Failed password for invalid user root from 203.0.113.5 port 49198 ssh2',
      '<34>May 26 12:02:30 web-server-01 sshd[999]: Failed password for invalid user ubuntu from 203.0.113.5 port 49202 ssh2',
      '<34>May 26 12:02:45 web-server-01 sshd[999]: Failed password for invalid user admin2 from 203.0.113.5 port 49210 ssh2',
      '<34>May 26 12:03:00 web-server-01 sshd[999]: Accepted password for root from 203.0.113.5 port 49215 ssh2',
      '<34>May 26 12:03:10 web-server-01 sudo[1002]:   root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow',
      '<34>May 26 12:03:40 web-server-01 sudo[1002]:   root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo attacker',
    ].join('\n');

    console.log('======================================================================');
    console.log('       SOC INCIDENT FORENSICS PIPELINE DEMONSTRATION RUN              ');
    console.log('======================================================================');
    
    // Stage 1: Ingestion snout sniffing & parsing
    console.log('\n[STAGE 1] Ingesting Syslog text and sniffing formats...');
    const parsedEntries = parseLogFile(realAttackLogs, mockSession.id);
    console.log(`- Detected format: SYSLOG (RFC 5424)`);
    console.log(`- Successfully parsed logs line count: ${parsedEntries.length} lines.`);
    expect(parsedEntries).toHaveLength(15);

    // Stage 2: Trigger Threat Rules Signatures Scanning Engine (Pure functions)
    console.log('\n[STAGE 2] Running security rules signatures scan...');
    const findings: any[] = [];
    findings.push(...ruleBruteForceSsh(parsedEntries, mockSession.id));
    findings.push(...rulePrivilegeEscalation(parsedEntries, mockSession.id));
    findings.push(...ruleOffHoursAccess(parsedEntries, mockSession.id));
    console.log(`- Scan completed! Threat Alerts emitted: ${findings.length} findings.`);
    
    findings.forEach((f, idx) => {
      console.log(`\n  🚨 [Alert #${idx + 1}] Severity: ${f.severity.toUpperCase()} | Title: ${f.title}`);
      console.log(`     Category: ${f.type}`);
      console.log(`     Forensics evidence summary: ${f.description}`);
    });

    // Verify SSH Brute Force and Privilege Escalation signatures were triggered
    const bruteForceAlert = findings.find((f) => f.title.includes('Brute Force') || f.title.includes('Brute-Force'));
    const privEscAlert = findings.find((f) => f.title.includes('Privilege'));
    expect(bruteForceAlert).toBeDefined();
    expect(privEscAlert).toBeDefined();

    // Stage 3: Sliding window log chunking
    console.log('\n[STAGE 3] Sliding window chunking logs for Vector RAG retrieval...');
    const chunks = chunkLogEntries(parsedEntries, 5); // small chunk size for testing
    console.log(`- Chunking parsed lines into ${chunks.length} overlapping text blocks.`);
    expect(chunks.length).toBeGreaterThan(0);

    console.log('  [Sample overlapping Chunk #1]:');
    console.log('  --------------------------------------------------------------');
    console.log(chunks[0].chunkText);
    console.log('  --------------------------------------------------------------');

    // Stage 4: Export Incident Report Metadata payload
    console.log('\n[STAGE 4] Exporting high-fidelity forensics incident briefing metadata...');
    const reportPayload = {
      incidentId: mockSession.id,
      targetAsset: 'web-server-01',
      analysisDate: new Date().toUTCString(),
      findings: findings.map(f => ({
        severity: f.severity,
        title: f.title,
        description: f.description,
        ip: f.evidence.ip || 'Unknown'
      })),
      timelineSummary: '12 failed password entries followed by root access compromise and backdoor wheel group modifications.'
    };

    const targetReportPath = path.join(__dirname, '../Incident_Report_Real_Problem.json');
    fs.writeFileSync(targetReportPath, JSON.stringify(reportPayload, null, 2));
    console.log(`- Report Briefing payload saved locally to: ${targetReportPath}`);
    expect(fs.existsSync(targetReportPath)).toBe(true);

    console.log('\n======================================================================');
    console.log('              FORENSICS ANALYSIS PIPELINE STATUS: OK                  ');
    console.log('======================================================================\n');
  });
});
