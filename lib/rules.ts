import { LogEntry, Finding } from '@/types';
import { insertFinding } from './db/findings';

/**
 * Helper to extract destination ports from a log line.
 * Scans firewall parameters (DST=port), standard ports key-values, and URL/socket patterns.
 */
export function extractDestinationPort(entry: LogEntry): number | null {
  // 1. Look for DST=port (common in firewall/iptables logs)
  const dstMatch = entry.rawLine.match(/(?:DST|dst)=(\d+)/);
  if (dstMatch) return parseInt(dstMatch[1], 10);

  // 2. Look for port numbers in generic key-value formats
  const portMatch = entry.rawLine.match(/(?:port|Port|PORT|dport|dest_port)[=:\s]+(\d+)/);
  if (portMatch) return parseInt(portMatch[1], 10);

  // 3. Look for standard socket suffix: e.g. 192.168.1.1:8080 or http://hostname:80/path
  const socketMatch = entry.rawLine.match(/(?::)(\d+)\b/);
  if (socketMatch) return parseInt(socketMatch[1], 10);

  return null;
}

/**
 * RULE 1 — BRUTE_FORCE_SSH
 * Group failed login entries by IP. If any IP has > 10 failures within any 5-minute sliding window,
 * emit a High finding. Includes count, time window, and up to 3 sample raw lines.
 */
export function ruleBruteForceSsh(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const failuresByIp: Record<string, LogEntry[]> = {};

  for (const entry of entries) {
    const isSsh =
      entry.format === 'syslog' ||
      entry.rawLine.includes('sshd') ||
      entry.rawLine.includes('secure') ||
      entry.rawLine.toLowerCase().includes('ssh');

    const isFailure =
      entry.action === 'sshd_failed' ||
      entry.action === 'auth_failure' ||
      entry.rawLine.toLowerCase().includes('failed password') ||
      entry.rawLine.toLowerCase().includes('invalid user') ||
      entry.rawLine.toLowerCase().includes('authentication failure');

    if (isSsh && isFailure && entry.ip) {
      if (!failuresByIp[entry.ip]) failuresByIp[entry.ip] = [];
      failuresByIp[entry.ip].push(entry);
    }
  }

  const WINDOW_MS = 5 * 60 * 1000; // 5 minutes sliding window

  for (const [ip, ipEntries] of Object.entries(failuresByIp)) {
    // Sort entries chronologically
    const sorted = [...ipEntries].sort((a, b) => {
      const ta = a.ts ? a.ts.getTime() : 0;
      const tb = b.ts ? b.ts.getTime() : 0;
      return ta - tb;
    });

    let maxCount = 0;
    let worstWindowEntries: LogEntry[] = [];

    for (let i = 0; i < sorted.length; i++) {
      const startEntry = sorted[i];
      const startMs = startEntry.ts ? startEntry.ts.getTime() : 0;
      if (startMs === 0) continue;

      const windowEntries = [startEntry];
      for (let j = i + 1; j < sorted.length; j++) {
        const currentEntry = sorted[j];
        const currentMs = currentEntry.ts ? currentEntry.ts.getTime() : 0;

        if (currentMs - startMs <= WINDOW_MS) {
          windowEntries.push(currentEntry);
        } else {
          break;
        }
      }

      if (windowEntries.length > maxCount) {
        maxCount = windowEntries.length;
        worstWindowEntries = windowEntries;
      }
    }

    if (maxCount > 10) {
      const sampleLines = worstWindowEntries.slice(0, 3).map(e => e.rawLine);
      findings.push({
        sessionId,
        type: 'brute_force_ssh',
        severity: 'high',
        title: `SSH Brute Force Attack Detected from ${ip}`,
        description: `IP ${ip} performed ${maxCount} failed SSH login attempts within a 5-minute sliding window.`,
        evidence: {
          ip,
          count: maxCount,
          timeWindow: '5 minutes',
          sampleLines,
        },
        source: 'rule',
      });
    }
  }

  return findings;
}

/**
 * RULE 2 — BRUTE_FORCE_WEB
 * Same logic but for HTTP 401/403 responses.
 * Threshold: > 20 failures / IP / 5 minutes. Medium severity.
 */
export function ruleBruteForceWeb(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const failuresByIp: Record<string, LogEntry[]> = {};

  for (const entry of entries) {
    const isFailure = entry.statusCode === 401 || entry.statusCode === 403;
    if (isFailure && entry.ip) {
      if (!failuresByIp[entry.ip]) failuresByIp[entry.ip] = [];
      failuresByIp[entry.ip].push(entry);
    }
  }

  const WINDOW_MS = 5 * 60 * 1000; // 5 minutes sliding window

  for (const [ip, ipEntries] of Object.entries(failuresByIp)) {
    const sorted = [...ipEntries].sort((a, b) => {
      const ta = a.ts ? a.ts.getTime() : 0;
      const tb = b.ts ? b.ts.getTime() : 0;
      return ta - tb;
    });

    let maxCount = 0;
    let worstWindowEntries: LogEntry[] = [];

    for (let i = 0; i < sorted.length; i++) {
      const startEntry = sorted[i];
      const startMs = startEntry.ts ? startEntry.ts.getTime() : 0;
      if (startMs === 0) continue;

      const windowEntries = [startEntry];
      for (let j = i + 1; j < sorted.length; j++) {
        const currentEntry = sorted[j];
        const currentMs = currentEntry.ts ? currentEntry.ts.getTime() : 0;

        if (currentMs - startMs <= WINDOW_MS) {
          windowEntries.push(currentEntry);
        } else {
          break;
        }
      }

      if (windowEntries.length > maxCount) {
        maxCount = windowEntries.length;
        worstWindowEntries = windowEntries;
      }
    }

    if (maxCount > 20) {
      const sampleLines = worstWindowEntries.slice(0, 3).map(e => e.rawLine);
      findings.push({
        sessionId,
        type: 'brute_force_web',
        severity: 'medium',
        title: `Web Brute Force Attack Detected from ${ip}`,
        description: `IP ${ip} generated ${maxCount} unauthorized HTTP responses (401/403) within a 5-minute sliding window.`,
        evidence: {
          ip,
          count: maxCount,
          timeWindow: '5 minutes',
          sampleLines,
        },
        source: 'rule',
      });
    }
  }

  return findings;
}

/**
 * RULE 3 — PORT_SCAN
 * If a single IP appears in > 20 distinct destination ports within 1 minute, emit a High finding.
 */
export function rulePortScan(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const entriesByIp: Record<string, { entry: LogEntry; port: number }[]> = {};

  for (const entry of entries) {
    if (entry.ip) {
      const port = extractDestinationPort(entry);
      if (port !== null) {
        if (!entriesByIp[entry.ip]) entriesByIp[entry.ip] = [];
        entriesByIp[entry.ip].push({ entry, port });
      }
    }
  }

  const WINDOW_MS = 60 * 1000; // 1 minute

  for (const [ip, ipEntries] of Object.entries(entriesByIp)) {
    const sorted = [...ipEntries].sort((a, b) => {
      const ta = a.entry.ts ? a.entry.ts.getTime() : 0;
      const tb = b.entry.ts ? b.entry.ts.getTime() : 0;
      return ta - tb;
    });

    let maxDistinctPorts = 0;
    let worstWindowDistinctPortsList: number[] = [];
    let worstWindowEntries: LogEntry[] = [];

    for (let i = 0; i < sorted.length; i++) {
      const startItem = sorted[i];
      const startMs = startItem.entry.ts ? startItem.entry.ts.getTime() : 0;
      if (startMs === 0) continue;

      const windowDistinctPorts = new Set<number>([startItem.port]);
      const windowEntries = [startItem.entry];

      for (let j = i + 1; j < sorted.length; j++) {
        const currentItem = sorted[j];
        const currentMs = currentItem.entry.ts ? currentItem.entry.ts.getTime() : 0;

        if (currentMs - startMs <= WINDOW_MS) {
          windowDistinctPorts.add(currentItem.port);
          windowEntries.push(currentItem.entry);
        } else {
          break;
        }
      }

      if (windowDistinctPorts.size > maxDistinctPorts) {
        maxDistinctPorts = windowDistinctPorts.size;
        worstWindowDistinctPortsList = Array.from(windowDistinctPorts);
        worstWindowEntries = windowEntries;
      }
    }

    if (maxDistinctPorts > 20) {
      const sampleLines = worstWindowEntries.slice(0, 3).map(e => e.rawLine);
      findings.push({
        sessionId,
        type: 'port_scan',
        severity: 'high',
        title: `Port Scan Activity Detected from ${ip}`,
        description: `IP ${ip} scanned ${maxDistinctPorts} distinct destination ports within a 1-minute time window.`,
        evidence: {
          ip,
          distinctPortsCount: maxDistinctPorts,
          ports: worstWindowDistinctPortsList.slice(0, 10),
          timeWindow: '1 minute',
          sampleLines,
        },
        source: 'rule',
      });
    }
  }

  return findings;
}

/**
 * RULE 4 — PRIVILEGE_ESCALATION
 * Scan rawLine for patterns: sudo, su -, /etc/sudoers, passwd, usermod, groupadd.
 * Emit a Medium finding per unique user+action combo.
 */
export function rulePrivilegeEscalation(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const seenCombos = new Set<string>();

  const patterns = ['sudo', 'su -', '/etc/sudoers', 'passwd', 'usermod', 'groupadd'];

  for (const entry of entries) {
    const rawLower = entry.rawLine.toLowerCase();
    const matchedPattern = patterns.find(p => rawLower.includes(p));

    if (matchedPattern) {
      const user = entry.userName || 'unknown';
      const action = matchedPattern;
      const comboKey = `${user}:${action}`;

      if (!seenCombos.has(comboKey)) {
        seenCombos.add(comboKey);
        findings.push({
          sessionId,
          type: 'privilege_escalation',
          severity: 'medium',
          title: `Potential Privilege Escalation: ${user} executing ${action}`,
          description: `User "${user}" executed a command matching privilege escalation signature: "${action}".`,
          evidence: {
            userName: user,
            triggeredPattern: action,
            rawLine: entry.rawLine,
            lineNum: entry.lineNum,
          },
          source: 'rule',
        });
      }
    }
  }

  return findings;
}

/**
 * RULE 5 — OFF_HOURS_ACCESS
 * Successful logins (status 200 / auth success) between 23:00 and 05:00 UTC.
 * Emit an Info finding with the user and timestamp.
 */
export function ruleOffHoursAccess(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];

  for (const entry of entries) {
    if (!entry.ts) continue;

    const isLoginSuccess =
      (entry.action === 'login' && (entry.statusCode === 200 || entry.statusCode === null)) ||
      entry.rawLine.toLowerCase().includes('accepted password') ||
      entry.rawLine.toLowerCase().includes('accepted publickey') ||
      entry.rawLine.toLowerCase().includes('session opened for user') ||
      entry.rawLine.toLowerCase().includes('session opened for user root');

    if (isLoginSuccess) {
      const hour = entry.ts.getUTCHours();
      const isOffHours = hour >= 23 || hour < 5;

      if (isOffHours) {
        const user = entry.userName || 'unknown';
        findings.push({
          sessionId,
          type: 'off_hours_access',
          severity: 'low', // 'low' severity represents low-risk info finding alerts
          title: `Off-Hours User Access: ${user}`,
          description: `Successful user login detected during off-hours (23:00 - 05:00 UTC) for user "${user}".`,
          evidence: {
            userName: user,
            timestampUTC: entry.ts.toUTCString(),
            rawLine: entry.rawLine,
          },
          source: 'rule',
        });
      }
    }
  }

  return findings;
}

/**
 * RULE 6 — SOAP_API_FAULT
 * Scans raw logs for SOAP faults, SBL-ODU errors, or general soap fault messages.
 */
export function ruleSoapApiFault(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const seenMessages = new Set<string>();

  for (const entry of entries) {
    const rawLower = entry.rawLine.toLowerCase();
    if (
      rawLower.includes('soapfaultexception') ||
      rawLower.includes('soap fault') ||
      rawLower.includes('sbl-odu-') ||
      rawLower.includes('error sending the soap request')
    ) {
      if (!seenMessages.has(entry.rawLine)) {
        seenMessages.add(entry.rawLine);
        findings.push({
          sessionId,
          type: 'soap_api_fault',
          severity: 'medium',
          title: 'SOAP Web Service Fault Detected',
          description: `A SOAP web service fault or integration error was encountered: "${entry.rawLine.trim().substring(0, 150)}"`,
          evidence: {
            rawLine: entry.rawLine,
            lineNum: entry.lineNum,
          },
          source: 'rule',
        });
      }
    }
  }
  return findings;
}

/**
 * RULE 7 — RATE_LIMIT_EXCEEDED
 * Scans logs for API rate limit or request throttling warnings.
 */
export function ruleRateLimitAlert(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const seenMessages = new Set<string>();

  for (const entry of entries) {
    const rawLower = entry.rawLine.toLowerCase();
    if (
      rawLower.includes('rate limit') ||
      rawLower.includes('rate-limit') ||
      rawLower.includes('too many requests') ||
      rawLower.includes('rate limit error')
    ) {
      if (!seenMessages.has(entry.rawLine)) {
        seenMessages.add(entry.rawLine);
        findings.push({
          sessionId,
          type: 'rate_limit_exceeded',
          severity: 'medium',
          title: 'API / Service Rate Limiting Active',
          description: `The application experienced request throttling or rate limiting: "${entry.rawLine.trim().substring(0, 150)}"`,
          evidence: {
            rawLine: entry.rawLine,
            lineNum: entry.lineNum,
          },
          source: 'rule',
        });
      }
    }
  }
  return findings;
}

/**
 * RULE 8 — SOCKET_BIND_FAILURE
 * Scans for socket binding errors or address in use issues.
 */
export function ruleSocketBindFailure(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const seenMessages = new Set<string>();

  for (const entry of entries) {
    const rawLower = entry.rawLine.toLowerCase();
    if (
      rawLower.includes('failed to bind socket') ||
      rawLower.includes('address already in use') ||
      rawLower.includes('socket bind fail')
    ) {
      if (!seenMessages.has(entry.rawLine)) {
        seenMessages.add(entry.rawLine);
        findings.push({
          sessionId,
          type: 'socket_bind_failure',
          severity: 'high',
          title: 'Network Port Binding Conflict',
          description: `Critical network port binding failure: "${entry.rawLine.trim().substring(0, 150)}"`,
          evidence: {
            rawLine: entry.rawLine,
            lineNum: entry.lineNum,
          },
          source: 'rule',
        });
      }
    }
  }
  return findings;
}

/**
 * RULE 9 — APPLICATION_CRITICAL_EXCEPTION
 * Scans logs for unhandled critical exceptions, database timeout errors, or application crash signatures.
 */
export function ruleAppCriticalException(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const seenMessages = new Set<string>();

  for (const entry of entries) {
    const rawLower = entry.rawLine.toLowerCase();
    if (
      rawLower.includes('unhandled exception') ||
      rawLower.includes('nullreferenceexception') ||
      rawLower.includes('database connection failed') ||
      rawLower.includes('timeout occurred')
    ) {
      if (!seenMessages.has(entry.rawLine)) {
        seenMessages.add(entry.rawLine);
        findings.push({
          sessionId,
          type: 'app_critical_exception',
          severity: 'high',
          title: 'Unhandled Application Exception / DB Failure',
          description: `A critical runtime exception or database failure occurred: "${entry.rawLine.trim().substring(0, 150)}"`,
          evidence: {
            rawLine: entry.rawLine,
            lineNum: entry.lineNum,
          },
          source: 'rule',
        });
      }
    }
  }
  return findings;
}

/**
 * RULE 10 — RESOURCE_EXHAUSTION_WARNING
 * Scans for low disk space, high memory utilization, or hardware warnings.
 */
export function ruleResourceExhaustion(
  entries: LogEntry[],
  sessionId: string = ''
): Omit<Finding, 'id' | 'createdAt'>[] {
  const findings: Omit<Finding, 'id' | 'createdAt'>[] = [];
  const seenMessages = new Set<string>();

  for (const entry of entries) {
    const rawLower = entry.rawLine.toLowerCase();
    if (
      rawLower.includes('high memory usage') ||
      rawLower.includes('disk space running low') ||
      rawLower.includes('low memory') ||
      rawLower.includes('disk space low')
    ) {
      if (!seenMessages.has(entry.rawLine)) {
        seenMessages.add(entry.rawLine);
        findings.push({
          sessionId,
          type: 'resource_exhaustion_warning',
          severity: 'medium',
          title: 'System Resource Exhaustion Alert',
          description: `System resource warning or capacity limit reached: "${entry.rawLine.trim().substring(0, 150)}"`,
          evidence: {
            rawLine: entry.rawLine,
            lineNum: entry.lineNum,
          },
          source: 'rule',
        });
      }
    }
  }
  return findings;
}

/**
 * Orchestrator that applies all pure rule checks to standard log entries,
 * calling insertFinding() for each result in a single Promise.all batch.
 */
export async function runRules(
  sessionId: string,
  entries: LogEntry[]
): Promise<Finding[]> {
  console.log(`Running rules engine for session ${sessionId} across ${entries.length} log entries...`);

  const pendingFindings: Omit<Finding, 'id' | 'createdAt'>[] = [];

  pendingFindings.push(...ruleBruteForceSsh(entries, sessionId));
  pendingFindings.push(...ruleBruteForceWeb(entries, sessionId));
  pendingFindings.push(...rulePortScan(entries, sessionId));
  pendingFindings.push(...rulePrivilegeEscalation(entries, sessionId));
  pendingFindings.push(...ruleOffHoursAccess(entries, sessionId));
  pendingFindings.push(...ruleSoapApiFault(entries, sessionId));
  pendingFindings.push(...ruleRateLimitAlert(entries, sessionId));
  pendingFindings.push(...ruleSocketBindFailure(entries, sessionId));
  pendingFindings.push(...ruleAppCriticalException(entries, sessionId));
  pendingFindings.push(...ruleResourceExhaustion(entries, sessionId));

  console.log(`Rules engine processed. Generated ${pendingFindings.length} rule findings.`);

  // Insert all mapped findings concurrently in a single batch
  const insertedFindings = await Promise.all(
    pendingFindings.map(finding => insertFinding(finding))
  );

  return insertedFindings;
}

/**
 * Backward compatibility wrapper to ensure background job worker functions compile without issues.
 */
export async function runRuleDetection(
  sessionId: string,
  entries: LogEntry[]
): Promise<void> {
  await runRules(sessionId, entries);
}
