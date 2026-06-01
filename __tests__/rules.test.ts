import { LogEntry } from '@/types';
import { 
  ruleBruteForceSsh, 
  rulePrivilegeEscalation,
  ruleSoapApiFault,
  ruleRateLimitAlert,
  ruleSocketBindFailure,
  ruleAppCriticalException,
  ruleResourceExhaustion
} from '@/lib/rules';

describe('Log Sec Analyzer - Rules Engine Threat Signatures Tests', () => {
  const makeMockBaseEntry = (offsetMinutes: number, idx: number): LogEntry => ({
    id: `entry-${idx}`,
    sessionId: 'session-xyz',
    lineNum: idx + 1,
    ts: new Date(Date.UTC(2026, 4, 26, 12, offsetMinutes, 0)),
    ip: '192.168.1.10',
    userName: 'operator',
    action: 'login',
    resource: '/ssh',
    statusCode: null,
    rawLine: 'sshd: Failed password for operator from 192.168.1.10',
    format: 'syslog',
    parseError: null,
  });

  describe('RULE 1 — BRUTE_FORCE_SSH (Sliding Window)', () => {
    test('should emit High finding if IP has > 10 failed SSH logins within a 5-minute window', () => {
      // Create 11 failed entries within 4 minutes (e.g. 1 entry every 20 seconds)
      const entries: LogEntry[] = Array.from({ length: 11 }, (_, idx) => {
        const base = makeMockBaseEntry(0, idx);
        // Space them by 20 seconds
        base.ts = new Date(Date.UTC(2026, 4, 26, 12, 0, idx * 20));
        base.action = 'sshd_failed';
        return base;
      });

      const findings = ruleBruteForceSsh(entries, 'session-xyz');

      expect(findings).toHaveLength(1);
      expect(findings[0].type).toBe('brute_force_ssh');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].evidence.ip).toBe('192.168.1.10');
      expect(findings[0].evidence.count).toBe(11);
      expect(findings[0].evidence.sampleLines).toHaveLength(3);
    });

    test('should NOT emit finding if IP has exactly 10 failures in a 5-minute window', () => {
      const entries: LogEntry[] = Array.from({ length: 10 }, (_, idx) => {
        const base = makeMockBaseEntry(0, idx);
        base.ts = new Date(Date.UTC(2026, 4, 26, 12, 0, idx * 20));
        base.action = 'sshd_failed';
        return base;
      });

      const findings = ruleBruteForceSsh(entries, 'session-xyz');

      expect(findings).toHaveLength(0);
    });

    test('should NOT emit finding if failures are spread out (e.g. 11 failures over 20 minutes)', () => {
      const entries: LogEntry[] = Array.from({ length: 11 }, (_, idx) => {
        const base = makeMockBaseEntry(0, idx);
        // Space them by 2 minutes, so 11 failures spans 20 minutes (no 5-min window has > 10 failures)
        base.ts = new Date(Date.UTC(2026, 4, 26, 12, idx * 2, 0));
        base.action = 'sshd_failed';
        return base;
      });

      const findings = ruleBruteForceSsh(entries, 'session-xyz');

      expect(findings).toHaveLength(0);
    });

    test('should distinguish between different IPs and correctly group them', () => {
      // IP A: 11 failures within 1 minute
      const ipAEntries = Array.from({ length: 11 }, (_, idx) => {
        const base = makeMockBaseEntry(0, idx);
        base.ts = new Date(Date.UTC(2026, 4, 26, 12, 0, idx * 5));
        base.ip = '10.0.0.1';
        base.action = 'sshd_failed';
        return base;
      });

      // IP B: 5 failures within 1 minute
      const ipBEntries = Array.from({ length: 5 }, (_, idx) => {
        const base = makeMockBaseEntry(0, idx + 20);
        base.ts = new Date(Date.UTC(2026, 4, 26, 12, 0, idx * 5));
        base.ip = '10.0.0.2';
        base.action = 'sshd_failed';
        return base;
      });

      const findings = ruleBruteForceSsh([...ipAEntries, ...ipBEntries], 'session-xyz');

      // Only IP A exceeds the > 10 failures threshold
      expect(findings).toHaveLength(1);
      expect(findings[0].evidence.ip).toBe('10.0.0.1');
      expect(findings[0].evidence.count).toBe(11);
    });
  });

  describe('RULE 4 — PRIVILEGE_ESCALATION (Trigger and Duplicates)', () => {
    test('should emit Medium finding per unique user+action combo', () => {
      const entries: LogEntry[] = [
        {
          id: 'e1',
          sessionId: 'session-xyz',
          lineNum: 1,
          ts: new Date(),
          ip: '10.0.0.1',
          userName: 'dev1',
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'dev1 executed command: sudo apt update',
          format: 'generic',
          parseError: null,
        },
        {
          id: 'e2',
          sessionId: 'session-xyz',
          lineNum: 2,
          ts: new Date(),
          ip: '10.0.0.1',
          userName: 'dev1',
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'dev1 executed command: su - root',
          format: 'generic',
          parseError: null,
        },
        {
          id: 'e3',
          sessionId: 'session-xyz',
          lineNum: 3,
          ts: new Date(),
          ip: '10.0.0.1',
          userName: 'dev2',
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'dev2 executed command: sudo apt upgrade',
          format: 'generic',
          parseError: null,
        },
      ];

      const findings = rulePrivilegeEscalation(entries, 'session-xyz');

      // unique combos: dev1:sudo, dev1:su -, dev2:sudo. Total 3 findings!
      expect(findings).toHaveLength(3);
      
      const targets = findings.map(f => `${f.evidence.userName}:${f.evidence.triggeredPattern}`);
      expect(targets).toContain('dev1:sudo');
      expect(targets).toContain('dev1:su -');
      expect(targets).toContain('dev2:sudo');

      expect(findings[0].severity).toBe('medium');
      expect(findings[0].type).toBe('privilege_escalation');
    });

    test('should eliminate duplicates if same user executes same matching command multiple times', () => {
      const entries: LogEntry[] = [
        {
          id: 'e1',
          sessionId: 'session-xyz',
          lineNum: 1,
          ts: new Date(),
          ip: '10.0.0.1',
          userName: 'operator',
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'operator executed: sudo usermod -aG sudo guest',
          format: 'generic',
          parseError: null,
        },
        {
          id: 'e2',
          sessionId: 'session-xyz',
          lineNum: 2,
          ts: new Date(),
          ip: '10.0.0.1',
          userName: 'operator',
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'operator executed: sudo passwd operator',
          format: 'generic',
          parseError: null,
        },
      ];

      const findings = rulePrivilegeEscalation(entries, 'session-xyz');

      // Operator executed sudo twice. Both match 'sudo' (even though the command also contains usermod and passwd, the patterns array evaluates sudo first. Seen combos contains operator:sudo).
      // So only 1 finding is emitted!
      expect(findings).toHaveLength(1);
      expect(findings[0].evidence.userName).toBe('operator');
      expect(findings[0].evidence.triggeredPattern).toBe('sudo');
    });
  });

  describe('RULE 6 — SOAP_API_FAULT', () => {
    test('should detect SoapFaultException and SBL-ODU errors', () => {
      const entries: LogEntry[] = [
        {
          id: 'e1',
          sessionId: 'session-xyz',
          lineNum: 1,
          ts: new Date(),
          ip: null,
          userName: null,
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'Experienced SoapFaultException: Error sending the SOAP request to web service: SBL-ODU-01005',
          format: 'generic',
          parseError: null,
        }
      ];

      const findings = ruleSoapApiFault(entries, 'session-xyz');
      expect(findings).toHaveLength(1);
      expect(findings[0].type).toBe('soap_api_fault');
      expect(findings[0].severity).toBe('medium');
    });
  });

  describe('RULE 7 — RATE_LIMIT_EXCEEDED', () => {
    test('should detect rate limit errors', () => {
      const entries: LogEntry[] = [
        {
          id: 'e1',
          sessionId: 'session-xyz',
          lineNum: 1,
          ts: new Date(),
          ip: null,
          userName: null,
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'Experienced SOAP Request Rate Limit error while sending the validation request.',
          format: 'generic',
          parseError: null,
        }
      ];

      const findings = ruleRateLimitAlert(entries, 'session-xyz');
      expect(findings).toHaveLength(1);
      expect(findings[0].type).toBe('rate_limit_exceeded');
      expect(findings[0].severity).toBe('medium');
    });
  });

  describe('RULE 8 — SOCKET_BIND_FAILURE', () => {
    test('should detect port binding collision errors', () => {
      const entries: LogEntry[] = [
        {
          id: 'e1',
          sessionId: 'session-xyz',
          lineNum: 1,
          ts: new Date(),
          ip: null,
          userName: null,
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'Failed to bind socket on port 8080 - Address already in use',
          format: 'generic',
          parseError: null,
        }
      ];

      const findings = ruleSocketBindFailure(entries, 'session-xyz');
      expect(findings).toHaveLength(1);
      expect(findings[0].type).toBe('socket_bind_failure');
      expect(findings[0].severity).toBe('high');
    });
  });

  describe('RULE 9 — APPLICATION_CRITICAL_EXCEPTION', () => {
    test('should detect null reference and DB connection errors', () => {
      const entries: LogEntry[] = [
        {
          id: 'e1',
          sessionId: 'session-xyz',
          lineNum: 1,
          ts: new Date(),
          ip: null,
          userName: null,
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'Database connection failed - Timeout occurred',
          format: 'generic',
          parseError: null,
        },
        {
          id: 'e2',
          sessionId: 'session-xyz',
          lineNum: 2,
          ts: new Date(),
          ip: null,
          userName: null,
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'Unhandled exception in API request: NullReferenceException',
          format: 'generic',
          parseError: null,
        }
      ];

      const findings = ruleAppCriticalException(entries, 'session-xyz');
      expect(findings).toHaveLength(2);
      expect(findings[0].type).toBe('app_critical_exception');
      expect(findings[0].severity).toBe('high');
    });
  });

  describe('RULE 10 — RESOURCE_EXHAUSTION_WARNING', () => {
    test('should detect resource issues like low disk space and high memory', () => {
      const entries: LogEntry[] = [
        {
          id: 'e1',
          sessionId: 'session-xyz',
          lineNum: 1,
          ts: new Date(),
          ip: null,
          userName: null,
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'High memory usage detected: 85% utilized',
          format: 'generic',
          parseError: null,
        },
        {
          id: 'e2',
          sessionId: 'session-xyz',
          lineNum: 2,
          ts: new Date(),
          ip: null,
          userName: null,
          action: null,
          resource: null,
          statusCode: null,
          rawLine: 'Disk space running low: 5% remaining',
          format: 'generic',
          parseError: null,
        }
      ];

      const findings = ruleResourceExhaustion(entries, 'session-xyz');
      expect(findings).toHaveLength(2);
      expect(findings[0].type).toBe('resource_exhaustion_warning');
      expect(findings[0].severity).toBe('medium');
    });
  });
});
