import {
  parseSyslog,
  parseApache,
  parseCloudTrail,
  parseGeneric,
  detectFormat,
  parseLogFile,
} from '@/lib/parsers';

describe('Log Sec Analyzer - Log Parsers Unit Tests', () => {
  const sessionId = 'test-session-123';

  describe('Syslog Parser (RFC 5424 / RFC 3164 BSD)', () => {
    test('should parse RFC 3164 (BSD) syslog successfully', () => {
      const line = "<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for lonvick on /dev/pts/8";
      const entry = parseSyslog(line, sessionId, 1);

      expect(entry.format).toBe('syslog');
      expect(entry.sessionId).toBe(sessionId);
      expect(entry.lineNum).toBe(1);
      expect(entry.userName).toBe('lonvick');
      expect(entry.action).toBe('su_failed');
      expect(entry.resource).toBe('/dev/pts/8');
      expect(entry.ip).toBeNull();
      expect(entry.statusCode).toBeNull();
      expect(entry.parseError).toBeNull();
      expect(entry.ts).toBeInstanceOf(Date);
      expect(entry.ts?.getMonth()).toBe(9); // Oct is 9 (0-indexed)
      expect(entry.ts?.getDate()).toBe(11);
    });

    test('should parse RFC 5424 syslog successfully with IP', () => {
      const line = '<13>1 2026-05-26T15:58:55.123Z host1 sshd 12345 ID47 - Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2';
      const entry = parseSyslog(line, sessionId, 2);

      expect(entry.format).toBe('syslog');
      expect(entry.userName).toBe('admin');
      expect(entry.ip).toBe('192.168.1.100');
      expect(entry.action).toBe('sshd_failed');
      expect(entry.resource).toBe('sshd');
      expect(entry.parseError).toBeNull();
      expect(entry.ts?.toISOString()).toBe('2026-05-26T15:58:55.123Z');
    });

    test('should parse BSD style syslog without PRI header and with exit code', () => {
      const line = 'May 26 16:00:00 web-server kernel: [123.456] status=0 Out of memory: Kill process 999 (node)';
      const entry = parseSyslog(line, sessionId, 3);

      expect(entry.format).toBe('syslog');
      expect(entry.action).toBe('kernel_failed');
      expect(entry.resource).toBe('kernel');
      expect(entry.statusCode).toBe(0);
      expect(entry.parseError).toBeNull();
    });

    test('should handle completely malformed syslog gracefully', () => {
      const malformed = 'Not a syslog line at all';
      const entry = parseSyslog(malformed, sessionId, 4);

      expect(entry.format).toBe('syslog');
      expect(entry.parseError).not.toBeNull();
      expect(entry.parseError).toContain('does not match RFC 5424 or RFC 3164');
    });
  });

  describe('Apache Combined Access Log Parser', () => {
    test('should parse standard Apache Combined Log successfully', () => {
      const line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326';
      const entry = parseApache(line, sessionId, 1);

      expect(entry.format).toBe('apache');
      expect(entry.ip).toBe('127.0.0.1');
      expect(entry.userName).toBe('frank');
      expect(entry.action).toBe('GET');
      expect(entry.resource).toBe('/apache_pb.gif');
      expect(entry.statusCode).toBe(200);
      expect(entry.parseError).toBeNull();
      expect(entry.ts).toBeInstanceOf(Date);
      expect(entry.ts?.toISOString()).toBe('2000-10-10T20:55:36.000Z'); // 13:55:36 -0700 is 20:55:36 UTC
    });

    test('should parse Apache Combined Log with no username and POST request with positive offset', () => {
      const line = '192.168.1.50 - - [26/May/2026:15:58:55 +0530] "POST /api/v1/login HTTP/1.1" 401 50 "https://example.com/" "Mozilla/5.0"';
      const entry = parseApache(line, sessionId, 2);

      expect(entry.format).toBe('apache');
      expect(entry.ip).toBe('192.168.1.50');
      expect(entry.userName).toBeNull();
      expect(entry.action).toBe('POST');
      expect(entry.resource).toBe('/api/v1/login');
      expect(entry.statusCode).toBe(401);
      expect(entry.parseError).toBeNull();
      expect(entry.ts?.toISOString()).toBe('2026-05-26T10:28:55.000Z'); // 15:58:55 +0530 is 10:28:55 UTC
    });

    test('should parse Apache Combined Log with local IPv6 and DELETE request', () => {
      const line = '::1 - admin [26/May/2026:16:00:00 -0400] "DELETE /users/42 HTTP/2.0" 204 0';
      const entry = parseApache(line, sessionId, 3);

      expect(entry.format).toBe('apache');
      expect(entry.ip).toBe('::1');
      expect(entry.userName).toBe('admin');
      expect(entry.action).toBe('DELETE');
      expect(entry.resource).toBe('/users/42');
      expect(entry.statusCode).toBe(204);
      expect(entry.parseError).toBeNull();
    });

    test('should handle malformed Apache combined log gracefully', () => {
      const malformed = '127.0.0.1 - - broken-date "GET /" 200';
      const entry = parseApache(malformed, sessionId, 4);

      expect(entry.format).toBe('apache');
      expect(entry.parseError).not.toBeNull();
    });
  });

  describe('AWS CloudTrail JSON Event Parser', () => {
    test('should parse standard ConsoleLogin event', () => {
      const line = '{"eventTime": "2026-05-26T15:58:55Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "sourceIPAddress": "192.0.2.1", "userIdentity": {"userName": "Alice"}, "eventID": "123"}';
      const entry = parseCloudTrail(line, sessionId, 1);

      expect(entry.format).toBe('cloudtrail');
      expect(entry.ip).toBe('192.0.2.1');
      expect(entry.userName).toBe('Alice');
      expect(entry.action).toBe('ConsoleLogin');
      expect(entry.resource).toBe('signin.amazonaws.com');
      expect(entry.statusCode).toBe(200);
      expect(entry.parseError).toBeNull();
      expect(entry.ts?.toISOString()).toBe('2026-05-26T15:58:55.000Z');
    });

    test('should parse AccessDenied event and map to status 403', () => {
      const line = '{"eventTime": "2026-05-26T15:59:00Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "sourceIPAddress": "203.0.113.12", "userIdentity": {"arn": "arn:aws:iam::123:user/Bob"}, "errorCode": "AccessDenied"},';
      const entry = parseCloudTrail(line, sessionId, 2);

      expect(entry.format).toBe('cloudtrail');
      expect(entry.ip).toBe('203.0.113.12');
      expect(entry.userName).toBe('arn:aws:iam::123:user/Bob');
      expect(entry.action).toBe('GetObject');
      expect(entry.resource).toBe('s3.amazonaws.com');
      expect(entry.statusCode).toBe(403);
      expect(entry.parseError).toBeNull();
    });

    test('should parse assumed role event', () => {
      const line = '{"eventTime": "2026-05-26T16:01:23Z", "eventSource": "ec2.amazonaws.com", "eventName": "RunInstances", "sourceIPAddress": "172.31.0.5", "userIdentity": {"type": "AssumedRole", "principalId": "AROA:session", "userName": "RoleSession"}}';
      const entry = parseCloudTrail(line, sessionId, 3);

      expect(entry.format).toBe('cloudtrail');
      expect(entry.ip).toBe('172.31.0.5');
      expect(entry.userName).toBe('RoleSession');
      expect(entry.action).toBe('RunInstances');
      expect(entry.resource).toBe('ec2.amazonaws.com');
      expect(entry.statusCode).toBe(200);
      expect(entry.parseError).toBeNull();
    });

    test('should handle invalid JSON in CloudTrail gracefully', () => {
      const line = '{"eventTime": "2026-05-26T15:58:55Z", "eventSource": "signin.amazonaws.com",';
      const entry = parseCloudTrail(line, sessionId, 4);

      expect(entry.format).toBe('cloudtrail');
      expect(entry.parseError).not.toBeNull();
    });
  });

  describe('Generic Key-Value Parser', () => {
    test('should parse standard KV structure', () => {
      const line = 'time="2026-05-26T15:58:55Z" ip=10.0.0.1 user=admin action=login status=200 msg="Login success"';
      const entry = parseGeneric(line, sessionId, 1);

      expect(entry.format).toBe('generic');
      expect(entry.ip).toBe('10.0.0.1');
      expect(entry.userName).toBe('admin');
      expect(entry.action).toBe('login');
      expect(entry.statusCode).toBe(200);
      expect(entry.parseError).toBeNull();
      expect(entry.ts?.toISOString()).toBe('2026-05-26T15:58:55.000Z');
    });

    test('should parse alternate key names and epoch timestamp milliseconds', () => {
      const line = 'ts=1779811135000 client_ip=192.168.10.5 email="dev@company.com" event="file_upload" target="/shared/report.pdf" code=210';
      const entry = parseGeneric(line, sessionId, 2);

      expect(entry.format).toBe('generic');
      expect(entry.ip).toBe('192.168.10.5');
      expect(entry.userName).toBe('dev@company.com');
      expect(entry.action).toBe('file_upload');
      expect(entry.resource).toBe('/shared/report.pdf');
      expect(entry.statusCode).toBe(210);
      expect(entry.parseError).toBeNull();
      expect(entry.ts).toBeInstanceOf(Date);
      expect(entry.ts?.getTime()).toBe(1779811135000);
    });

    test('should parse fallback flat text line', () => {
      const line = 'Error occurred on host 192.168.1.100 while processing user transactions';
      const entry = parseGeneric(line, sessionId, 3);

      expect(entry.format).toBe('generic');
      expect(entry.ip).toBe('192.168.1.100');
      expect(entry.action).toBe('error');
      expect(entry.userName).toBeNull();
      expect(entry.resource).toBeNull();
      expect(entry.parseError).toBeNull();
    });
  });

  describe('Integration & Format Sniffing', () => {
    test('should sniff correct log formats', () => {
      const syslogContent = '<34>Oct 11 22:14:15 mymachine su[1234]: message\n<34>Oct 11 22:14:16 mymachine sshd[123]: failed';
      const apacheContent = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 1234';
      const cloudtrailContent = '{"eventTime": "2026-05-26T15:58:55Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject"}';
      const genericContent = 'time="2026-05-26T15:58:55Z" ip=1.1.1.1 status=500';

      expect(detectFormat(syslogContent)).toBe('syslog');
      expect(detectFormat(apacheContent)).toBe('apache');
      expect(detectFormat(cloudtrailContent)).toBe('cloudtrail');
      expect(detectFormat(genericContent)).toBe('generic');
    });

    test('should parse files cleanly using parseLogFile orchestrator', () => {
      const fileContent = `
        127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
        192.168.1.50 - - [26/May/2026:15:58:55 +0530] "POST /api/v1/login HTTP/1.1" 401 50
      `;
      const entries = parseLogFile(fileContent, sessionId);

      expect(entries).toHaveLength(2);
      expect(entries[0].format).toBe('apache');
      expect(entries[0].userName).toBe('frank');
      expect(entries[0].statusCode).toBe(200);

      expect(entries[1].format).toBe('apache');
      expect(entries[1].userName).toBeNull();
      expect(entries[1].statusCode).toBe(401);
    });
  });
});
