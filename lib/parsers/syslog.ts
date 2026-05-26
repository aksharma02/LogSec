import crypto from 'crypto';
import { LogEntry, LogEntrySchema } from '@/types';

// Regex for RFC 5424 format
// Example: <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8
const RFC5424_REGEX = /^<(?<pri>\d+)>(?<version>\d+)\s+(?<ts>\S+)\s+(?<host>\S+)\s+(?<app>\S+)\s+(?<pid>\S+)\s+(?<msgid>\S+)\s+(?<sd>\[.+?\]|-)(?:\s+(?<msg>.*))?$/;

// Regex for RFC 3164 (BSD) format
// Example: <34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for lonvick on /dev/pts/8
const RFC3164_REGEX = /^(?:<(?<pri>\d+)>)?(?<ts>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<app>[^\[:]+)(?:\[(?<pid>\d+)\])?:\s*(?<msg>.*)$/;

function parseSyslogDate(dateStr: string): Date | null {
  try {
    // If it's ISO format (RFC 5424)
    if (dateStr.includes('-') && dateStr.includes('T')) {
      const parsed = new Date(dateStr);
      return isNaN(parsed.getTime()) ? null : parsed;
    }
    
    // BSD style (RFC 3164) e.g., "Oct 11 22:14:15"
    // Since there's no year, we assume the current year
    const currentYear = new Date().getFullYear();
    const parsed = new Date(`${dateStr} ${currentYear}`);
    return isNaN(parsed.getTime()) ? null : parsed;
  } catch {
    return null;
  }
}

export function parseSyslog(
  line: string,
  sessionId: string = '',
  lineNum: number = 1
): LogEntry {
  const entryId = crypto.randomUUID();
  let ts: Date | null = null;
  let ip: string | null = null;
  let userName: string | null = null;
  let action: string | null = null;
  let resource: string | null = null;
  let statusCode: number | null = null;
  let parseError: string | null = null;

  try {
    const trimmedLine = line.trim();
    let match = trimmedLine.match(RFC5424_REGEX);
    let app: string | null = null;
    let msg: string = '';

    if (match && match.groups) {
      const { ts: tsStr, app: appStr, msg: msgStr } = match.groups;
      ts = parseSyslogDate(tsStr);
      app = appStr !== '-' ? appStr : null;
      msg = msgStr || '';
    } else {
      match = trimmedLine.match(RFC3164_REGEX);
      if (match && match.groups) {
        const { ts: tsStr, app: appStr, msg: msgStr } = match.groups;
        ts = parseSyslogDate(tsStr);
        app = appStr ? appStr.trim() : null;
        msg = msgStr || '';
      } else {
        throw new Error('Line does not match RFC 5424 or RFC 3164 syslog formats');
      }
    }

    // Extract IP address from message body
    const ipMatch = msg.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    if (ipMatch) {
      ip = ipMatch[0];
    }

    // Extract username (intelligent heuristics)
    // Matches: "for invalid user admin", "for user admin", "for admin", "user=admin", "username=admin"
    const userMatch = msg.match(/(?:for invalid user|for user|for|user=|username=)\s*["']?([a-zA-Z0-9_\-\.]+)/i);
    if (userMatch) {
      userName = userMatch[1];
    }

    // Extract Action
    const msgLower = msg.toLowerCase();
    if (
      msgLower.includes('failed') ||
      msgLower.includes('failure') ||
      msgLower.includes('error') ||
      msgLower.includes('kill') ||
      msgLower.includes('out of memory') ||
      msgLower.includes('oom')
    ) {
      action = app ? `${app}_failed` : 'failed';
    } else if (msgLower.includes('accepted') || msgLower.includes('success')) {
      action = app ? `${app}_success` : 'success';
    } else {
      action = app || 'event';
    }

    // Extract Resource
    // Matches standard filesystem paths
    const pathMatch = msg.match(/(?:^|\s)(\/[a-zA-Z0-9_\-\.\/]+)/);
    if (pathMatch) {
      resource = pathMatch[1];
    } else {
      resource = app;
    }

    // Extract Status/Exit Code if present
    const codeMatch = msg.match(/(?:status|exit|code)=(\d+)/i);
    if (codeMatch) {
      statusCode = parseInt(codeMatch[1], 10);
    }
  } catch (err: any) {
    parseError = err.message || String(err);
  }

  const result: LogEntry = {
    id: entryId,
    sessionId,
    lineNum,
    ts,
    ip,
    userName,
    action,
    resource,
    statusCode,
    rawLine: line,
    format: 'syslog',
    parseError,
  };

  // Validate the parsed entry against our Zod schema
  const validation = LogEntrySchema.safeParse(result);
  if (!validation.success) {
    result.parseError = result.parseError 
      ? `${result.parseError}; Zod: ${validation.error.message}`
      : `Zod: ${validation.error.message}`;
  }

  return result;
}
