import crypto from 'crypto';
import { LogEntry, LogEntrySchema } from '@/types';

// Regex to capture key=value, key="value", or key='value'
const KV_REGEX = /([a-zA-Z0-9_\-\.]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+))/g;

function parseGenericDate(dateStr: string): Date | null {
  try {
    // If it's a Unix timestamp (digits only)
    if (/^\d+$/.test(dateStr)) {
      const val = parseInt(dateStr, 10);
      if (dateStr.length === 10) {
        // Epoch seconds
        return new Date(val * 1000);
      } else if (dateStr.length === 13) {
        // Epoch milliseconds
        return new Date(val);
      }
    }
    const parsed = new Date(dateStr);
    return isNaN(parsed.getTime()) ? null : parsed;
  } catch {
    return null;
  }
}

export function parseGeneric(
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
    const kvMap: Record<string, string> = {};
    let match;
    
    // Reset regex index
    KV_REGEX.lastIndex = 0;
    
    while ((match = KV_REGEX.exec(line)) !== null) {
      const key = match[1].toLowerCase();
      const val = match[2] !== undefined ? match[2] : (match[3] !== undefined ? match[3] : match[4]);
      kvMap[key] = val;
    }

    const keysCount = Object.keys(kvMap).length;

    if (keysCount > 0) {
      // 1. Resolve Timestamp
      const tsKey = ['timestamp', 'time', 'ts', 'date', 'datetime', 'eventtime'].find(k => kvMap[k] !== undefined);
      if (tsKey) {
        ts = parseGenericDate(kvMap[tsKey]);
      }

      // 2. Resolve IP
      const ipKey = ['ip', 'ip_address', 'client_ip', 'sourceipaddress', 'src', 'src_ip', 'client'].find(k => kvMap[k] !== undefined);
      if (ipKey) {
        ip = kvMap[ipKey];
      }

      // 3. Resolve Username
      const userKey = ['username', 'user', 'user_name', 'email', 'usr', 'username'].find(k => kvMap[k] !== undefined);
      if (userKey) {
        userName = kvMap[userKey];
      }

      // 4. Resolve Action
      const actionKey = ['action', 'event', 'method', 'event_name', 'eventname'].find(k => kvMap[k] !== undefined);
      if (actionKey) {
        action = kvMap[actionKey];
      } else {
        const msgKey = ['msg', 'message', 'info'].find(k => kvMap[k] !== undefined);
        if (msgKey) {
          action = kvMap[msgKey];
        }
      }

      // 5. Resolve Resource
      const resKey = ['resource', 'path', 'url', 'uri', 'file', 'target', 'eventsource'].find(k => kvMap[k] !== undefined);
      if (resKey) {
        resource = kvMap[resKey];
      }

      // 6. Resolve Status Code
      const codeKey = ['status', 'statuscode', 'status_code', 'code'].find(k => kvMap[k] !== undefined);
      if (codeKey) {
        const parsedCode = parseInt(kvMap[codeKey], 10);
        statusCode = isNaN(parsedCode) ? null : parsedCode;
      }
    } else {
      // Fallback: If no key-value pairs are found, parse the line as unstructured text.
      // Search for any IPv4 address in the text
      const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      if (ipMatch) {
        ip = ipMatch[0];
      }
      
      // Look for standard action keywords
      const lower = line.toLowerCase();
      if (lower.includes('fail') || lower.includes('error')) {
        action = 'error';
      } else if (lower.includes('success') || lower.includes('login') || lower.includes('connect')) {
        action = 'info';
      } else {
        action = 'log';
      }
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
    format: 'generic',
    parseError,
  };

  // Validate via Zod
  const validation = LogEntrySchema.safeParse(result);
  if (!validation.success) {
    result.parseError = result.parseError
      ? `${result.parseError}; Zod: ${validation.error.message}`
      : `Zod: ${validation.error.message}`;
  }

  return result;
}
