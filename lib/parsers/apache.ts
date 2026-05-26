import crypto from 'crypto';
import { LogEntry, LogEntrySchema } from '@/types';

// Regex for Apache/Nginx Combined Log Format
// Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
// Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/referer_html" "Mozilla/4.08 [en]"
export const APACHE_COMBINED_REGEX = /^(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?$/;

function parseApacheDate(dateStr: string): Date | null {
  try {
    // Expected: "10/Oct/2000:13:55:36 -0700"
    const match = dateStr.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/);
    if (!match) return null;
    
    const [_, day, month, year, hour, minute, second, offset] = match;
    
    const months: Record<string, number> = {
      Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
      Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
    };
    
    const monthIdx = months[month];
    if (monthIdx === undefined) return null;
    
    // Convert offset "+0530" to "+05:30"
    const offsetFormatted = offset.slice(0, 3) + ':' + offset.slice(3);
    const monthNumStr = String(monthIdx + 1).padStart(2, '0');
    const dayNumStr = day.padStart(2, '0');
    
    const isoStr = `${year}-${monthNumStr}-${dayNumStr}T${hour}:${minute}:${second}${offsetFormatted}`;
    const parsed = new Date(isoStr);
    return isNaN(parsed.getTime()) ? null : parsed;
  } catch {
    return null;
  }
}

export function parseApache(
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
    const match = trimmedLine.match(APACHE_COMBINED_REGEX);
    if (!match) {
      throw new Error('Line does not match Apache/Nginx combined log format');
    }

    const [_, ipStr, ident, userStr, tsStr, requestStr, statusStr, bytesStr] = match;

    // Set IP if not dash
    ip = ipStr !== '-' ? ipStr : null;

    // Set username if not dash
    userName = userStr !== '-' ? userStr : null;

    // Parse date
    ts = parseApacheDate(tsStr);

    // Parse request e.g., "GET /apache_pb.gif HTTP/1.0"
    if (requestStr) {
      const parts = requestStr.split(/\s+/);
      if (parts.length > 0) {
        action = parts[0]; // Method e.g., "GET"
      }
      if (parts.length > 1) {
        resource = parts[1]; // URL/Path e.g., "/apache_pb.gif"
      }
    }

    // Parse status code
    if (statusStr) {
      statusCode = parseInt(statusStr, 10);
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
    format: 'apache',
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
