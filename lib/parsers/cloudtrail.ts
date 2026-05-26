import crypto from 'crypto';
import { LogEntry, LogEntrySchema } from '@/types';

interface CloudTrailIdentity {
  type?: string;
  principalId?: string;
  arn?: string;
  accountId?: string;
  accessKeyId?: string;
  userName?: string;
}

interface CloudTrailEvent {
  eventTime?: string;
  sourceIPAddress?: string;
  userIdentity?: CloudTrailIdentity;
  eventName?: string;
  eventSource?: string;
  errorCode?: string;
  errorMessage?: string;
  [key: string]: any;
}

export function parseCloudTrail(
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
    // If the line has a trailing comma (e.g., from an array of records), clean it
    const cleanLine = trimmedLine.endsWith(',') ? trimmedLine.slice(0, -1).trim() : trimmedLine;
    
    const event: CloudTrailEvent = JSON.parse(cleanLine);

    // Validate standard CloudTrail indicators
    if (!event.eventTime && !event.eventName && !event.eventSource) {
      throw new Error('Parsed JSON does not appear to be an AWS CloudTrail event (missing key fields)');
    }

    // Parse Event Time
    if (event.eventTime) {
      const parsedDate = new Date(event.eventTime);
      ts = isNaN(parsedDate.getTime()) ? null : parsedDate;
    }

    // Set Source IP
    ip = event.sourceIPAddress || null;

    // Resolve User Identity
    if (event.userIdentity) {
      userName = 
        event.userIdentity.userName || 
        event.userIdentity.arn || 
        event.userIdentity.principalId || 
        null;
    }

    // Resolve Action
    action = event.eventName || null;

    // Resolve Resource
    resource = event.eventSource || null;

    // Parse Semantic Status Code based on AWS Error codes
    if (event.errorCode) {
      if (event.errorCode === 'AccessDenied' || event.errorCode === 'UnauthorizedOperation') {
        statusCode = 403;
      } else {
        statusCode = 400;
      }
    } else {
      statusCode = 200;
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
    format: 'cloudtrail',
    parseError,
  };

  // Validate via Zod schema
  const validation = LogEntrySchema.safeParse(result);
  if (!validation.success) {
    result.parseError = result.parseError
      ? `${result.parseError}; Zod: ${validation.error.message}`
      : `Zod: ${validation.error.message}`;
  }

  return result;
}
