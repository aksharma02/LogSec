import { parseSyslog } from './syslog';
import { parseApache } from './apache';
import { parseCloudTrail } from './cloudtrail';
import { parseGeneric } from './generic';
import { LogEntry } from '@/types';

export { parseSyslog } from './syslog';
export { parseApache } from './apache';
export { parseCloudTrail } from './cloudtrail';
export { parseGeneric } from './generic';

/**
 * Sniffs the log format by scoring the first 5 non-empty lines of content.
 * Returns 'syslog', 'apache', 'cloudtrail', or fallback 'generic'.
 */
export function detectFormat(content: string): string {
  if (!content) return 'generic';

  const lines = content
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .slice(0, 5);

  if (lines.length === 0) return 'generic';

  const scores = {
    cloudtrail: 0,
    apache: 0,
    syslog: 0,
    generic: 0,
  };

  // Regular expressions for sniffing matching structures
  const RFC5424_REGEX = /^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/;
  const RFC3164_REGEX = /^(?:<(\d+)>)?(?:[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:\s*(.*)$/;
  const APACHE_COMBINED_REGEX = /^(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?$/;
  const KV_REGEX = /([a-zA-Z0-9_\-\.]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+))/g;

  for (const line of lines) {
    // 1. Sniff CloudTrail JSON
    try {
      const cleanLine = line.endsWith(',') ? line.slice(0, -1).trim() : line;
      const parsed = JSON.parse(cleanLine);
      if (parsed && typeof parsed === 'object') {
        if (parsed.eventTime || parsed.eventVersion || parsed.userIdentity || parsed.eventName || parsed.eventSource) {
          scores.cloudtrail += 5;
        } else {
          scores.cloudtrail += 2;
        }
      }
    } catch {}

    // 2. Sniff Apache Combined Access
    if (APACHE_COMBINED_REGEX.test(line)) {
      scores.apache += 5;
    }

    // 3. Sniff Syslog RFC 5424 or BSD
    if (RFC5424_REGEX.test(line) || RFC3164_REGEX.test(line)) {
      scores.syslog += 5;
    }

    // 4. Sniff Generic Key-Value Log
    KV_REGEX.lastIndex = 0;
    const kvMatches = line.match(KV_REGEX);
    if (kvMatches && kvMatches.length >= 2) {
      scores.generic += kvMatches.length;
    }
  }

  let bestFormat = 'generic';
  let highestScore = 0;

  for (const [format, score] of Object.entries(scores)) {
    if (score > highestScore) {
      highestScore = score;
      bestFormat = format;
    }
  }

  return bestFormat;
}

/**
 * Orchestrator that detects the log format of the given content and parses
 * each non-empty line using the detected format parser.
 */
export function parseLogFile(content: string, sessionId: string): LogEntry[] {
  const format = detectFormat(content);
  const lines = content.split(/\r?\n/);
  const entries: LogEntry[] = [];

  let lineNum = 0;
  for (const line of lines) {
    lineNum++;
    if (!line.trim()) continue; // skip blank lines

    let entry: LogEntry;
    if (format === 'syslog') {
      entry = parseSyslog(line, sessionId, lineNum);
    } else if (format === 'apache') {
      entry = parseApache(line, sessionId, lineNum);
    } else if (format === 'cloudtrail') {
      entry = parseCloudTrail(line, sessionId, lineNum);
    } else {
      entry = parseGeneric(line, sessionId, lineNum);
    }
    entries.push(entry);
  }

  return entries;
}
