import { query } from './client';
import { LogEntry, DbLogEntry } from '@/types';

/**
 * Helper to translate raw DB rows to strongly-typed DbLogEntry entities.
 */
function mapRowToDbLogEntry(row: any): DbLogEntry {
  return {
    id: row.id,
    sessionId: row.session_id,
    lineNum: row.line_num,
    ts: row.ts ? new Date(row.ts) : null,
    ip: row.ip,
    userName: row.user_name,
    action: row.action,
    resource: row.resource,
    statusCode: row.status_code,
    rawLine: row.raw_line,
    format: row.format,
    parseError: row.parse_error,
    createdAt: new Date(row.created_at),
  };
}

/**
 * Inserts a batch of log entries efficiently using a single dynamic multi-row SQL INSERT query.
 * All insertion values are parameterized to ensure 100% security against SQL injections.
 */
export async function insertLogEntries(entries: LogEntry[]): Promise<void> {
  if (entries.length === 0) return;

  const columns = [
    'id',
    'session_id',
    'line_num',
    'ts',
    'ip',
    'user_name',
    'action',
    'resource',
    'status_code',
    'raw_line',
    'format',
    'parse_error',
  ];

  const values: any[] = [];
  const valuePlaceholders: string[] = [];
  let placeholderIndex = 1;

  for (const entry of entries) {
    const rowPlaceholders: string[] = [];

    // Push the values in the exact DDL schema columns order
    values.push(entry.id);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.sessionId);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.lineNum);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.ts);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.ip);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.userName);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.action);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.resource);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.statusCode);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.rawLine);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.format);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    values.push(entry.parseError);
    rowPlaceholders.push(`$${placeholderIndex++}`);

    valuePlaceholders.push(`(${rowPlaceholders.join(', ')})`);
  }

  const sql = `
    INSERT INTO log_entries (${columns.join(', ')})
    VALUES ${valuePlaceholders.join(', ')}
  `;

  await query(sql, values);
}

/**
 * Retrieves all log entries belonging to a given session, ordered sequentially by line_num.
 */
export async function getEntriesBySession(sessionId: string): Promise<DbLogEntry[]> {
  const sql = `
    SELECT * FROM log_entries
    WHERE session_id = $1
    ORDER BY line_num ASC
  `;
  const res = await query(sql, [sessionId]);
  return res.rows.map(mapRowToDbLogEntry);
}
