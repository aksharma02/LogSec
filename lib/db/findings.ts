import { query } from './client';
import { Finding } from '@/types';

/**
 * Helper to map raw database row attributes to typed Finding entities.
 */
function mapRowToFinding(row: any): Finding {
  return {
    id: row.id,
    sessionId: row.session_id,
    type: row.type,
    severity: row.severity as Finding['severity'],
    title: row.title,
    description: row.description,
    evidence: row.evidence, // Automatically parsed by the pg client as JSON/Object
    source: row.source as Finding['source'],
    createdAt: new Date(row.created_at),
  };
}

/**
 * Inserts a new security finding/anomaly alert for a session.
 */
export async function insertFinding(
  finding: Omit<Finding, 'id' | 'createdAt'>
): Promise<Finding> {
  const sql = `
    INSERT INTO findings (session_id, type, severity, title, description, evidence, source)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *
  `;
  const res = await query(sql, [
    finding.sessionId,
    finding.type,
    finding.severity,
    finding.title,
    finding.description,
    finding.evidence ? JSON.stringify(finding.evidence) : null,
    finding.source || 'rule',
  ]);
  return mapRowToFinding(res.rows[0]);
}

/**
 * Retrieves all security findings belonging to a given session, sorted chronologically.
 */
export async function getFindingsBySession(sessionId: string): Promise<Finding[]> {
  const sql = `
    SELECT * FROM findings
    WHERE session_id = $1
    ORDER BY created_at ASC
  `;
  const res = await query(sql, [sessionId]);
  return res.rows.map(mapRowToFinding);
}
