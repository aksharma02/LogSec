import { query } from './client';
import { QaHistory } from '@/types';

/**
 * Maps raw database Q&A rows into typed QaHistory entities.
 */
function mapRowToQaHistory(row: any): QaHistory {
  return {
    id: row.id,
    sessionId: row.session_id,
    question: row.question,
    answer: row.answer, // Node-pg automatically parses JSONB as standard objects
    createdAt: new Date(row.created_at),
  };
}

/**
 * Inserts a new Q&A interaction into the qa_history archiving table.
 */
export async function insertQaHistory(
  sessionId: string,
  question: string,
  answer: any
): Promise<QaHistory> {
  const sql = `
    INSERT INTO qa_history (session_id, question, answer)
    VALUES ($1, $2, $3)
    RETURNING *
  `;
  const res = await query(sql, [
    sessionId,
    question,
    answer ? JSON.stringify(answer) : null,
  ]);
  return mapRowToQaHistory(res.rows[0]);
}

/**
 * Retrieves all previous Q&A conversation exchanges for a session sorted chronologically.
 */
export async function getQaHistoryBySession(sessionId: string): Promise<QaHistory[]> {
  const sql = `
    SELECT * FROM qa_history
    WHERE session_id = $1
    ORDER BY created_at ASC
  `;
  const res = await query(sql, [sessionId]);
  return res.rows.map(mapRowToQaHistory);
}
