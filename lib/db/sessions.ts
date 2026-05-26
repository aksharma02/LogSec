import { query } from './client';
import { Session } from '@/types';

/**
 * Maps a raw PostgreSQL row to a typed Session object.
 */
function mapRowToSession(row: any): Session {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    logSource: row.log_source,
    status: row.status as Session['status'],
    logCount: row.log_count || 0,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
  };
}

/**
 * Creates a new log parsing session in the database.
 */
export async function createSession(
  userId: string,
  name: string,
  logSource: string
): Promise<Session> {
  const sql = `
    INSERT INTO sessions (user_id, name, log_source, status)
    VALUES ($1, $2, $3, 'pending')
    RETURNING *
  `;
  const res = await query(sql, [userId, name, logSource]);
  return mapRowToSession(res.rows[0]);
}

/**
 * Updates the status and optional log count of a session.
 */
export async function updateSessionStatus(
  id: string,
  status: Session['status'],
  logCount?: number
): Promise<Session> {
  let sql: string;
  let params: any[];

  if (logCount !== undefined) {
    sql = `
      UPDATE sessions
      SET status = $1, log_count = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
      RETURNING *
    `;
    params = [status, logCount, id];
  } else {
    sql = `
      UPDATE sessions
      SET status = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING *
    `;
    params = [status, id];
  }

  const res = await query(sql, params);
  if (res.rows.length === 0) {
    throw new Error(`Session with id ${id} not found`);
  }
  return mapRowToSession(res.rows[0]);
}

/**
 * Retrieves a single session by its unique ID. Returns null if not found.
 */
export async function getSession(id: string): Promise<Session | null> {
  const sql = `SELECT * FROM sessions WHERE id = $1`;
  const res = await query(sql, [id]);
  if (res.rows.length === 0) {
    return null;
  }
  return mapRowToSession(res.rows[0]);
}

/**
 * Retrieves all sessions belonging to a specific user, sorted in descending chronological order.
 */
export async function getUserSessions(userId: string): Promise<Session[]> {
  const sql = `
    SELECT * FROM sessions 
    WHERE user_id = $1 
    ORDER BY created_at DESC
  `;
  const res = await query(sql, [userId]);
  return res.rows.map(mapRowToSession);
}
