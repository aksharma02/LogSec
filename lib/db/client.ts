import { Pool } from 'pg';

// Fallback to local default development database URI
const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/ai_sec_analyzer';

// Singleton PostgreSQL Connection Pool
export const pool = new Pool({
  connectionString,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

/**
 * Utility helper to execute a parameterized query against the database.
 * No SQL string interpolation is allowed to protect against SQL injections.
 */
export const query = (text: string, params?: any[]) => {
  return pool.query(text, params);
};

export default pool;
