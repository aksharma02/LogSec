import { query } from './client';

export interface DbUser {
  id: string;
  name: string | null;
  email: string;
  image: string | null;
  createdAt: Date;
}

function mapRowToUser(row: any): DbUser {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    image: row.image,
    createdAt: new Date(row.created_at),
  };
}

/**
 * Persists or updates a NextAuth authenticated user inside our PostgreSQL table.
 */
export async function upsertUser(user: {
  name?: string | null;
  email: string;
  image?: string | null;
}): Promise<DbUser> {
  const sql = `
    INSERT INTO users (name, email, image)
    VALUES ($1, $2, $3)
    ON CONFLICT (email)
    DO UPDATE SET name = EXCLUDED.name, image = EXCLUDED.image
    RETURNING *
  `;
  const res = await query(sql, [user.name || null, user.email, user.image || null]);
  return mapRowToUser(res.rows[0]);
}

/**
 * Retrieves a persisted user profile using their unique email index.
 */
export async function getUserByEmail(email: string): Promise<DbUser | null> {
  const sql = `
    SELECT * FROM users
    WHERE email = $1
  `;
  const res = await query(sql, [email]);
  if (res.rows.length === 0) return null;
  return mapRowToUser(res.rows[0]);
}
