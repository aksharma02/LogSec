import { query } from './client';

export interface DbUser {
  id: string;
  name: string | null;
  email: string;
  image: string | null;
  password?: string | null;
  createdAt: Date;
}

let migratorPromise: Promise<any> | null = null;
async function ensurePasswordColumn() {
  if (!migratorPromise) {
    migratorPromise = query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS password VARCHAR(255);
    `).catch(err => {
      console.error('Failed to run users schema migration:', err);
    });
  }
  return migratorPromise;
}

function mapRowToUser(row: any): DbUser {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    image: row.image,
    password: row.password || null,
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
  await ensurePasswordColumn();
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
  await ensurePasswordColumn();
  const sql = `
    SELECT * FROM users
    WHERE email = $1
  `;
  const res = await query(sql, [email]);
  if (res.rows.length === 0) return null;
  return mapRowToUser(res.rows[0]);
}

/**
 * Updates a user's password in the database.
 */
export async function updateUserPassword(email: string, password: string): Promise<DbUser> {
  await ensurePasswordColumn();
  const sql = `
    UPDATE users
    SET password = $2
    WHERE email = $1
    RETURNING *
  `;
  const res = await query(sql, [email, password]);
  return mapRowToUser(res.rows[0]);
}

/**
 * Creates a new user with password inside our PostgreSQL table.
 */
export async function createUserWithPassword(user: {
  name?: string | null;
  email: string;
  password: string;
}): Promise<DbUser> {
  await ensurePasswordColumn();
  const sql = `
    INSERT INTO users (name, email, password)
    VALUES ($1, $2, $3)
    ON CONFLICT (email)
    DO UPDATE SET password = EXCLUDED.password, name = COALESCE(users.name, EXCLUDED.name)
    RETURNING *
  `;
  const res = await query(sql, [user.name || null, user.email, user.password]);
  return mapRowToUser(res.rows[0]);
}
