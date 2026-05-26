import fs from 'fs';
import path from 'path';
import pool from './client';

/**
 * Reads the schema.sql file and executes it within a database transaction.
 * All DDL expressions are structured as idempotent statements (e.g. IF NOT EXISTS),
 * making this migration orchestrator safe to run repeatedly.
 */
export async function runMigrations(): Promise<void> {
  const schemaPath = path.join(process.cwd(), 'lib/db/schema.sql');
  
  if (!fs.existsSync(schemaPath)) {
    throw new Error(`Schema file not found at path: ${schemaPath}`);
  }

  let sql = fs.readFileSync(schemaPath, 'utf8');

  // Acquire a dedicated client from the pool to execute the transaction
  const client = await pool.connect();
  
  try {
    console.log('Starting PostgreSQL + pgvector schema migrations...');
    
    // Check if pgvector extension is available in the pg server
    const extRes = await client.query("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'");
    const hasVector = extRes.rowCount > 0;
    
    if (!hasVector) {
      console.warn("pgvector extension is NOT available in this PostgreSQL server. Falling back to standard TEXT representation for local vector storage.");
      
      // Strip CREATE EXTENSION vector statement
      sql = sql.replace(/CREATE EXTENSION IF NOT EXISTS vector;/gi, '-- CREATE EXTENSION IF NOT EXISTS vector; (disabled offline)');
      
      // Convert VECTOR(1536) to TEXT
      sql = sql.replace(/embedding VECTOR\(1536\) NOT NULL/gi, 'embedding TEXT NOT NULL');
      
      // Disable the USING hnsw vector index
      sql = sql.replace(/CREATE INDEX IF NOT EXISTS idx_chunks_embedding ON chunks USING hnsw \(embedding vector_cosine_ops\);/gi, '-- CREATE INDEX IF NOT EXISTS idx_chunks_embedding (disabled offline)');
    }
    
    await client.query('BEGIN');
    
    // Execute all SQL definitions in one go
    await client.query(sql);
    
    await client.query('COMMIT');
    console.log('PostgreSQL schema migrations executed successfully!');
  } catch (err: any) {
    await client.query('ROLLBACK');
    console.error('PostgreSQL migration failed, transaction rolled back safely.', err);
    throw err;
  } finally {
    // Release the client back to the pool
    client.release();
  }
}
