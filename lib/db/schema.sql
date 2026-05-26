-- Enable the pgvector extension for high-performance vector similarity search
CREATE EXTENSION IF NOT EXISTS vector;

-- Enable gen_random_uuid() for robust UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create Sessions table to organize log parsing sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    log_source VARCHAR(100) NOT NULL, -- e.g. 'syslog', 'apache', 'cloudtrail', 'generic'
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'processing', 'completed', 'failed'
    log_count INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Log Entries table for Zod-validated log parsing records
CREATE TABLE IF NOT EXISTS log_entries (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    line_num INT NOT NULL,
    ts TIMESTAMP WITH TIME ZONE,
    ip VARCHAR(100),
    user_name VARCHAR(255),
    action VARCHAR(255),
    resource TEXT,
    status_code INT,
    raw_line TEXT NOT NULL,
    format VARCHAR(50) NOT NULL,
    parse_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Chunks table to store vector embeddings for semantic logs lookup
CREATE TABLE IF NOT EXISTS chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    chunk_text TEXT NOT NULL,
    embedding VECTOR(1536) NOT NULL, -- Standard 1536-dimensional embeddings (e.g. OpenAI text-embedding-3-small)
    chunk_index INT NOT NULL,
    line_start INT NOT NULL,
    line_end INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Findings table for security intelligence and anomaly alerts
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    type VARCHAR(100) NOT NULL, -- e.g. 'auth_failure', 'anomaly', 'dos_attack'
    severity VARCHAR(50) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    evidence JSONB,
    source VARCHAR(50) NOT NULL DEFAULT 'rule',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Establish relational indices to accelerate standard lookup operations
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_log_entries_session_id ON log_entries(session_id);
CREATE INDEX IF NOT EXISTS idx_log_entries_ip ON log_entries(ip);
CREATE INDEX IF NOT EXISTS idx_log_entries_user_name ON log_entries(user_name);
CREATE INDEX IF NOT EXISTS idx_chunks_session_id ON chunks(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(session_id);

-- Create vector HNSW index for high-efficiency semantic vector searches
CREATE INDEX IF NOT EXISTS idx_chunks_embedding ON chunks USING hnsw (embedding vector_cosine_ops);

-- Create Q&A History table to archive analyst chat questions and responses
CREATE TABLE IF NOT EXISTS qa_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    question TEXT NOT NULL,
    answer JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_qa_history_session_id ON qa_history(session_id);

-- Create users table to persist NextAuth operator credentials
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    image TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
