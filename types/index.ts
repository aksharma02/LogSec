import { z } from 'zod';

export interface LogEntry {
  id: string;
  sessionId: string;
  lineNum: number;
  ts: Date | null;
  ip: string | null;
  userName: string | null;
  action: string | null;
  resource: string | null;
  statusCode: number | null;
  rawLine: string;
  format: string;
  parseError: string | null;
}

// Zod Schema to validate the LogEntry objects
export const LogEntrySchema = z.object({
  id: z.string().uuid(),
  sessionId: z.string(),
  lineNum: z.number().int(),
  ts: z.date().nullable(),
  ip: z.string().nullable(),
  userName: z.string().nullable(),
  action: z.string().nullable(),
  resource: z.string().nullable(),
  statusCode: z.number().int().nullable(),
  rawLine: z.string(),
  format: z.string(),
  parseError: z.string().nullable(),
});

export interface Session {
  id: string;
  userId: string;
  name: string;
  logSource: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  logCount: number;
  createdAt: Date;
  updatedAt: Date;
}

// Database version of LogEntry, which includes metadata like createdAt
export interface DbLogEntry extends LogEntry {
  createdAt: Date;
}

export interface Chunk {
  id: string;
  sessionId: string;
  chunkText: string;
  embedding: number[];
  chunkIndex: number;
  lineStart: number;
  lineEnd: number;
  createdAt: Date;
}

export interface Finding {
  id: string;
  sessionId: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: any; // JSONB structure
  source: 'rule' | 'ml' | 'llm';
  createdAt: Date;
}

export interface QaHistory {
  id: string;
  sessionId: string;
  question: string;
  answer: any; // JSONB structure
  createdAt: Date;
}

