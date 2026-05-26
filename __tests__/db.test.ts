import fs from 'fs';
import path from 'path';
import pool from '@/lib/db/client';
import { runMigrations } from '@/lib/db/migrations';
import { createSession, updateSessionStatus, getSession, getUserSessions } from '@/lib/db/sessions';
import { insertLogEntries, getEntriesBySession } from '@/lib/db/logEntries';
import { insertChunks, semanticSearch } from '@/lib/db/chunks';
import { insertFinding, getFindingsBySession } from '@/lib/db/findings';

// Mock the pg module connection pool
jest.mock('pg', () => {
  const mClient = {
    query: jest.fn(),
    release: jest.fn(),
  };
  const mPool = {
    connect: jest.fn(() => Promise.resolve(mClient)),
    query: jest.fn(),
    on: jest.fn(),
    end: jest.fn(),
  };
  return {
    Pool: jest.fn(() => mPool),
  };
});

describe('Log Sec Analyzer - Database Repository Integration Tests', () => {
  let mockPool: any;

  beforeEach(() => {
    jest.clearAllMocks();
    mockPool = pool;
  });

  describe('Database Migrations Runner', () => {
    test('should execute migrations schema within an ACID transaction', async () => {
      const mockClient = await mockPool.connect();
      mockClient.query.mockResolvedValue({ rows: [] });

      await runMigrations();

      // Verify transaction boundary is created
      expect(mockClient.query).toHaveBeenCalledWith('BEGIN');
      expect(mockClient.query).toHaveBeenCalledWith('COMMIT');
      expect(mockClient.release).toHaveBeenCalled();
      
      // Verify schema.sql content is executed
      expect(mockClient.query).toHaveBeenCalledWith(
        expect.stringContaining('CREATE TABLE IF NOT EXISTS sessions')
      );
    });

    test('should rollback transaction safely if DDL execution fails', async () => {
      const mockClient = await mockPool.connect();
      mockClient.query.mockImplementation((sql: string) => {
        if (sql.includes('CREATE TABLE')) {
          return Promise.reject(new Error('Syntax Error near HNSW'));
        }
        return Promise.resolve({ rows: [] });
      });

      await expect(runMigrations()).rejects.toThrow('Syntax Error near HNSW');

      expect(mockClient.query).toHaveBeenCalledWith('BEGIN');
      expect(mockClient.query).toHaveBeenCalledWith('ROLLBACK');
      expect(mockClient.release).toHaveBeenCalled();
    });
  });

  describe('Sessions Repository', () => {
    const mockSessionRow = {
      id: 'session-uuid-123',
      user_id: 'user-456',
      name: 'Apache Security Audit',
      log_source: 'apache',
      status: 'pending',
      log_count: 10,
      created_at: '2026-05-26T16:00:00Z',
      updated_at: '2026-05-26T16:00:00Z',
    };

    test('should insert and return a Session via createSession', async () => {
      mockPool.query.mockResolvedValue({ rows: [mockSessionRow] });

      const session = await createSession('user-456', 'Apache Security Audit', 'apache');

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO sessions'),
        ['user-456', 'Apache Security Audit', 'apache']
      );
      expect(session.id).toBe('session-uuid-123');
      expect(session.userId).toBe('user-456');
      expect(session.status).toBe('pending');
      expect(session.logCount).toBe(10);
    });

    test('should update status and log count of a session', async () => {
      const updatedRow = { ...mockSessionRow, status: 'completed', log_count: 500 };
      mockPool.query.mockResolvedValue({ rows: [updatedRow] });

      const session = await updateSessionStatus('session-uuid-123', 'completed', 500);

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE sessions'),
        ['completed', 500, 'session-uuid-123']
      );
      expect(session.status).toBe('completed');
      expect(session.logCount).toBe(500);
    });

    test('should retrieve session by ID', async () => {
      mockPool.query.mockResolvedValue({ rows: [mockSessionRow] });

      const session = await getSession('session-uuid-123');

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM sessions WHERE id = $1'),
        ['session-uuid-123']
      );
      expect(session).not.toBeNull();
      expect(session?.id).toBe('session-uuid-123');
    });

    test('should return null if session ID is not found', async () => {
      mockPool.query.mockResolvedValue({ rows: [] });

      const session = await getSession('session-uuid-999');

      expect(session).toBeNull();
    });

    test('should retrieve sessions belonging to a specific user', async () => {
      mockPool.query.mockResolvedValue({ rows: [mockSessionRow] });

      const sessions = await getUserSessions('user-456');

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM sessions'),
        ['user-456']
      );
      expect(sessions).toHaveLength(1);
      expect(sessions[0].userId).toBe('user-456');
    });
  });

  describe('LogEntries Repository', () => {
    const mockEntry = {
      id: 'entry-uuid-111',
      sessionId: 'session-uuid-123',
      lineNum: 1,
      ts: new Date('2026-05-26T15:58:55Z'),
      ip: '192.168.1.1',
      userName: 'admin',
      action: 'login',
      resource: '/dashboard',
      statusCode: 200,
      rawLine: 'raw line info',
      format: 'generic',
      parseError: null,
    };

    test('should execute bulk insertion dynamically in a single query', async () => {
      mockPool.query.mockResolvedValue({ rows: [] });

      const entries = [mockEntry, { ...mockEntry, id: 'entry-uuid-222', lineNum: 2 }];
      await insertLogEntries(entries);

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO log_entries'),
        expect.arrayContaining(['entry-uuid-111', 'session-uuid-123', 1, 'entry-uuid-222', 'session-uuid-123', 2])
      );
    });

    test('should retrieve log entries sequentially', async () => {
      const mockRow = {
        id: 'entry-uuid-111',
        session_id: 'session-uuid-123',
        line_num: 1,
        ts: '2026-05-26T15:58:55Z',
        ip: '192.168.1.1',
        user_name: 'admin',
        action: 'login',
        resource: '/dashboard',
        status_code: 200,
        raw_line: 'raw line info',
        format: 'generic',
        parse_error: null,
        created_at: '2026-05-26T16:00:00Z',
      };
      mockPool.query.mockResolvedValue({ rows: [mockRow] });

      const entries = await getEntriesBySession('session-uuid-123');

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM log_entries'),
        ['session-uuid-123']
      );
      expect(entries).toHaveLength(1);
      expect(entries[0].id).toBe('entry-uuid-111');
      expect(entries[0].lineNum).toBe(1);
    });
  });

  describe('Chunks Repository (pgvector operations)', () => {
    test('should execute bulk chunk insertion and format embedding float arrays as vector strings', async () => {
      mockPool.query.mockResolvedValue({ rows: [] });

      const chunks = [
        {
          sessionId: 'session-uuid-123',
          chunkText: 'some log contents',
          embedding: [0.1, 0.2, 0.3],
          chunkIndex: 0,
          lineStart: 1,
          lineEnd: 5,
        },
      ];

      await insertChunks(chunks);

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO chunks'),
        ['session-uuid-123', 'some log contents', '[0.1,0.2,0.3]', 0, 1, 5]
      );
    });

    test('should execute semanticSearch using HNSW cosine distance operator', async () => {
      const mockSearchResult = {
        chunkText: 'matched text',
        lineStart: 1,
        lineEnd: 5,
        similarity: 0.85,
      };
      mockPool.query.mockResolvedValue({ rows: [mockSearchResult] });

      const results = await semanticSearch('session-uuid-123', [0.1, 0.2, 0.3], 5);

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('ORDER BY embedding <=> $2::vector'),
        ['session-uuid-123', '[0.1,0.2,0.3]', 5]
      );
      expect(results).toHaveLength(1);
      expect(results[0].chunkText).toBe('matched text');
      expect(results[0].similarity).toBe(0.85);
    });
  });

  describe('Findings Repository', () => {
    const mockFindingRow = {
      id: 'finding-uuid-777',
      session_id: 'session-uuid-123',
      type: 'dos_attack',
      severity: 'high',
      title: 'DoS Attack Detected',
      description: 'Multiple continuous requests',
      evidence: { ip: '10.0.0.1', count: 1000 },
      source: 'rule',
      created_at: '2026-05-26T16:00:00Z',
    };

    test('should insert and serialize evidence JSON successfully', async () => {
      mockPool.query.mockResolvedValue({ rows: [mockFindingRow] });

      const input = {
        sessionId: 'session-uuid-123',
        type: 'dos_attack',
        severity: 'high' as const,
        title: 'DoS Attack Detected',
        description: 'Multiple continuous requests',
        evidence: { ip: '10.0.0.1', count: 1000 },
        source: 'rule' as const,
      };

      const finding = await insertFinding(input);

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO findings'),
        ['session-uuid-123', 'dos_attack', 'high', 'DoS Attack Detected', 'Multiple continuous requests', JSON.stringify({ ip: '10.0.0.1', count: 1000 }), 'rule']
      );
      expect(finding.id).toBe('finding-uuid-777');
      expect(finding.type).toBe('dos_attack');
      expect(finding.evidence).toEqual({ ip: '10.0.0.1', count: 1000 });
    });

    test('should retrieve findings belonging to a session ordered chronologically', async () => {
      mockPool.query.mockResolvedValue({ rows: [mockFindingRow] });

      const findings = await getFindingsBySession('session-uuid-123');

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM findings'),
        ['session-uuid-123']
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].id).toBe('finding-uuid-777');
      expect(findings[0].severity).toBe('high');
    });
  });
});
