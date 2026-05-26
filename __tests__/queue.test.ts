import fs from 'fs';
import { chunkLogEntries, embedText, embedBatch } from '@/lib/embeddings';
import { enqueueLogProcessing, logQueue } from '@/lib/queue/producer';
import { LogEntry } from '@/types';

// Mock OpenAI API calls
jest.mock('openai', () => {
  return jest.fn().mockImplementation(() => ({
    embeddings: {
      create: jest.fn().mockImplementation(({ input }) => {
        const embeddings = Array.isArray(input)
          ? input.map(() => ({ embedding: new Array(1536).fill(0.1) }))
          : [{ embedding: new Array(1536).fill(0.1) }];
        return Promise.resolve({ data: embeddings });
      }),
    },
  }));
});

// Mock BullMQ Connection
jest.mock('bullmq', () => {
  const mQueue = {
    add: jest.fn().mockResolvedValue({ id: 'job-uuid-555' }),
    getJob: jest.fn(),
  };
  const mWorker = {
    on: jest.fn(),
  };
  return {
    Queue: jest.fn(() => mQueue),
    Worker: jest.fn(() => mWorker),
  };
});

describe('Log Sec Analyzer - Embeddings & Async Processing Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Log Entries Sliding Window Chunking', () => {
    const makeMockEntries = (count: number): LogEntry[] => {
      return Array.from({ length: count }, (_, idx) => ({
        id: `id-${idx}`,
        sessionId: 'session-123',
        lineNum: idx + 1,
        ts: new Date(),
        ip: '10.0.0.1',
        userName: 'admin',
        action: 'login',
        resource: '/app',
        statusCode: 200,
        rawLine: `Log line number ${idx + 1}`,
        format: 'generic',
        parseError: null,
      }));
    };

    test('should return empty chunk array for empty entries input', () => {
      const chunks = chunkLogEntries([], 75);
      expect(chunks).toHaveLength(0);
    });

    test('should slice sliding-window chunks with a 15-line overlap correctly', () => {
      // 100 entries. For window size 75, overlap 15:
      // Step size is 75 - 15 = 60 lines.
      // Chunk 0: index 0 to 74 (line 1 to 75)
      // Chunk 1: index 60 to 99 (line 61 to 100)
      const entries = makeMockEntries(100);
      const chunks = chunkLogEntries(entries, 75);

      expect(chunks).toHaveLength(2);

      // Verify Chunk 0
      expect(chunks[0].chunkIndex).toBe(0);
      expect(chunks[0].lineStart).toBe(1);
      expect(chunks[0].lineEnd).toBe(75);
      expect(chunks[0].chunkText).toContain('Log line number 1');
      expect(chunks[0].chunkText).toContain('Log line number 75');
      expect(chunks[0].chunkText).not.toContain('Log line number 76');

      // Verify Chunk 1
      expect(chunks[1].chunkIndex).toBe(1);
      expect(chunks[1].lineStart).toBe(61);
      expect(chunks[1].lineEnd).toBe(100);
      expect(chunks[1].chunkText).toContain('Log line number 61');
      expect(chunks[1].chunkText).toContain('Log line number 100');
    });

    test('should slide single window if total entries is smaller than chunkSize', () => {
      const entries = makeMockEntries(50);
      const chunks = chunkLogEntries(entries, 75);

      expect(chunks).toHaveLength(1);
      expect(chunks[0].chunkIndex).toBe(0);
      expect(chunks[0].lineStart).toBe(1);
      expect(chunks[0].lineEnd).toBe(50);
    });
  });

  describe('OpenAI Vector Embeddings Pipeline', () => {
    test('should generate single 1536-dimensional text vector via embedText', async () => {
      const vector = await embedText('some security log raw content');

      expect(vector).toHaveLength(1536);
      expect(vector[0]).toBe(0.1);
    });

    test('should batch process texts in chunks of 100 via embedBatch', async () => {
      const texts = Array.from({ length: 250 }, (_, idx) => `Text sample #${idx + 1}`);
      const embeddings = await embedBatch(texts);

      expect(embeddings).toHaveLength(250);
      expect(embeddings[0]).toHaveLength(1536);
    });
  });

  describe('Async BullMQ Job Producer', () => {
    test('should add job to background queue with max retries and return jobId', async () => {
      const mockQueue = logQueue as any;

      const jobId = await enqueueLogProcessing('session-abc', '/logs/secure.log', 'user-999');

      expect(mockQueue.add).toHaveBeenCalledWith(
        'process-logs',
        {
          sessionId: 'session-abc',
          filePath: '/logs/secure.log',
          userId: 'user-999',
        },
        expect.objectContaining({
          attempts: 3,
          backoff: expect.objectContaining({
            type: 'exponential',
            delay: 1000,
          }),
        })
      );
      expect(jobId).toBe('job-uuid-555');
    });
  });
});
