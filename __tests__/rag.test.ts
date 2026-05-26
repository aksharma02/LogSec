import { assembleContext } from '@/lib/rag';
import { POST } from '@/app/api/analyze/route';
import { NextRequest } from 'next/server';

// 1. Mock OpenAI
jest.mock('openai', () => {
  return jest.fn().mockImplementation(() => ({
    embeddings: {
      create: jest.fn().mockResolvedValue({
        data: [{ embedding: new Array(1536).fill(0.2) }],
      }),
    },
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue([
          { choices: [{ delta: { content: '{"summary": "Test' } }] },
          { choices: [{ delta: { content: ' summary", "severity": "medium", ' } }] },
          { choices: [{ delta: { content: '"threatCategories": [], "findings": [], "recommendations": []}' } }] },
        ]),
      },
    },
  }));
});

// 2. Mock database chunks and qaHistory repositories
const mockSemanticSearch = jest.fn();
jest.mock('@/lib/db/chunks', () => ({
  semanticSearch: (...args: any[]) => mockSemanticSearch(...args),
}));

const mockInsertQaHistory = jest.fn();
jest.mock('@/lib/db/qaHistory', () => ({
  insertQaHistory: (...args: any[]) => mockInsertQaHistory(...args),
}));

// 3. Mock NextAuth getServerSession
jest.mock('next-auth/next', () => ({
  getServerSession: jest.fn().mockResolvedValue({
    user: { email: 'analyst@sec.company' },
  }),
}));

// 4. Mock Upstash Redis and Ratelimit
jest.mock('@upstash/redis', () => ({
  Redis: jest.fn().mockImplementation(() => ({})),
}));

jest.mock('@upstash/ratelimit', () => ({
  Ratelimit: jest.fn().mockImplementation(() => ({
    limit: jest.fn().mockResolvedValue({ success: true }),
  })),
}));

describe('Log Sec Analyzer - RAG Context Builder & Q&A Streaming API Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('RAG Context Assembly (assembleContext)', () => {
    test('should fetch and format semantic chunks correctly', async () => {
      mockSemanticSearch.mockResolvedValue([
        { chunkIndex: 0, lineStart: 1, lineEnd: 5, chunkText: 'Authentication failed for root' },
        { chunkIndex: 1, lineStart: 6, lineEnd: 10, chunkText: 'Port scan detected on DST=22' },
      ]);

      const context = await assembleContext('session-123', 'brute force attack query', 2);

      expect(mockSemanticSearch).toHaveBeenCalledWith('session-123', expect.any(Array), 2);
      expect(context).toContain('[Lines 1-5]\nAuthentication failed for root');
      expect(context).toContain('[Lines 6-10]\nPort scan detected on DST=22');
      expect(context).toContain('\n---\n');
    });

    test('should cap context length under 6000 tokens (24,000 characters) budget limit', async () => {
      // Create a huge chunk of 30,000 characters
      const largeText = 'X'.repeat(30000);
      mockSemanticSearch.mockResolvedValue([
        { chunkIndex: 0, lineStart: 1, lineEnd: 100, chunkText: largeText },
        { chunkIndex: 1, lineStart: 101, lineEnd: 200, chunkText: 'Should be omitted' },
      ]);

      const context = await assembleContext('session-123', 'brute force attack query', 2);

      // The large text is 30,000 chars, which exceeds the max chars limit of 24,000 (6000 * 4).
      // The context loop will halt and return empty or omit it since it exceeds the budget.
      expect(context).not.toContain('Should be omitted');
    });
  });

  describe('Streaming Q&A API Endpoint (POST /api/analyze)', () => {
    test('should stream OpenAI completion tokens and parse JSON on stream finish', async () => {
      mockSemanticSearch.mockResolvedValue([
        { chunkIndex: 0, lineStart: 1, lineEnd: 50, chunkText: 'Test logs snippet context' },
      ]);

      const requestPayload = {
        sessionId: 'session-xyz',
        question: 'Any privilege escalation attacks?',
      };

      const req = new NextRequest('http://localhost:3000/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestPayload),
      });

      const response = await POST(req);

      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/plain');

      // Consume the readable stream
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let streamContent = '';

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          streamContent += decoder.decode(value, { stream: true });
        }
      }

      // Assert that tokens are emitted sequentially
      expect(streamContent).toContain('{"summary": "Test');
      expect(streamContent).toContain(' summary", "severity": "medium", ');

      // Give background microtasks a brief cycle to process database logs insertion
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Confirm that the completed, schema-validated threat report was stored in qa_history
      expect(mockInsertQaHistory).toHaveBeenCalledWith(
        'session-xyz',
        'Any privilege escalation attacks?',
        expect.objectContaining({
          summary: 'Test summary',
          severity: 'medium',
          findings: [],
          threatCategories: [],
          recommendations: [],
        })
      );
    });

    test('should reject requests with missing body arguments', async () => {
      const req = new NextRequest('http://localhost:3000/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: 'Who logged in?' }), // Missing sessionId
      });

      const response = await POST(req);
      expect(response.status).toBe(400);

      const json = await response.json();
      expect(json.error).toContain('Missing required parameters');
    });
  });
});
