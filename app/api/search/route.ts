import { NextRequest, NextResponse } from 'next/server';
import { embedText } from '@/lib/embeddings';
import { semanticSearch } from '@/lib/db/chunks';

/**
 * POST /api/search
 * High-performance vector semantic search across logs chunks using pgvector cosine similarity.
 */
export async function POST(req: NextRequest): Promise<Response> {
  try {
    const body = await req.json();
    const { sessionId, query, limit = 10 } = body;

    if (!sessionId || !query) {
      return NextResponse.json(
        { error: 'Missing required parameters: "sessionId" and "query".' },
        { status: 400 }
      );
    }

    // 1. Convert text search query to high-dimensional embedding vector
    const queryEmbedding = await embedText(query);

    // 2. Query similarity matches in PostgreSQL
    const results = await semanticSearch(sessionId, queryEmbedding, limit);

    // Map rows into clean JSON results carrying exact similarity metrics
    const searchResults = results.map((r) => ({
      id: r.id,
      sessionId: r.sessionId,
      chunkText: r.chunkText,
      chunkIndex: r.chunkIndex,
      lineStart: r.lineStart,
      lineEnd: r.lineEnd,
      similarity: r.similarity || 0, // already computed as: 1 - (embedding <=> queryEmbedding)
    }));

    return NextResponse.json(searchResults);
  } catch (err: any) {
    console.error('Fatal error during vector logs search:', err);
    return NextResponse.json({ error: err.message || 'Server error' }, { status: 500 });
  }
}
