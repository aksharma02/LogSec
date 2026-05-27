import { query } from './client';

interface ChunkInsertInput {
  sessionId: string;
  chunkText: string;
  embedding: number[];
  chunkIndex: number;
  lineStart: number;
  lineEnd: number;
}

interface SemanticSearchResult {
  chunkText: string;
  similarity: number;
  lineStart: number;
  lineEnd: number;
}

/**
 * Batch inserts log chunk vector embeddings into the database.
 * The float array embedding is automatically formatted to standard pgvector syntax '[val1,val2,...]'.
 */
export async function insertChunks(chunks: ChunkInsertInput[]): Promise<void> {
  if (chunks.length === 0) return;

  const columns = ['session_id', 'chunk_text', 'embedding', 'chunk_index', 'line_start', 'line_end'];
  const batchSize = 500;

  for (let i = 0; i < chunks.length; i += batchSize) {
    const batch = chunks.slice(i, i + batchSize);
    const values: any[] = [];
    const valuePlaceholders: string[] = [];
    let placeholderIndex = 1;

    for (const chunk of batch) {
      const rowPlaceholders: string[] = [];

      // 1. session_id
      values.push(chunk.sessionId);
      rowPlaceholders.push(`$${placeholderIndex++}`);

      // 2. chunk_text
      values.push(chunk.chunkText);
      rowPlaceholders.push(`$${placeholderIndex++}`);

      // 3. embedding (pgvector expects format: '[0.123,0.456,...]')
      const formattedEmbedding = `[${chunk.embedding.join(',')}]`;
      values.push(formattedEmbedding);
      rowPlaceholders.push(`$${placeholderIndex++}`);

      // 4. chunk_index
      values.push(chunk.chunkIndex);
      rowPlaceholders.push(`$${placeholderIndex++}`);

      // 5. line_start
      values.push(chunk.lineStart);
      rowPlaceholders.push(`$${placeholderIndex++}`);

      // 6. line_end
      values.push(chunk.lineEnd);
      rowPlaceholders.push(`$${placeholderIndex++}`);

      valuePlaceholders.push(`(${rowPlaceholders.join(', ')})`);
    }

    const sql = `
      INSERT INTO chunks (${columns.join(', ')})
      VALUES ${valuePlaceholders.join(', ')}
    `;

    await query(sql, values);
  }
}

/**
 * Performs semantic similarity search inside a session's log chunks using pgvector or a high-fidelity JavaScript Cosine Similarity fallback if pgvector is unavailable.
 * Returns the topK matching text chunks, sorting in descending order of similarity.
 */
export async function semanticSearch(
  sessionId: string,
  queryEmbedding: number[],
  topK: number
): Promise<SemanticSearchResult[]> {
  // Check if pgvector extension is actively installed in the postgres database
  let isVectorInstalled = false;
  try {
    const checkRes = await query("SELECT 1 FROM pg_extension WHERE extname = 'vector'");
    isVectorInstalled = checkRes.rowCount > 0;
  } catch (err) {
    // Fall back gracefully if pg_extension check throws permissions errors
  }

  if (isVectorInstalled) {
    const formattedQueryEmbedding = `[${queryEmbedding.join(',')}]`;
    const sql = `
      SELECT
        chunk_text AS "chunkText",
        line_start AS "lineStart",
        line_end AS "lineEnd",
        (1 - (embedding <=> $2::vector)) AS "similarity"
      FROM chunks
      WHERE session_id = $1
      ORDER BY embedding <=> $2::vector
      LIMIT $3
    `;

    const res = await query(sql, [sessionId, formattedQueryEmbedding, topK]);
    return res.rows.map(row => ({
      chunkText: row.chunkText,
      similarity: parseFloat(row.similarity),
      lineStart: parseInt(row.lineStart, 10),
      lineEnd: parseInt(row.lineEnd, 10),
    }));
  } else {
    // Fallback: Retrieve all chunks for this session and compute similarity in JS (fast and offline-safe)
    const sql = `
      SELECT
        chunk_text AS "chunkText",
        line_start AS "lineStart",
        line_end AS "lineEnd",
        embedding
      FROM chunks
      WHERE session_id = $1
    `;
    
    const res = await query(sql, [sessionId]);
    
    const results: SemanticSearchResult[] = res.rows.map(row => {
      let vector: number[] = [];
      try {
        const rawVector = row.embedding;
        if (typeof rawVector === 'string') {
          // Parse pgvector formatted string representation: '[val1,val2,...]'
          const sanitized = rawVector.replace(/[\[\]]/g, '');
          vector = sanitized.split(',').map(parseFloat);
        } else if (Array.isArray(rawVector)) {
          vector = rawVector;
        }
      } catch (err) {
        console.error('Failed to parse vector embedding inside offline fallback search:', err);
      }

      // Compute standard Cosine Similarity mathematically
      let dotProduct = 0;
      let normA = 0;
      let normB = 0;
      const length = Math.min(vector.length, queryEmbedding.length);
      
      for (let i = 0; i < length; i++) {
        dotProduct += vector[i] * queryEmbedding[i];
        normA += vector[i] * vector[i];
        normB += queryEmbedding[i] * queryEmbedding[i];
      }
      
      const similarity = normA && normB ? dotProduct / (Math.sqrt(normA) * Math.sqrt(normB)) : 0;

      return {
        chunkText: row.chunkText,
        similarity,
        lineStart: parseInt(row.lineStart, 10),
        lineEnd: parseInt(row.lineEnd, 10),
      };
    });

    // Sort descending and cap to topK results
    return results
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, topK);
  }
}
