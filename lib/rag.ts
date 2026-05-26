import { embedText } from './embeddings';
import { semanticSearch } from './db/chunks';

/**
 * Builds the RAG (Retrieval-Augmented Generation) context by embedding the target query,
 * executing a cosine similarity lookup against pgvector chunks, formatting boundaries,
 * and capping the cumulative token budget under 6000 tokens (approx 24,000 characters).
 */
export async function assembleContext(
  sessionId: string,
  query: string,
  topK: number = 15
): Promise<string> {
  console.log(`Assembling RAG context for Session ${sessionId} (Query: "${query}", TopK: ${topK})...`);

  // 1. Convert user's flat question to a 1536-dimensional float vector
  const queryEmbedding = await embedText(query);

  // 2. Perform similarity search in chunks database repository
  const searchResults = await semanticSearch(sessionId, queryEmbedding, topK);

  if (searchResults.length === 0) {
    return 'No relevant log entries found for this session.';
  }

  // 3. Assemble and join matched text snippets up to the token budget
  const formattedChunks: string[] = [];
  let currentLengthChars = 0;
  const maxCharsLimit = 6000 * 4; // Capping total context at 6000 tokens (Estimate: 1 token ≈ 4 characters)

  for (const chunk of searchResults) {
    const formattedSnippet = `[Lines ${chunk.lineStart}-${chunk.lineEnd}]\n${chunk.chunkText}`;
    
    // Add separator separator spacing overhead '\n---\n'
    const expectedCharsCount = currentLengthChars + formattedSnippet.length + 5;

    // Halt adding further context once the 6000-token threshold is reached
    if (expectedCharsCount > maxCharsLimit) {
      console.log(`RAG Context capped at ${currentLengthChars} characters (approx ${Math.round(currentLengthChars / 4)} tokens).`);
      break;
    }

    formattedChunks.push(formattedSnippet);
    currentLengthChars = expectedCharsCount;
  }

  return formattedChunks.join('\n---\n');
}
