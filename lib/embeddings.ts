import OpenAI from 'openai';
import { LogEntry } from '@/types';

// Initialize the OpenAI client using the API key from environment variables
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || 'mock-api-key',
});

/**
 * Interface representing a chunk partition with lines bounds and sequential indexing.
 */
export interface LogChunk {
  chunkText: string;
  chunkIndex: number;
  lineStart: number;
  lineEnd: number;
}

/**
 * Requests a single 1536-dimensional vector embedding for a block of text using text-embedding-3-small.
 */
export async function embedText(text: string): Promise<number[]> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey || apiKey.startsWith('mock') || apiKey.includes('your-openai-api-key')) {
    // Generate a deterministic mock 1536-dimensional float vector filled with 0.1
    return new Array(1536).fill(0.1);
  }
  const response = await openai.embeddings.create({
    model: 'text-embedding-3-small',
    input: text,
  });
  return response.data[0].embedding;
}

/**
 * Requests embeddings for a batch of strings, grouping inputs into batches of 100
 * and running them concurrently to prevent sequential rate-limiting delays.
 */
export async function embedBatch(texts: string[]): Promise<number[][]> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey || apiKey.startsWith('mock') || apiKey.includes('your-openai-api-key')) {
    // Generate deterministic mock vectors filled with 0.1 for all text elements concurrently
    return texts.map(() => new Array(1536).fill(0.1));
  }

  const batchSize = 100;
  const batches: string[][] = [];
  for (let i = 0; i < texts.length; i += batchSize) {
    batches.push(texts.slice(i, i + batchSize));
  }

  // Trigger concurrent OpenAI API embedding requests for all batches
  const promises = batches.map(batch =>
    openai.embeddings.create({
      model: 'text-embedding-3-small',
      input: batch,
    })
  );

  const responses = await Promise.all(promises);

  const embeddings: number[][] = [];
  for (const response of responses) {
    const batchEmbeddings = response.data.map(d => d.embedding);
    embeddings.push(...batchEmbeddings);
  }

  return embeddings;
}

/**
 * Formats parsed log lines into contiguous text chunks.
 * Joins entry.rawLine strings with newlines, using a sliding window of chunkSize with a 15-line overlap.
 */
export function chunkLogEntries(
  entries: LogEntry[],
  chunkSize: number = 75
): LogChunk[] {
  const chunks: LogChunk[] = [];
  if (entries.length === 0) return chunks;

  const overlap = 15;
  // Step is chunkSize minus overlap. E.g., for 75-size chunk, step is 60.
  const step = chunkSize - overlap > 0 ? chunkSize - overlap : 1;

  let chunkIndex = 0;
  for (let i = 0; i < entries.length; i += step) {
    const windowEntries = entries.slice(i, i + chunkSize);
    if (windowEntries.length === 0) break;

    // Concatenate raw line texts of this window segment with newlines
    const rawLines = windowEntries.map(e => e.rawLine);
    const chunkText = rawLines.join('\n');
    const lineStart = windowEntries[0].lineNum;
    const lineEnd = windowEntries[windowEntries.length - 1].lineNum;

    chunks.push({
      chunkText,
      chunkIndex,
      lineStart,
      lineEnd,
    });

    chunkIndex++;

    // Terminate sliding loop if the window reaches the tail boundary of the entries
    if (i + chunkSize >= entries.length) {
      break;
    }
  }

  return chunks;
}
