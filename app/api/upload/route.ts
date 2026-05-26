import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
import { enqueueLogProcessing } from '@/lib/queue/producer';

/**
 * POST /api/upload
 * Processes multipart security logs file uploads, persists them to disk,
 * and schedules a background BullMQ job.
 */
export async function POST(req: NextRequest): Promise<Response> {
  try {
    const formData = await req.formData();
    const file = formData.get('file') as File | null;
    const sessionId = formData.get('sessionId') as string | null;

    if (!file || !sessionId) {
      return NextResponse.json(
        { error: 'Missing required parameters: "file" or "sessionId".' },
        { status: 400 }
      );
    }

    // Convert browser File stream to standard Node Buffer
    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Create an isolated tmp/uploads workspace directory for persistence
    const uploadsDir = path.join(process.cwd(), 'tmp', 'uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    // Persist file securely using timestamped session prefixes
    const safeFileName = file.name.replace(/[^a-zA-Z0-9.-]/g, '_');
    const filePath = path.join(uploadsDir, `${sessionId}_${Date.now()}_${safeFileName}`);
    fs.writeFileSync(filePath, buffer);

    const userId = 'operator-admin';

    let jobId = '';
    try {
      // Trigger the high-performance background logging analysis worker
      jobId = await enqueueLogProcessing(sessionId, filePath, userId);
    } catch (redisErr) {
      console.warn('Redis connection failed. Running synchronous inline log analysis fallback...', redisErr);
      
      const fileContent = fs.readFileSync(filePath, 'utf8');
      
      // Stage 1: Sniff and parse the ingested logs file
      const { parseLogFile } = await import('@/lib/parsers');
      const parsedEntries = parseLogFile(fileContent, sessionId);
      
      // Stage 2: Register parsed LogEntries to PostgreSQL
      const { updateSessionStatus } = await import('@/lib/db/sessions');
      const { insertLogEntries } = await import('@/lib/db/logEntries');
      await updateSessionStatus(sessionId, 'processing', parsedEntries.length);
      await insertLogEntries(parsedEntries);
      
      // Stage 3: Scan security threat signatures
      const { runRuleDetection } = await import('@/lib/rules');
      await runRuleDetection(sessionId, parsedEntries);
      
      // Stage 4: Log chunking and vector embeddings indexing fallback
      const { chunkLogEntries, embedBatch } = await import('@/lib/embeddings');
      const chunks = chunkLogEntries(parsedEntries);
      if (chunks.length > 0) {
        const { insertChunks } = await import('@/lib/db/chunks');
        const chunkTexts = chunks.map(c => c.chunkText);
        const embeddings = await embedBatch(chunkTexts);
        
        const chunksWithEmbeddings = chunks.map((chunk, idx) => ({
          sessionId,
          chunkText: chunk.chunkText,
          embedding: embeddings[idx],
          chunkIndex: chunk.chunkIndex,
          lineStart: chunk.lineStart,
          lineEnd: chunk.lineEnd,
        }));
        
        await insertChunks(chunksWithEmbeddings);
      }
      
      // Stage 5: Sync session completion
      await updateSessionStatus(sessionId, 'completed');
      jobId = 'sync-offline-fallback';
    }

    return NextResponse.json({
      success: true,
      jobId,
      filePath,
      fileName: file.name,
      sizeBytes: file.size,
    });
  } catch (err: any) {
    console.error('Fatal error during file upload:', err);
    return NextResponse.json(
      { error: err.message || 'An error occurred during file upload.' },
      { status: 500 }
    );
  }
}
