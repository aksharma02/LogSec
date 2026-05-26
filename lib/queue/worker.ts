import { Worker, Job } from 'bullmq';
import fs from 'fs';
import { redisConnection } from './client';
import { parseLogFile } from '../parsers';
import { updateSessionStatus } from '../db/sessions';
import { insertLogEntries } from '../db/logEntries';
import { runRuleDetection } from '../rules';
import { chunkLogEntries, embedBatch } from '../embeddings';
import { insertChunks } from '../db/chunks';

interface WorkerJobPayload {
  sessionId: string;
  filePath: string;
  userId: string;
}

/**
 * BullMQ Worker processing the "log-processing" queue.
 * Orchestrates a 6-stage security pipeline, emitting progress events and keeping
 * the PostgreSQL session status synchronized.
 */
export const logWorker = new Worker<WorkerJobPayload>(
  'log-processing',
  async (job: Job<WorkerJobPayload>) => {
    const { sessionId, filePath } = job.data;
    const maxAttempts = job.opts.attempts || 3;
    console.log(`Starting background processing for Job #${job.id} (Session: ${sessionId})...`);

    try {
      // Step 1: Read log file from disk
      await job.updateProgress({ step: 'reading', progress: 10 });
      if (!fs.existsSync(filePath)) {
        throw new Error(`Log file not found at disk path: "${filePath}"`);
      }
      const fileContent = fs.readFileSync(filePath, 'utf8');

      // Step 2: Parse logs using format snout sniffing orchestrator
      await job.updateProgress({ step: 'parsing', progress: 30 });
      const parsedEntries = parseLogFile(fileContent, sessionId);

      // Step 3: Update session status to processing and batch-insert log entries
      await job.updateProgress({ step: 'inserting-logs', progress: 50, parsedCount: parsedEntries.length });
      await updateSessionStatus(sessionId, 'processing', parsedEntries.length);
      await insertLogEntries(parsedEntries);

      // Step 4: Run rule-based detection signatures scanner
      await job.updateProgress({ step: 'scanning-rules', progress: 65 });
      await runRuleDetection(sessionId, parsedEntries);

      // Step 5: Sliding-window chunking & vector embedding generation
      await job.updateProgress({ step: 'embeddings', progress: 80 });
      const chunks = chunkLogEntries(parsedEntries);
      if (chunks.length > 0) {
        const chunkTexts = chunks.map(c => c.chunkText);
        // Call OpenAI embeddings batch processor (batches in groups of 100 with a 500ms delay)
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
      await job.updateProgress({ step: 'completed', progress: 95, embeddedCount: chunks.length });

      // Step 6: Mark session completed successfully in database
      await updateSessionStatus(sessionId, 'completed');
      await job.updateProgress({ step: 'done', progress: 100 });
      console.log(`Successfully processed Job #${job.id} (Session: ${sessionId}).`);

    } catch (err: any) {
      console.error(`Error in log worker Job #${job.id} (Attempt ${job.attemptsMade} of ${maxAttempts}):`, err);
      
      // If we have exhausted all scheduled retries, mark the session state as failed
      if (job.attemptsMade >= maxAttempts) {
        try {
          await updateSessionStatus(sessionId, 'failed');
        } catch (dbErr) {
          console.error(`Failed to mark session ${sessionId} as failed in DB:`, dbErr);
        }
      }
      
      throw err; // Re-throw the error to trigger BullMQ retry mechanics
    }
  },
  {
    connection: redisConnection,
  }
);

// Worker failure event listener as an additional diagnostic fallback
logWorker.on('failed', async (job, err) => {
  if (job) {
    const { sessionId } = job.data;
    console.error(`Job #${job.id} (Session: ${sessionId}) completely failed after exhaustive retries:`, err);
    try {
      await updateSessionStatus(sessionId, 'failed');
    } catch (dbErr) {
      console.error(`Failed to mark session ${sessionId} as failed during worker error listener:`, dbErr);
    }
  }
});

export default logWorker;
