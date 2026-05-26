import { NextRequest } from 'next/server';
import { logQueue } from '@/lib/queue/producer';

/**
 * Server-Sent Events (SSE) GET endpoint to stream real-time background processing status
 * and logs ingestion metrics for a scheduled BullMQ job ID.
 * Route: GET /api/jobs/[id]/stream
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
): Promise<Response> {
  const { id } = params;
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      // Helper utility to enqueue formatted SSE protocol events
      const sendEvent = (data: any) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
        } catch (err) {
          console.warn(`Attempted to send event to a closed SSE stream for job ID ${id}:`, err);
        }
      };

      // Poll the BullMQ job progress and state once per second
      const intervalId = setInterval(async () => {
        try {
          const job = await logQueue.getJob(id);

          if (!job) {
            sendEvent({
              id,
              status: 'failed',
              progress: 0,
              error: 'Log analysis job was not found in the queue.',
            });
            clearInterval(intervalId);
            controller.close();
            return;
          }

          const state = await job.getState(); // 'active' | 'completed' | 'failed' | 'waiting' | 'delayed'
          const progressData = job.progress;

          // Normalize progress state variables
          let progressVal = 0;
          let step = 'queued';
          let parsedCount = 0;
          let embeddedCount = 0;

          if (typeof progressData === 'object' && progressData !== null) {
            const p = progressData as any;
            progressVal = p.progress || 0;
            step = p.step || 'processing';
            parsedCount = p.parsedCount || 0;
            embeddedCount = p.embeddedCount || 0;
          } else if (typeof progressData === 'number') {
            progressVal = progressData;
          }

          const ssePayload = {
            id: job.id,
            status: state,
            progress: progressVal,
            step,
            parsedCount,
            embeddedCount,
            error: job.failedReason || null,
          };

          sendEvent(ssePayload);

          // Close the stream cleanly when the job reaches its final state
          if (state === 'completed' || state === 'failed') {
            clearInterval(intervalId);
            controller.close();
          }
        } catch (err: any) {
          sendEvent({
            id,
            status: 'failed',
            progress: 100,
            error: err.message || 'An error occurred during real-time status tracking.',
          });
          clearInterval(intervalId);
          controller.close();
        }
      }, 1000);

      // Clean up the polling timer immediately if the client disconnects/aborts
      req.signal.addEventListener('abort', () => {
        console.log(`SSE connection for job #${id} aborted by client. Cleaning up interval.`);
        clearInterval(intervalId);
      });
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
    },
  });
}
