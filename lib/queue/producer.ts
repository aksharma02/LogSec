import { Queue } from 'bullmq';
import { redisConnection } from './client';

// Private backing field for the lazy-loaded BullMQ Queue instance
let _logQueue: Queue | null = null;

/**
 * Lazy initializer for the BullMQ log-processing Queue.
 * Prevents active connection socket attempts during compiler builds.
 */
export function getLogQueue(): Queue {
  if (!_logQueue) {
    _logQueue = new Queue('log-processing', {
      connection: redisConnection,
    });
  }
  return _logQueue;
}

/**
 * Enqueues a security log analysis job into the background log-processing queue.
 * Configured with max 3 attempts and exponential retry backoff (starting at 1s).
 * Automatically prunes successful items from Redis while retaining failures for diagnostics.
 */
export async function enqueueLogProcessing(
  sessionId: string,
  filePath: string,
  userId: string
): Promise<string> {
  const queue = getLogQueue();
  const job = await queue.add(
    'process-logs',
    { sessionId, filePath, userId },
    {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 1000, // Start backoff retry delay at 1000ms (1 second)
      },
      removeOnComplete: true, // Prune successfully completed jobs automatically
      removeOnFail: false,   // Retain failures for diagnostic security checks
    }
  );

  return job.id || '';
}

// Backward-compatible lazy ES6 Proxy delegation for test suite spys and mocks.
// Allows mock assertions to inspect and trigger add/get operations without
// establishing eager Redis socket connections during dynamic build pre-renderers.
export const logQueue = new Proxy({}, {
  get(target, prop) {
    return (getLogQueue() as any)[prop];
  }
}) as any;
