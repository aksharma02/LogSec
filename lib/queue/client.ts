import { ConnectionOptions } from 'bullmq';

const redisUrlString = process.env.REDIS_URL || 'redis://127.0.0.1:6379';

/**
 * Safely parses the REDIS_URL environment variable to extract standard ConnectionOptions.
 * Automatically supports TLS protocols ('rediss://') and username/password credentials.
 */
export function getRedisConnectionOptions(): ConnectionOptions {
  try {
    const parsed = new URL(redisUrlString);
    return {
      host: parsed.hostname || '127.0.0.1',
      port: parsed.port ? parseInt(parsed.port, 10) : 6379,
      username: parsed.username ? decodeURIComponent(parsed.username) : undefined,
      password: parsed.password ? decodeURIComponent(parsed.password) : undefined,
      tls: parsed.protocol === 'rediss:' ? {} : undefined,
    };
  } catch (err) {
    console.warn(`Failed to parse REDIS_URL: "${redisUrlString}". Falling back to default Redis configuration.`, err);
    return {
      host: '127.0.0.1',
      port: 6379,
    };
  }
}

export const redisConnection = getRedisConnectionOptions();

export default redisConnection;
