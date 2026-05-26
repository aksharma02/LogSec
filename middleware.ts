import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getToken } from 'next-auth/jwt';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

// Initialize the Upstash Redis client for edge middleware environments
let redis: Redis | null = null;
try {
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });
  }
} catch (err) {
  console.warn('Middleware failed to initialize Upstash Redis Rest client:', err);
}

// Instantiate specific rate limiters using sliding windows
const analyzeLimiter = redis
  ? new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(20, '1 h'), // 20 req / user / hour
      prefix: 'ratelimit:analyze',
    })
  : null;

const uploadLimiter = redis
  ? new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(10, '24 h'), // 10 req / user / day
      prefix: 'ratelimit:upload',
    })
  : null;

const reportLimiter = redis
  ? new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(5, '24 h'), // 5 req / user / day
      prefix: 'ratelimit:report',
    })
  : null;

/**
 * Next.js Edge Middleware for routing controls.
 * Gates dashboard paths and runs rate limiting over core security endpoints.
 */
export async function middleware(req: NextRequest) {
  const pathname = req.nextUrl.pathname;
  const secret = process.env.NEXTAUTH_SECRET || 'mock-secret-key-12345';

  // 1. NextAuth Authentication Gate
  if (pathname.startsWith('/sessions/')) {
    const token = await getToken({ req, secret });
    if (!token) {
      // Redirect unauthenticated operator attempts to sign-in portal
      const loginUrl = new URL('/api/auth/signin', req.url);
      loginUrl.searchParams.set('callbackUrl', req.url);
      return NextResponse.redirect(loginUrl);
    }
  }

  // 2. API Rate Limiting Gate (only execute if Upstash is configured)
  if (!redis) {
    return NextResponse.next();
  }

  // Resolve user identifier via token sub or email (fallback to anonymous context)
  const token = await getToken({ req, secret });
  const userId = token?.email || token?.sub || 'anonymous-operator';

  // Path matches for Q&A Analysis
  if (pathname.startsWith('/api/analyze')) {
    if (analyzeLimiter) {
      const { success, reset } = await analyzeLimiter.limit(userId);
      if (!success) {
        const seconds = Math.max(0, Math.ceil((reset - Date.now()) / 1000));
        return new NextResponse(
          JSON.stringify({ error: 'Rate limit exceeded', retryAfter: seconds }),
          { status: 429, headers: { 'Content-Type': 'application/json' } }
        );
      }
    }
  }

  // Path matches for log uploads
  if (pathname.startsWith('/api/upload')) {
    if (uploadLimiter) {
      const { success, reset } = await uploadLimiter.limit(userId);
      if (!success) {
        const seconds = Math.max(0, Math.ceil((reset - Date.now()) / 1000));
        return new NextResponse(
          JSON.stringify({ error: 'Rate limit exceeded', retryAfter: seconds }),
          { status: 429, headers: { 'Content-Type': 'application/json' } }
        );
      }
    }
  }

  // Path matches for PDF report exports
  if (pathname.match(/^\/api\/sessions\/[^/]+\/report$/)) {
    if (reportLimiter) {
      const { success, reset } = await reportLimiter.limit(userId);
      if (!success) {
        const seconds = Math.max(0, Math.ceil((reset - Date.now()) / 1000));
        return new NextResponse(
          JSON.stringify({ error: 'Rate limit exceeded', retryAfter: seconds }),
          { status: 429, headers: { 'Content-Type': 'application/json' } }
        );
      }
    }
  }

  return NextResponse.next();
}

// Config matchers covering security paths and critical API routes
export const config = {
  matcher: [
    '/sessions/:id*',
    '/api/analyze',
    '/api/upload',
    '/api/sessions/:id/report',
  ],
};
