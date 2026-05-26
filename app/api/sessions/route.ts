import { NextRequest, NextResponse } from 'next/server';
import { createSession } from '@/lib/db/sessions';

/**
 * POST /api/sessions
 * Creates a new security analysis session.
 */
export async function POST(req: NextRequest): Promise<Response> {
  try {
    const body = await req.json();
    const { name, logSource } = body;

    if (!name || !logSource) {
      return NextResponse.json(
        { error: 'Missing required parameters: "name" and "logSource".' },
        { status: 400 }
      );
    }

    // Default mock user ID in case standard auth sessions are not fully present
    const userId = 'operator-admin';

    const session = await createSession(userId, name, logSource);
    return NextResponse.json(session);
  } catch (err: any) {
    console.error('Failed to create session:', err);
    return NextResponse.json({ error: err.message || 'Server error' }, { status: 500 });
  }
}
