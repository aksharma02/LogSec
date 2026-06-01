import { NextResponse } from 'next/server';
import { getUserByEmail } from '@/lib/db/users';

/**
 * Pre-flight check endpoint to safely verify if an operator account exists.
 * Helps the custom login UI dynamically toggle between sign-in and sign-up with high precision.
 */
export async function POST(req: Request) {
  try {
    const { email } = await req.json();
    if (!email) {
      return NextResponse.json({ error: 'Email parameter is required.' }, { status: 400 });
    }

    const trimmedEmail = email.toLowerCase().trim();
    const user = await getUserByEmail(trimmedEmail);

    return NextResponse.json({ exists: !!user });
  } catch (err: any) {
    console.error('Error during Operator account pre-flight check:', err);
    return NextResponse.json({ error: 'Internal database service error.' }, { status: 500 });
  }
}
