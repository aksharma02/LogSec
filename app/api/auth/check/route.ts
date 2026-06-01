import { NextResponse } from 'next/server';
import { getUserByEmail } from '@/lib/db/users';
import { runMigrations } from '@/lib/db/migrations';

let migrationsPromise: Promise<void> | null = null;
async function ensureMigrated() {
  if (!migrationsPromise) {
    migrationsPromise = runMigrations().catch(err => {
      console.error('Auto-migration during pre-flight check failed:', err);
    });
  }
  return migrationsPromise;
}

/**
 * Pre-flight check endpoint to safely verify if an operator account exists.
 * Helps the custom login UI dynamically toggle between sign-in and sign-up with high precision.
 */
export async function POST(req: Request) {
  try {
    // 1. Verify if DATABASE_URL environment variable is configured in Render
    const hasDbUrl = !!process.env.DATABASE_URL;
    if (!hasDbUrl) {
      return NextResponse.json({ 
        error: "Render Configuration Warning: DATABASE_URL environment variable is NOT defined in your Render dashboard environment settings! Please create a PostgreSQL database and bind it as DATABASE_URL." 
      }, { status: 500 });
    }

    // Force schema migrations to run automatically on production boot/first request
    await ensureMigrated();

    const { email } = await req.json();
    if (!email) {
      return NextResponse.json({ error: 'Email parameter is required.' }, { status: 400 });
    }

    const trimmedEmail = email.toLowerCase().trim();
    const user = await getUserByEmail(trimmedEmail);

    return NextResponse.json({ exists: !!user });
  } catch (err: any) {
    console.error('Error during Operator account pre-flight check:', err);
    
    // Extract robust error diagnostics
    const errMessage = err instanceof Error ? err.message : String(err);
    const errCode = err && typeof err === 'object' ? err.code || 'NO_CODE' : 'NO_CODE';

    return NextResponse.json({ 
      error: `Database Service Exception [Code ${errCode}]: ${errMessage}` 
    }, { status: 500 });
  }
}
