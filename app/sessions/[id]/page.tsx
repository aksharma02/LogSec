import React from 'react';
import { notFound } from 'next/navigation';
import { getSession } from '@/lib/db/sessions';
import { getFindingsBySession } from '@/lib/db/findings';
import { getEntriesBySession } from '@/lib/db/logEntries';
import { getQaHistoryBySession } from '@/lib/db/qaHistory';
import SessionDashboard from '@/components/SessionDashboard';

// Force Next.js to render this route dynamically on every request
export const revalidate = 0;

interface SessionPageProps {
  params: {
    id: string;
  };
}

/**
 * Server component that fetches session details, findings, logs history,
 * and previous chat responses in parallel before rendering the interactive dashboard.
 */
export default async function SessionPage({ params }: SessionPageProps) {
  const sessionId = params.id;

  try {
    // 1. Execute safe parallel database fetches
    const [session, findings, logEntries, qaHistory] = await Promise.all([
      getSession(sessionId),
      getFindingsBySession(sessionId),
      getEntriesBySession(sessionId),
      getQaHistoryBySession(sessionId),
    ]);

    // Handle session not found
    if (!session) {
      console.warn(`Audit Session UUID ${sessionId} not found in database.`);
      return notFound();
    }

    // 2. Render the interactive Client Dashboard layout
    return (
      <SessionDashboard
        session={session}
        findings={findings}
        logEntries={logEntries}
        qaHistory={qaHistory}
      />
    );
  } catch (err) {
    console.error('Fatal error loading security audit session page:', err);
    return notFound();
  }
}
