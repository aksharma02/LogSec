'use client';

import { SessionProvider } from 'next-auth/react';
import React from 'react';

/**
 * Client provider wrapper to expose NextAuth session contexts across dashboard views.
 */
export default function AuthProvider({ children }: { children: React.ReactNode }) {
  return <SessionProvider>{children}</SessionProvider>;
}
