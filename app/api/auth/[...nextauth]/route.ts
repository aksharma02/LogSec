import NextAuth from 'next-auth';
import GithubProvider from 'next-auth/providers/github';
import GoogleProvider from 'next-auth/providers/google';
import CredentialsProvider from 'next-auth/providers/credentials';
import { upsertUser } from '@/lib/db/users';

const authOptions = {
  providers: [
    GithubProvider({
      clientId: process.env.GITHUB_CLIENT_ID || 'mock-github-client-id',
      clientSecret: process.env.GITHUB_CLIENT_SECRET || 'mock-github-client-secret',
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID || 'mock-google-client-id',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'mock-google-client-secret',
    }),
    CredentialsProvider({
      name: 'Security Analyst Portal',
      credentials: {
        email: { label: "Operator Email", type: "email", placeholder: "admin@sec.company" },
        password: { label: "Security Password", type: "password", placeholder: "admin" }
      },
      async authorize(credentials) {
        // Support standard development operator credentials
        if (credentials?.email === 'admin@sec.company' && credentials?.password === 'admin') {
          return {
            id: 'dev-operator-1',
            name: 'Lead SOC Analyst',
            email: 'admin@sec.company',
            image: null
          };
        }
        // Let operators register or test with custom emails under the 'admin' password
        if (credentials?.email && credentials?.password === 'admin') {
          return {
            id: 'custom-operator',
            name: credentials.email.split('@')[0],
            email: credentials.email,
            image: null
          };
        }
        return null;
      }
    })
  ],
  callbacks: {
    async signIn({ user }: any) {
      if (user.email) {
        try {
          // Persist user parameters inside PostgreSQL users database table
          await upsertUser({
            name: user.name,
            email: user.email,
            image: user.image,
          });
          console.log(`Successfully persisted authenticated NextAuth operator: ${user.email}`);
        } catch (err) {
          console.error('Failed to persist NextAuth operator to PostgreSQL:', err);
        }
      }
      return true;
    },
    async session({ session, token }: any) {
      if (session.user) {
        session.user.id = token.sub;
      }
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET || 'mock-secret-key-12345',
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
export { authOptions };
