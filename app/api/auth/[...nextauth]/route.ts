import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import GoogleProvider from 'next-auth/providers/google';
import { getUserByEmail, createUserWithPassword, updateUserPassword, upsertUser } from '@/lib/db/users';

const authOptions = {
  providers: [
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
        if (!credentials?.email || !credentials?.password) {
          return null;
        }

        const email = credentials.email.toLowerCase().trim();
        const password = credentials.password;

        // Support standard development operator credentials
        if (email === 'admin@sec.company' && password === 'admin') {
          return {
            id: 'dev-operator-1',
            name: 'Lead SOC Analyst',
            email: 'admin@sec.company',
            image: null
          };
        }

        try {
          const user = await getUserByEmail(email);

          if (user) {
            // User exists, verify password
            if (user.password === password) {
              return {
                id: user.id,
                name: user.name || email.split('@')[0],
                email: user.email,
                image: user.image
              };
            }
            
            // If user exists but has no password (e.g. legacy user), set it on first login!
            if (!user.password) {
              await updateUserPassword(user.email, password);
              return {
                id: user.id,
                name: user.name || email.split('@')[0],
                email: user.email,
                image: user.image
              };
            }

            console.warn(`Auth failed: Incorrect password for user ${email}`);
            return null;
          } else {
            // User does not exist, automatically register / create password!
            const newUser = await createUserWithPassword({
              name: email.split('@')[0],
              email: email,
              password: password
            });

            console.log(`Successfully registered new analyst account: ${email}`);
            return {
              id: newUser.id,
              name: newUser.name || email.split('@')[0],
              email: newUser.email,
              image: newUser.image
            };
          }
        } catch (err) {
          console.error('Error during Operator credentials authorization:', err);
          return null;
        }
      }
    })
  ],
  pages: {
    signIn: '/auth/signin',
  },
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
