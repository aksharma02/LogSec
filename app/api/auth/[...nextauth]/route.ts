import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { getUserByEmail, createUserWithPassword, upsertUser } from '@/lib/db/users';

const authOptions = {
  providers: [
    CredentialsProvider({
      name: 'Security Analyst Portal',
      credentials: {
        email: { label: "Operator Email", type: "email" },
        password: { label: "Security Password", type: "password" },
        isSignUp: { type: "text" } // 'true' or 'false'
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null;
        }

        const email = credentials.email.toLowerCase().trim();
        const password = credentials.password;
        const isSignUp = credentials.isSignUp === 'true';

        // Support standard development operator credentials for login
        if (!isSignUp && email === 'admin@sec.company' && password === 'admin') {
          return {
            id: 'dev-operator-1',
            name: 'Lead SOC Analyst',
            email: 'admin@sec.company',
            image: null
          };
        }

        try {
          const user = await getUserByEmail(email);

          if (isSignUp) {
            // Registration mode
            if (user) {
              // Account already exists under this email, block duplicate signup
              throw new Error('AccountAlreadyExists');
            }

            // Create new operator
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
          } else {
            // Sign In mode
            if (!user) {
              throw new Error('AccountDoesNotExist');
            }

            // User exists, verify password
            if (user.password === password) {
              return {
                id: user.id,
                name: user.name || email.split('@')[0],
                email: user.email,
                image: user.image
              };
            }

            throw new Error('IncorrectPassword');
          }
        } catch (err: any) {
          console.warn('Operator authorization error:', err.message);
          // Pass the specific error message to NextAuth client callback
          throw err;
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
