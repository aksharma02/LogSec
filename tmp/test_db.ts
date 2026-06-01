import { getUserByEmail } from '../lib/db/users';

async function run() {
  console.log('--- DB USER QUERY TEST ---');
  try {
    const user = await getUserByEmail('admin@sec.company');
    console.log('Successfully queried database! Result:', user);
  } catch (err) {
    console.error('Database query crashed with error:', err);
  }
}

run();
