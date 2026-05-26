import { runMigrations } from '../lib/db/migrations';

async function main() {
  try {
    console.log("Triggering official PostgreSQL database schema migrations...");
    await runMigrations();
    console.log("PostgreSQL schema successfully initialized!");
    process.exit(0);
  } catch (err: any) {
    console.error("Migration failed:", err);
    process.exit(1);
  }
}

main();
