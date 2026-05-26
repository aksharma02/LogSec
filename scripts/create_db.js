const { Client } = require('pg');

async function main() {
  // Connect to the default 'postgres' database which always exists
  const client = new Client({
    connectionString: "postgresql://postgres:postgres@localhost:5432/postgres"
  });

  try {
    await client.connect();
    console.log("Connected to default 'postgres' database successfully.");
    
    // Check if ai_sec_analyzer database already exists
    const res = await client.query("SELECT 1 FROM pg_database WHERE datname='ai_sec_analyzer'");
    if (res.rowCount === 0) {
      console.log("Creating database 'ai_sec_analyzer'...");
      await client.query("CREATE DATABASE ai_sec_analyzer");
      console.log("Database 'ai_sec_analyzer' created successfully!");
    } else {
      console.log("Database 'ai_sec_analyzer' already exists!");
    }
  } catch (err) {
    console.error("Failed to provision database 'ai_sec_analyzer':", err.message);
  } finally {
    await client.end();
  }
}

main();
