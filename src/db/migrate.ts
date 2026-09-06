import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import postgres from 'postgres';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const sql = postgres(databaseUrl, { max: 1, prepare: false });
const migrationUrl = new URL('../../db/migrations/0001_foundation.sql', import.meta.url);
const migration = await readFile(fileURLToPath(migrationUrl), 'utf8');
try {
  await sql.unsafe(migration);
  console.log('migration 0001_foundation applied');
} finally {
  await sql.end();
}
