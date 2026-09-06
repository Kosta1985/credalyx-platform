import { readdir, readFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import postgres from 'postgres';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const sql = postgres(databaseUrl, { max: 1, prepare: false });
const migrationsDir = dirname(fileURLToPath(new URL('../../db/migrations/placeholder', import.meta.url)));

try {
  await sql`create table if not exists schema_migrations (
    version text primary key,
    applied_at timestamptz not null default now()
  )`;
  const files = (await readdir(migrationsDir)).filter((file) => file.endsWith('.sql')).sort();
  for (const file of files) {
    const version = basename(file, '.sql');
    const applied = await sql<{ version: string }[]>`select version from schema_migrations where version = ${version}`;
    if (applied[0]) {
      console.log(`migration ${version} already applied`);
      continue;
    }
    const migration = await readFile(join(migrationsDir, file), 'utf8');
    await sql.unsafe(migration);
    await sql`insert into schema_migrations (version) values (${version})`;
    console.log(`migration ${version} applied`);
  }
} finally {
  await sql.end();
}
