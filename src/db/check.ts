import postgres from 'postgres';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const sql = postgres(databaseUrl, { max: 1, prepare: false });
try {
  const rows = await sql<{ name: string }[]>`
    select tablename as name
    from pg_tables
    where schemaname = 'public'
      and tablename in ('agents', 'agent_passports', 'ledger_transactions', 'ledger_entries', 'audit_events')
    order by tablename
  `;
  if (rows.length !== 5) throw new Error(`foundation schema incomplete: found ${rows.length}/5 critical tables`);
  console.log(rows.map((row) => row.name).join(','));
} finally {
  await sql.end();
}
