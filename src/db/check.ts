import postgres from 'postgres';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const sql = postgres(databaseUrl, { max: 1, prepare: false });
try {
  const rows = await sql<{ name: string }[]>`
    select tablename as name
    from pg_tables
    where schemaname = 'public'
      and tablename in (
        'agents',
        'agent_keys',
        'agent_key_rotations',
        'agent_passports',
        'issuer_signing_keys',
        'issuer_key_status_history',
        'ledger_transactions',
        'ledger_entries',
        'audit_events'
      )
    order by tablename
  `;
  if (rows.length !== 9) throw new Error(`foundation schema incomplete: found ${rows.length}/9 critical tables`);

  const columns = await sql<{ table_name: string; column_name: string }[]>`
    select table_name, column_name
    from information_schema.columns
    where table_schema = 'public'
      and (
        (table_name = 'agent_keys' and column_name = 'activated_at')
        or (table_name = 'agent_challenges' and column_name = 'agent_key_id')
        or (table_name = 'agent_passports' and column_name = 'passport_version')
        or (table_name = 'issuer_signing_keys' and column_name = 'key_id')
        or (table_name = 'issuer_signing_keys' and column_name = 'public_jwk')
        or (table_name = 'issuer_signing_keys' and column_name = 'provider_key_reference')
        or (table_name = 'issuer_signing_keys' and column_name = 'status')
      )
    order by table_name, column_name
  `;
  if (columns.length !== 7) {
    throw new Error(`credential/issuer lifecycle schema incomplete: found ${columns.length}/7 required columns`);
  }
  console.log([
    ...rows.map((row) => row.name),
    ...columns.map((row) => `${row.table_name}.${row.column_name}`),
  ].join(','));
} finally {
  await sql.end();
}
