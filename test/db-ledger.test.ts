import assert from 'node:assert/strict';
import test from 'node:test';
import postgres from 'postgres';
import { uuidv7 } from '../src/crypto.js';

const databaseUrl = process.env.DATABASE_URL;

test('database rejects sealing an unbalanced ledger transaction and locks sealed entries', { skip: !databaseUrl }, async () => {
  const sql = postgres(databaseUrl!, { max: 1, prepare: false });
  try {
    const txId = uuidv7();
    const clearingId = uuidv7();
    const revenueId = uuidv7();
    await sql`insert into ledger_accounts (id, code, account_type, scope_type, scope_id) values
      (${clearingId}, 'payment_provider_clearing', 'asset', 'platform', 'platform'),
      (${revenueId}, 'passport_revenue', 'revenue', 'platform', 'platform')
      on conflict (code, scope_type, scope_id) do nothing`;
    const accounts = await sql<{ id: string; code: string }[]>`select id, code from ledger_accounts where scope_type='platform' and scope_id='platform' and code in ('payment_provider_clearing','passport_revenue')`;
    const byCode = new Map(accounts.map((row) => [row.code, row.id]));

    await assert.rejects(sql.begin(async (trx) => {
      await trx`insert into ledger_transactions (id, idempotency_key, external_reference, transaction_type) values (${txId}, ${`test:${txId}`}, 'test', 'test')`;
      await trx`insert into ledger_entries (id, transaction_id, account_id, amount_minor, currency) values
        (${uuidv7()}, ${txId}, ${byCode.get('payment_provider_clearing')!}, 200, 'USD'),
        (${uuidv7()}, ${txId}, ${byCode.get('passport_revenue')!}, -199, 'USD')`;
      await trx`update ledger_transactions set sealed_at = now() where id = ${txId}`;
    }), /unbalanced ledger transaction/);

    const goodTxId = uuidv7();
    await sql.begin(async (trx) => {
      await trx`insert into ledger_transactions (id, idempotency_key, external_reference, transaction_type) values (${goodTxId}, ${`test:${goodTxId}`}, 'test', 'test')`;
      await trx`insert into ledger_entries (id, transaction_id, account_id, amount_minor, currency) values
        (${uuidv7()}, ${goodTxId}, ${byCode.get('payment_provider_clearing')!}, 200, 'USD'),
        (${uuidv7()}, ${goodTxId}, ${byCode.get('passport_revenue')!}, -200, 'USD')`;
      await trx`update ledger_transactions set sealed_at = now() where id = ${goodTxId}`;
    });
    await assert.rejects(
      sql`insert into ledger_entries (id, transaction_id, account_id, amount_minor, currency) values (${uuidv7()}, ${goodTxId}, ${byCode.get('payment_provider_clearing')!}, 1, 'USD')`,
      /is sealed/,
    );
  } finally {
    await sql.end();
  }
});
