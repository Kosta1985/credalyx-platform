import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import postgres from 'postgres';
import { uuidv7 } from '../src/crypto.js';
import { PostgresLifecyclePlatformStore } from '../src/db/store-postgres-lifecycle.js';
import type { AgentRecord } from '../src/domain.js';

const databaseUrl = process.env.DATABASE_URL;

test('PostgreSQL rejects payout account substitution across owners', { skip: !databaseUrl }, async (t) => {
  const store = new PostgresLifecyclePlatformStore(databaseUrl!);
  const sql = postgres(databaseUrl!, { max: 1, prepare: false });
  t.after(async () => Promise.all([store.close(), sql.end()]));

  const runId = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  async function createAgent(ownerSubject: string): Promise<AgentRecord> {
    const pair = generateKeyPairSync('ed25519');
    const agent: AgentRecord = {
      id: uuidv7(),
      publicId: `apn_guard_${uuidv7().replaceAll('-', '')}`,
      ownerSubject,
      publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      endpoint: `https://${ownerSubject}.example/a2a`,
      capabilities: ['payout.guard.test'],
      verificationLevel: 0,
      status: 'pending',
      referralCode: `ref_guard_${uuidv7().replaceAll('-', '')}`,
      version: 1,
    };
    await store.createAgent(agent);
    return agent;
  }

  const ownerA = `guard-owner-a-${runId}`;
  const ownerB = `guard-owner-b-${runId}`;
  const agentA = await createAgent(ownerA);
  await createAgent(ownerB);

  const ownerBRows = await sql<{ id: string }[]>`
    select id from users where external_subject = ${ownerB} limit 1
  `;
  assert.ok(ownerBRows[0]);
  const foreignAccountId = uuidv7();
  await sql`
    insert into payout_accounts (
      id, owner_user_id, provider, provider_account_id, onboarding_status, created_at, updated_at
    ) values (
      ${foreignAccountId}, ${ownerBRows[0]!.id}, 'sandbox-payout', ${`acct_foreign_${runId}`}, 'complete', now(), now()
    )
  `;

  await assert.rejects(
    sql`
      insert into payouts (
        id, payout_account_id, agent_id, provider, payout_reference, amount_minor, currency,
        status, idempotency_key, risk_decision, risk_score, reserved_at, created_at
      ) values (
        ${uuidv7()}, ${foreignAccountId}, ${agentA.id}, 'sandbox-payout', ${`pay_guard_${runId}`},
        100, 'USD', 'pending', ${`guard-idem-${runId}`}, 'approve', 0, now(), now()
      )
    `,
    /payout account owner does not match agent owner/,
  );
});
