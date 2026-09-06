import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import postgres from 'postgres';
import { uuidv7 } from '../src/crypto.js';
import { PostgresLifecyclePlatformStore } from '../src/db/store-postgres-lifecycle.js';
import type { AgentRecord } from '../src/domain.js';

const databaseUrl = process.env.DATABASE_URL;

test('pure payout policy denial does not create a fraud risk signal, while debt denial does', { skip: !databaseUrl }, async (t) => {
  const platform = new PostgresLifecyclePlatformStore(databaseUrl!);
  const sql = postgres(databaseUrl!, { max: 1, prepare: false });
  t.after(async () => {
    await Promise.all([platform.close(), sql.end()]);
  });

  const pair = generateKeyPairSync('ed25519');
  const agent: AgentRecord = {
    id: uuidv7(),
    publicId: `apn_risk_policy_${uuidv7().replaceAll('-', '')}`,
    ownerSubject: `risk-policy-owner-${Date.now()}`,
    publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    endpoint: 'https://risk-policy.example/a2a',
    capabilities: ['payout.risk.policy.test'],
    verificationLevel: 0,
    status: 'pending',
    referralCode: `ref_risk_policy_${uuidv7().replaceAll('-', '')}`,
    version: 1,
  };
  await platform.createAgent(agent);

  const policyAssessmentId = uuidv7();
  await sql`
    insert into payout_risk_assessments (
      id, agent_id, idempotency_key, amount_minor, currency, decision, score, reasons, created_at
    ) values (
      ${policyAssessmentId}, ${agent.id}, ${`policy-${policyAssessmentId}`}, 50, 'USD', 'deny', 100,
      ${sql.json(['below_minimum_payout'])}, now()
    )
  `;
  const policySignals = await sql<{ id: string }[]>`select id from risk_signals where id = ${policyAssessmentId}`;
  assert.equal(policySignals.length, 0);

  const debtAssessmentId = uuidv7();
  await sql`
    insert into payout_risk_assessments (
      id, agent_id, idempotency_key, amount_minor, currency, decision, score, reasons, created_at
    ) values (
      ${debtAssessmentId}, ${agent.id}, ${`debt-${debtAssessmentId}`}, 2500, 'USD', 'deny', 100,
      ${sql.json(['wallet_has_debt'])}, now()
    )
  `;
  const debtSignals = await sql<{ score: number; metadata: { reasons?: string[] } }[]>`
    select score, metadata from risk_signals where id = ${debtAssessmentId} limit 1
  `;
  assert.equal(debtSignals.length, 1);
  assert.equal(debtSignals[0]!.score, 100);
  assert.deepEqual(debtSignals[0]!.metadata.reasons, ['wallet_has_debt']);
});
