import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import postgres from 'postgres';
import { uuidv7 } from '../src/crypto.js';
import { PostgresLifecyclePlatformStore } from '../src/db/store-postgres-lifecycle.js';
import type { AgentRecord } from '../src/domain.js';

const databaseUrl = process.env.DATABASE_URL;

test('non-zero payout risk assessment emits a normalized risk signal', { skip: !databaseUrl }, async (t) => {
  const platform = new PostgresLifecyclePlatformStore(databaseUrl!);
  const sql = postgres(databaseUrl!, { max: 1, prepare: false });
  t.after(async () => {
    await Promise.all([platform.close(), sql.end()]);
  });

  const pair = generateKeyPairSync('ed25519');
  const agent: AgentRecord = {
    id: uuidv7(),
    publicId: `apn_risk_${uuidv7().replaceAll('-', '')}`,
    ownerSubject: `risk-owner-${Date.now()}`,
    publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    endpoint: 'https://risk-signal.example/a2a',
    capabilities: ['payout.risk.test'],
    verificationLevel: 0,
    status: 'pending',
    referralCode: `ref_risk_${uuidv7().replaceAll('-', '')}`,
    version: 1,
  };
  await platform.createAgent(agent);

  const assessmentId = uuidv7();
  await sql`
    insert into payout_risk_assessments (
      id, agent_id, idempotency_key, amount_minor, currency, decision, score, reasons, created_at
    ) values (
      ${assessmentId}, ${agent.id}, ${`risk-signal-${assessmentId}`}, 5000, 'USD', 'review', 40,
      ${sql.json(['amount_above_auto_approve_limit'])}, now()
    )
  `;

  const rows = await sql<{ signal_type: string; score: number; metadata: { decision?: string; idempotency_key?: string } }[]>`
    select signal_type, score, metadata
    from risk_signals
    where id = ${assessmentId}
    limit 1
  `;
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.signal_type, 'payout_risk_assessment');
  assert.equal(rows[0]!.score, 40);
  assert.equal(rows[0]!.metadata.decision, 'review');
  assert.equal(rows[0]!.metadata.idempotency_key, `risk-signal-${assessmentId}`);
});

test('zero-risk approved assessment does not create a risk signal', { skip: !databaseUrl }, async (t) => {
  const platform = new PostgresLifecyclePlatformStore(databaseUrl!);
  const sql = postgres(databaseUrl!, { max: 1, prepare: false });
  t.after(async () => {
    await Promise.all([platform.close(), sql.end()]);
  });

  const pair = generateKeyPairSync('ed25519');
  const agent: AgentRecord = {
    id: uuidv7(),
    publicId: `apn_clean_${uuidv7().replaceAll('-', '')}`,
    ownerSubject: `clean-risk-owner-${Date.now()}`,
    publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    endpoint: 'https://clean-risk.example/a2a',
    capabilities: ['payout.risk.test'],
    verificationLevel: 0,
    status: 'pending',
    referralCode: `ref_clean_${uuidv7().replaceAll('-', '')}`,
    version: 1,
  };
  await platform.createAgent(agent);

  const assessmentId = uuidv7();
  await sql`
    insert into payout_risk_assessments (
      id, agent_id, idempotency_key, amount_minor, currency, decision, score, reasons, created_at
    ) values (
      ${assessmentId}, ${agent.id}, ${`clean-risk-${assessmentId}`}, 2500, 'USD', 'approve', 0,
      ${sql.json([])}, now()
    )
  `;

  const rows = await sql<{ id: string }[]>`select id from risk_signals where id = ${assessmentId}`;
  assert.equal(rows.length, 0);
});
