import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { uuidv7 } from '../src/crypto.js';
import type { AgentRecord, LedgerEntry } from '../src/domain.js';
import { SandboxPayoutProvider } from '../src/payouts/sandbox.js';
import { MemoryPayoutStore } from '../src/payouts/store.js';
import { MemoryPlatformStore } from '../src/store.js';

function fixture() {
  const platform = new MemoryPlatformStore();
  const payouts = new MemoryPayoutStore(platform);
  const provider = new SandboxPayoutProvider();
  const pair = generateKeyPairSync('ed25519');
  const agent: AgentRecord = {
    id: uuidv7(),
    publicId: `apn_${uuidv7().replaceAll('-', '')}`,
    ownerSubject: 'owner-payout-store',
    publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    endpoint: 'https://payout-store.example/a2a',
    capabilities: ['payout.test'],
    verificationLevel: 1,
    status: 'active',
    controlVerifiedAt: new Date().toISOString(),
    referralCode: `ref_${uuidv7().replaceAll('-', '')}`,
    version: 1,
  };
  platform.agents.set(agent.publicId, structuredClone(agent));
  const entries: LedgerEntry[] = [
    { account: 'passport_revenue', scopeType: 'platform', scopeId: 'platform', amountMinor: 500n, currency: 'USD' },
    { account: 'agent_owner_available_balance', scopeType: 'agent', scopeId: agent.id, amountMinor: -500n, currency: 'USD' },
  ];
  platform.ledgerTransactions.set('seed:payout-store', {
    id: uuidv7(),
    idempotencyKey: 'seed:payout-store',
    transactionType: 'test_reward_seed',
    externalReference: 'seed',
    createdAt: new Date().toISOString(),
    entries,
  });
  return { platform, payouts, provider, agent };
}

async function reserveProcessing() {
  const { platform, payouts, provider, agent } = fixture();
  const session = await provider.createOnboardingSession({
    beneficiaryReference: `owner:${agent.ownerSubject}`,
    idempotencyKey: 'onboard-payout-store-0001',
    returnUrl: 'https://credalyx.test/return',
    refreshUrl: 'https://credalyx.test/refresh',
  });
  const account = await payouts.upsertPayoutAccount(agent, session, new Date());
  const reservation = await payouts.reservePayout({
    agent,
    payoutAccount: account,
    payoutReference: 'pay_store_001',
    idempotencyKey: 'payout-store-idempotency-0001',
    amountMinor: 100n,
    currency: 'USD',
    assessment: { decision: 'approve', score: 0, reasons: [] },
    reservedAt: new Date(),
  });
  const providerPayout = await provider.createPayout({
    payoutReference: reservation.payout.payoutReference,
    providerAccountId: account.providerAccountId,
    amountMinor: 100n,
    currency: 'USD',
    idempotencyKey: 'payout-store-idempotency-0001',
  });
  const payout = await payouts.markSubmitted(reservation.payout.payoutReference, providerPayout, new Date());
  return { platform, payouts, agent, payout };
}

test('mismatched provider payout event is rejected before ledger settlement', async () => {
  const { platform, payouts, payout } = await reserveProcessing();
  const beforeLedgerSize = platform.ledgerTransactions.size;
  await assert.rejects(
    payouts.applyProviderEvent({
      provider: payout.provider,
      eventId: 'evt_mismatch_amount',
      eventType: 'payout.paid',
      payloadHash: 'hash',
      payoutReference: payout.payoutReference,
      providerPayoutId: payout.providerPayoutId!,
      amountMinor: 101n,
      currency: 'USD',
      occurredAt: new Date(),
    }),
    /provider event mismatch/,
  );
  assert.equal(platform.ledgerTransactions.size, beforeLedgerSize);
  assert.equal((await payouts.getPayout(payout.payoutReference))?.status, 'processing');
});

test('replayed payout success event creates settlement exactly once', async () => {
  const { platform, payouts, agent, payout } = await reserveProcessing();
  const event = {
    provider: payout.provider,
    eventId: 'evt_paid_once',
    eventType: 'payout.paid' as const,
    payloadHash: 'hash-paid',
    payoutReference: payout.payoutReference,
    providerPayoutId: payout.providerPayoutId!,
    amountMinor: 100n,
    currency: 'USD' as const,
    occurredAt: new Date(),
  };
  const first = await payouts.applyProviderEvent(event);
  assert.equal(first.duplicate, false);
  assert.equal(first.status, 'paid');
  const ledgerAfterFirst = platform.ledgerTransactions.size;
  const second = await payouts.applyProviderEvent(event);
  assert.equal(second.duplicate, true);
  assert.equal(second.status, 'paid');
  assert.equal(platform.ledgerTransactions.size, ledgerAfterFirst);
  const summary = await payouts.getPayoutSummary(agent.id);
  assert.equal(summary.reservedMinor, 0n);
  assert.equal(summary.paidMinor, 100n);
});

test('payout idempotency key cannot be reused for different amount', async () => {
  const { payouts, provider, agent } = fixture();
  const session = await provider.createOnboardingSession({
    beneficiaryReference: `owner:${agent.ownerSubject}`,
    idempotencyKey: 'onboard-payout-store-0002',
    returnUrl: 'https://credalyx.test/return',
    refreshUrl: 'https://credalyx.test/refresh',
  });
  const account = await payouts.upsertPayoutAccount(agent, session, new Date());
  const common = {
    agent,
    payoutAccount: account,
    payoutReference: 'pay_store_idem',
    idempotencyKey: 'payout-store-idempotency-conflict',
    currency: 'USD' as const,
    assessment: { decision: 'approve' as const, score: 0, reasons: [] },
    reservedAt: new Date(),
  };
  await payouts.reservePayout({ ...common, amountMinor: 100n });
  await assert.rejects(
    payouts.reservePayout({ ...common, payoutReference: 'pay_store_other', amountMinor: 200n }),
    /idempotency key reused with different parameters/,
  );
});
