import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { testHeaderAuthenticator } from '../src/auth.js';
import { signSandboxWebhook, uuidv7 } from '../src/crypto.js';
import { PassportSigner, type LedgerEntry } from '../src/domain.js';
import { SandboxPaymentProvider } from '../src/payments/sandbox.js';
import { registerPayoutRoutes } from '../src/payouts/routes.js';
import { SandboxPayoutProvider } from '../src/payouts/sandbox.js';
import { MemoryPayoutStore } from '../src/payouts/store.js';
import { buildApp } from '../src/server.js';
import { MemoryPlatformStore } from '../src/store.js';

const paymentSecret = 'payout-test-payment-secret-012345678901';
const payoutSecret = 'payout-test-webhook-secret-012345678901';

async function fixture() {
  const store = new MemoryPlatformStore();
  const payoutStore = new MemoryPayoutStore(store);
  const payoutProvider = new SandboxPayoutProvider();
  const app = await buildApp({
    store,
    signer: PassportSigner.ephemeral('https://credalyx.test'),
    authenticate: testHeaderAuthenticator(),
    paymentProvider: new SandboxPaymentProvider(),
    config: {
      nodeEnv: 'test',
      publicBaseUrl: 'https://credalyx.test',
      passportPriceMinor: 200n,
      referralCommissionMinor: 100n,
      referralHoldDays: 30,
      minPayoutMinor: 100n,
      passportTtlDays: 30,
      sandboxWebhookSecret: paymentSecret,
    },
  });
  registerPayoutRoutes({
    app,
    platform: store,
    store: payoutStore,
    provider: payoutProvider,
    authenticate: testHeaderAuthenticator(),
    config: {
      publicBaseUrl: 'https://credalyx.test',
      minPayoutMinor: 100n,
      autoApproveMaxMinor: 10_000n,
      maxPayoutsPer24h: 3,
      sandboxPayoutWebhookSecret: payoutSecret,
    },
  });
  app.addHook('onClose', async () => payoutStore.close());
  return { app, store, payoutStore };
}

async function registerVerifyAndActivate(
  app: Awaited<ReturnType<typeof buildApp>>,
  owner: string,
  suffix: string,
) {
  const pair = generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const created = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: { 'x-test-subject': owner },
    payload: {
      public_key_pem: publicKeyPem,
      endpoint: `https://${owner}.example/a2a`,
      capabilities: ['payout.test'],
    },
  });
  assert.equal(created.statusCode, 201, created.body);
  const agentId = created.json<{ agent_id: string }>().agent_id;
  const challengeResponse = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/challenge`,
    headers: { 'x-test-subject': owner },
  });
  assert.equal(challengeResponse.statusCode, 200, challengeResponse.body);
  const challenge = challengeResponse.json<{ challenge: string; signing_payload: string }>();
  const verified = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/verify-control`,
    headers: { 'x-test-subject': owner },
    payload: {
      challenge: challenge.challenge,
      signature: sign(null, Buffer.from(challenge.signing_payload), pair.privateKey).toString('base64url'),
    },
  });
  assert.equal(verified.statusCode, 200, verified.body);

  const checkout = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/passport-checkout`,
    headers: { 'x-test-subject': owner, 'idempotency-key': `payout-activation-${suffix}-0001` },
  });
  assert.equal(checkout.statusCode, 201, checkout.body);
  const purchaseId = checkout.json<{ purchase_id: string }>().purchase_id;
  const event = {
    event_id: `evt_payout_activation_${suffix}`,
    type: 'payment.succeeded',
    purchase_id: purchaseId,
    agent_id: agentId,
    amount_minor: 200,
    currency: 'USD',
  } as const;
  const timestamp = Math.floor(Date.now() / 1000);
  const paid = await app.inject({
    method: 'POST',
    url: '/v1/webhooks/payment-provider',
    headers: {
      'x-sandbox-timestamp': String(timestamp),
      'x-sandbox-signature': signSandboxWebhook(paymentSecret, timestamp, event),
    },
    payload: event,
  });
  assert.equal(paid.statusCode, 201, paid.body);
  return agentId;
}

function seedAvailable(store: MemoryPlatformStore, internalAgentId: string, amountMinor: bigint, suffix: string) {
  const entries: LedgerEntry[] = [
    { account: 'passport_revenue', scopeType: 'platform', scopeId: 'platform', amountMinor, currency: 'USD' },
    { account: 'agent_owner_available_balance', scopeType: 'agent', scopeId: internalAgentId, amountMinor: -amountMinor, currency: 'USD' },
  ];
  store.ledgerTransactions.set(`seed:${suffix}`, {
    id: uuidv7(),
    idempotencyKey: `seed:${suffix}`,
    transactionType: 'test_reward_seed',
    externalReference: suffix,
    createdAt: new Date().toISOString(),
    entries,
  });
}

function postAvailableDebit(store: MemoryPlatformStore, internalAgentId: string, amountMinor: bigint, suffix: string) {
  const entries: LedgerEntry[] = [
    { account: 'agent_owner_available_balance', scopeType: 'agent', scopeId: internalAgentId, amountMinor, currency: 'USD' },
    { account: 'chargebacks', scopeType: 'platform', scopeId: 'platform', amountMinor: -amountMinor, currency: 'USD' },
  ];
  store.ledgerTransactions.set(`chargeback:${suffix}`, {
    id: uuidv7(),
    idempotencyKey: `chargeback:${suffix}`,
    transactionType: 'passport_chargeback',
    externalReference: suffix,
    createdAt: new Date().toISOString(),
    entries,
  });
}

async function onboard(app: Awaited<ReturnType<typeof buildApp>>, owner: string, agentId: string, suffix: string) {
  const response = await app.inject({
    method: 'POST',
    url: '/v1/payouts/onboarding',
    headers: { 'x-test-subject': owner, 'idempotency-key': `payout-onboarding-${suffix}-0001` },
    payload: { agent_id: agentId },
  });
  assert.equal(response.statusCode, 201, response.body);
  assert.equal(response.json<{ onboarding_status: string }>().onboarding_status, 'complete');
}

async function payoutWebhook(app: Awaited<ReturnType<typeof buildApp>>, event: Record<string, unknown>) {
  const timestamp = Math.floor(Date.now() / 1000);
  return app.inject({
    method: 'POST',
    url: '/v1/webhooks/payout-provider',
    headers: {
      'x-sandbox-timestamp': String(timestamp),
      'x-sandbox-signature': signSandboxWebhook(payoutSecret, timestamp, event),
    },
    payload: event,
  });
}

test('payout reserves available funds, deduplicates requests, settles on provider success and releases on failure', async (t) => {
  const { app, store, payoutStore } = await fixture();
  t.after(async () => app.close());
  const owner = 'owner-payout-happy';
  const agentId = await registerVerifyAndActivate(app, owner, 'happy');
  const agent = await store.getAgent(agentId);
  assert.ok(agent);
  seedAvailable(store, agent.id, 300n, 'happy');
  await onboard(app, owner, agentId, 'happy');

  const request = {
    method: 'POST' as const,
    url: '/v1/payouts',
    headers: { 'x-test-subject': owner, 'idempotency-key': 'payout-happy-request-0001' },
    payload: { agent_id: agentId, amount_minor: '100' },
  };
  const created = await app.inject(request);
  assert.equal(created.statusCode, 201, created.body);
  const createdBody = created.json<{ payout: { payout_id: string; provider_payout_id: string; status: string } }>().payout;
  assert.equal(createdBody.status, 'processing');
  assert.ok(createdBody.provider_payout_id);
  const reserved = await payoutStore.getPayoutSummary(agent.id);
  assert.equal(reserved.reservedMinor, 100n);
  assert.equal(reserved.paidMinor, 0n);

  const duplicate = await app.inject(request);
  assert.equal(duplicate.statusCode, 200, duplicate.body);
  assert.equal(duplicate.json<{ payout: { payout_id: string } }>().payout.payout_id, createdBody.payout_id);

  const secondWhileOpen = await app.inject({
    method: 'POST',
    url: '/v1/payouts',
    headers: { 'x-test-subject': owner, 'idempotency-key': 'payout-happy-request-0002' },
    payload: { agent_id: agentId, amount_minor: '100' },
  });
  assert.equal(secondWhileOpen.statusCode, 409, secondWhileOpen.body);
  assert.equal(secondWhileOpen.json<{ code: string }>().code, 'PAYOUT_DENIED');

  const paid = await payoutWebhook(app, {
    event_id: 'evt_payout_paid_happy',
    type: 'payout.paid',
    payout_id: createdBody.payout_id,
    provider_payout_id: createdBody.provider_payout_id,
    amount_minor: '100',
    currency: 'USD',
  });
  assert.equal(paid.statusCode, 200, paid.body);
  assert.equal(paid.json<{ status: string }>().status, 'paid');
  const afterPaid = await payoutStore.getPayoutSummary(agent.id);
  assert.equal(afterPaid.reservedMinor, 0n);
  assert.equal(afterPaid.paidMinor, 100n);

  const failedRequest = await app.inject({
    method: 'POST',
    url: '/v1/payouts',
    headers: { 'x-test-subject': owner, 'idempotency-key': 'payout-happy-request-0003' },
    payload: { agent_id: agentId, amount_minor: '100' },
  });
  assert.equal(failedRequest.statusCode, 201, failedRequest.body);
  const failedPayout = failedRequest.json<{ payout: { payout_id: string; provider_payout_id: string } }>().payout;
  const failed = await payoutWebhook(app, {
    event_id: 'evt_payout_failed_happy',
    type: 'payout.failed',
    payout_id: failedPayout.payout_id,
    provider_payout_id: failedPayout.provider_payout_id,
    amount_minor: '100',
    currency: 'USD',
    reason_code: 'recipient_unavailable',
  });
  assert.equal(failed.statusCode, 200, failed.body);
  assert.equal(failed.json<{ status: string }>().status, 'failed');
  const context = await payoutStore.getRiskContext(agent.id, new Date());
  assert.equal(context.availableMinor, 200n, 'failed payout must return reserved funds to available');
});

test('chargeback while payout is processing creates debt that remains after payout settlement', async (t) => {
  const { app, store, payoutStore } = await fixture();
  t.after(async () => app.close());
  const owner = 'owner-payout-chargeback';
  const agentId = await registerVerifyAndActivate(app, owner, 'chargeback');
  const agent = await store.getAgent(agentId);
  assert.ok(agent);
  seedAvailable(store, agent.id, 300n, 'chargeback');
  await onboard(app, owner, agentId, 'chargeback');

  const created = await app.inject({
    method: 'POST',
    url: '/v1/payouts',
    headers: { 'x-test-subject': owner, 'idempotency-key': 'payout-chargeback-request-0001' },
    payload: { agent_id: agentId, amount_minor: '300' },
  });
  assert.equal(created.statusCode, 201, created.body);
  const payout = created.json<{ payout: { payout_id: string; provider_payout_id: string } }>().payout;
  assert.equal((await payoutStore.getPayoutSummary(agent.id)).reservedMinor, 300n);

  postAvailableDebit(store, agent.id, 100n, 'in-flight');
  const during = await payoutStore.getRiskContext(agent.id, new Date());
  assert.equal(during.debtMinor, 100n);

  const paid = await payoutWebhook(app, {
    event_id: 'evt_payout_paid_chargeback',
    type: 'payout.paid',
    payout_id: payout.payout_id,
    provider_payout_id: payout.provider_payout_id,
    amount_minor: '300',
    currency: 'USD',
  });
  assert.equal(paid.statusCode, 200, paid.body);
  const after = await payoutStore.getRiskContext(agent.id, new Date());
  assert.equal(after.debtMinor, 100n, 'settling reserved funds must not hide post-reservation debt');
  assert.equal((await payoutStore.getPayoutSummary(agent.id)).paidMinor, 300n);

  const blocked = await app.inject({
    method: 'POST',
    url: '/v1/payouts',
    headers: { 'x-test-subject': owner, 'idempotency-key': 'payout-chargeback-request-0002' },
    payload: { agent_id: agentId, amount_minor: '100' },
  });
  assert.equal(blocked.statusCode, 409, blocked.body);
  assert.equal(blocked.json<{ code: string }>().code, 'PAYOUT_DENIED');
});
