import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { testHeaderAuthenticator } from '../src/auth.js';
import { signSandboxWebhook } from '../src/crypto.js';
import { PassportSigner } from '../src/domain.js';
import { SandboxPaymentProvider } from '../src/payments/sandbox.js';
import { buildApp } from '../src/server.js';
import { MemoryPlatformStore } from '../src/store.js';

const secret = '01234567890123456789012345678901';

async function createFixture() {
  const store = new MemoryPlatformStore();
  const signer = PassportSigner.ephemeral('https://credalyx.test');
  const app = await buildApp({
    store,
    signer,
    authenticate: testHeaderAuthenticator(),
    paymentProvider: new SandboxPaymentProvider(),
    config: {
      nodeEnv: 'test',
      publicBaseUrl: 'https://credalyx.test',
      passportPriceMinor: 200n,
      referralCommissionMinor: 100n,
      referralHoldDays: 30,
      minPayoutMinor: 2500n,
      passportTtlDays: 30,
      sandboxWebhookSecret: secret,
    },
  });
  return { app, store };
}

async function registerAndVerify(app: Awaited<ReturnType<typeof buildApp>>, owner: string, referralCode?: string) {
  const pair = generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const created = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: { 'x-test-subject': owner },
    payload: {
      public_key_pem: publicKeyPem,
      endpoint: `https://${owner}.example/a2a`,
      capabilities: ['orders.create'],
      ...(referralCode ? { referral_code: referralCode } : {}),
    },
  });
  assert.equal(created.statusCode, 201, created.body);
  const createdBody = created.json<{ agent_id: string; referral_code: string }>();
  const challengeResponse = await app.inject({
    method: 'POST',
    url: `/v1/agents/${createdBody.agent_id}/challenge`,
    headers: { 'x-test-subject': owner },
  });
  assert.equal(challengeResponse.statusCode, 200, challengeResponse.body);
  const challenge = challengeResponse.json<{ challenge: string; signing_payload: string }>();
  const signature = sign(null, Buffer.from(challenge.signing_payload), pair.privateKey).toString('base64url');
  const verified = await app.inject({
    method: 'POST',
    url: `/v1/agents/${createdBody.agent_id}/verify-control`,
    headers: { 'x-test-subject': owner },
    payload: { challenge: challenge.challenge, signature },
  });
  assert.equal(verified.statusCode, 200, verified.body);
  return { ...createdBody, pair, challenge, signature };
}

async function createCheckout(app: Awaited<ReturnType<typeof buildApp>>, owner: string, agentId: string, key: string) {
  const response = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/passport-checkout`,
    headers: { 'x-test-subject': owner, 'idempotency-key': key },
  });
  assert.equal(response.statusCode, 201, response.body);
  return response.json<{ purchase_id: string; amount_minor: string; checkout_url: string }>();
}

async function sendPaymentEvent(app: Awaited<ReturnType<typeof buildApp>>, event: Record<string, unknown>) {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = signSandboxWebhook(secret, timestamp, event);
  return app.inject({
    method: 'POST',
    url: '/v1/webhooks/payment-provider',
    headers: { 'x-sandbox-timestamp': String(timestamp), 'x-sandbox-signature': signature },
    payload: event,
  });
}

test('vertical MVP requires checkout correlation before passport issuance and handles refund', async (t) => {
  const { app, store } = await createFixture();
  t.after(async () => app.close());
  const registered = await registerAndVerify(app, 'owner-a');

  const forgedButSigned = {
    event_id: 'evt_without_checkout',
    type: 'payment.succeeded',
    purchase_id: 'pur_not_created',
    agent_id: registered.agent_id,
    amount_minor: 200,
    currency: 'USD',
  };
  const missingCheckout = await sendPaymentEvent(app, forgedButSigned);
  assert.equal(missingCheckout.statusCode, 404);

  const checkout = await createCheckout(app, 'owner-a', registered.agent_id, 'idem-owner-a-0001');
  assert.equal(checkout.amount_minor, '200');
  assert.match(checkout.checkout_url, /^https:\/\/checkout\.sandbox\.credalyx\.invalid\//);
  const retryCheckout = await createCheckout(app, 'owner-a', registered.agent_id, 'idem-owner-a-0001');
  assert.equal(retryCheckout.purchase_id, checkout.purchase_id);

  const payment = {
    event_id: 'evt_001',
    type: 'payment.succeeded',
    purchase_id: checkout.purchase_id,
    agent_id: registered.agent_id,
    amount_minor: 200,
    currency: 'USD',
  } as const;
  const paid = await sendPaymentEvent(app, payment);
  assert.equal(paid.statusCode, 201, paid.body);
  const { passport_id: passportId } = paid.json<{ passport_id: string }>();
  assert.equal(store.ledgerTransactions.size, 1);

  const duplicate = await sendPaymentEvent(app, payment);
  assert.equal(duplicate.statusCode, 200, duplicate.body);
  assert.equal(store.ledgerTransactions.size, 1);

  const secondCheckout = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agent_id}/passport-checkout`,
    headers: { 'x-test-subject': 'owner-a', 'idempotency-key': 'idem-owner-a-0002' },
  });
  assert.equal(secondCheckout.statusCode, 409);

  const valid = await app.inject({ method: 'POST', url: `/v1/passports/${passportId}/verify` });
  assert.equal(valid.json<{ valid: boolean }>().valid, true);

  const refund = {
    event_id: 'evt_refund_001',
    type: 'payment.refunded',
    purchase_id: checkout.purchase_id,
    amount_minor: 200,
    currency: 'USD',
    reason_code: 'customer_refund',
  } as const;
  const reversed = await sendPaymentEvent(app, refund);
  assert.equal(reversed.statusCode, 200, reversed.body);
  assert.equal(reversed.json<{ reversed: boolean }>().reversed, true);
  assert.equal(store.ledgerTransactions.size, 2);

  const invalidAfterRefund = await app.inject({ method: 'POST', url: `/v1/passports/${passportId}/verify` });
  assert.equal(invalidAfterRefund.json<{ valid: boolean }>().valid, false);

  const duplicateRefund = await sendPaymentEvent(app, refund);
  assert.equal(duplicateRefund.statusCode, 200);
  assert.equal(store.ledgerTransactions.size, 2);
});

test('referral commission moves pending -> available after hold and reverses on chargeback', async (t) => {
  const { app, store } = await createFixture();
  t.after(async () => app.close());

  const referrer = await registerAndVerify(app, 'owner-referrer');
  const referrerCheckout = await createCheckout(app, 'owner-referrer', referrer.agent_id, 'idem-referrer-0001');
  const referrerPaid = await sendPaymentEvent(app, {
    event_id: 'evt_referrer_paid',
    type: 'payment.succeeded',
    purchase_id: referrerCheckout.purchase_id,
    agent_id: referrer.agent_id,
    amount_minor: 200,
    currency: 'USD',
  });
  assert.equal(referrerPaid.statusCode, 201, referrerPaid.body);

  const referred = await registerAndVerify(app, 'owner-referred', referrer.referral_code);
  const referredCheckout = await createCheckout(app, 'owner-referred', referred.agent_id, 'idem-referred-0001');
  const referredPaid = await sendPaymentEvent(app, {
    event_id: 'evt_referred_paid',
    type: 'payment.succeeded',
    purchase_id: referredCheckout.purchase_id,
    agent_id: referred.agent_id,
    amount_minor: 200,
    currency: 'USD',
  });
  assert.equal(referredPaid.statusCode, 201, referredPaid.body);

  const pendingWallet = await app.inject({
    method: 'GET',
    url: `/v1/wallet?agent_id=${referrer.agent_id}`,
    headers: { 'x-test-subject': 'owner-referrer' },
  });
  assert.equal(pendingWallet.statusCode, 200, pendingWallet.body);
  assert.equal(pendingWallet.json<{ pending_minor: string }>().pending_minor, '100');

  const referrerInternal = await store.getAgent(referrer.agent_id);
  assert.ok(referrerInternal);
  const release = await store.releaseEligibleCommissions(new Date(Date.now() + 31 * 86_400_000), 100);
  assert.equal(release.released, 1);
  assert.equal(release.amountMinor, 100n);
  const available = await store.getWallet(referrerInternal.id, 2500n);
  assert.equal(available.pendingMinor, 0n);
  assert.equal(available.availableMinor, 100n);
  assert.equal(available.payoutEligible, false);

  const chargeback = await sendPaymentEvent(app, {
    event_id: 'evt_chargeback_001',
    type: 'payment.chargeback',
    purchase_id: referredCheckout.purchase_id,
    amount_minor: 200,
    currency: 'USD',
    reason_code: 'provider_chargeback',
  });
  assert.equal(chargeback.statusCode, 200, chargeback.body);
  assert.equal(chargeback.json<{ commission_reversed: boolean }>().commission_reversed, true);

  const afterChargeback = await store.getWallet(referrerInternal.id, 2500n);
  assert.equal(afterChargeback.pendingMinor, 0n);
  assert.equal(afterChargeback.availableMinor, 0n);
  assert.equal(afterChargeback.reversedMinor, 100n);
  assert.equal(afterChargeback.payoutEligible, false);
});

test('tenant owner cannot open checkout or wallet for another owner', async (t) => {
  const { app } = await createFixture();
  t.after(async () => app.close());
  const registered = await registerAndVerify(app, 'owner-a');
  const checkout = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agent_id}/passport-checkout`,
    headers: { 'x-test-subject': 'owner-b', 'idempotency-key': 'idem-owner-b-0001' },
  });
  assert.equal(checkout.statusCode, 403);
  const wallet = await app.inject({
    method: 'GET',
    url: `/v1/wallet?agent_id=${registered.agent_id}`,
    headers: { 'x-test-subject': 'owner-b' },
  });
  assert.equal(wallet.statusCode, 403);
});

test('A2A discovery card uses v1.0 supportedInterfaces structure', async (t) => {
  const { app } = await createFixture();
  t.after(async () => app.close());
  const response = await app.inject({ method: 'GET', url: '/.well-known/agent-card.json' });
  assert.equal(response.statusCode, 200);
  const card = response.json<{ supportedInterfaces: Array<{ protocolVersion: string }>; protocolVersion?: string }>();
  assert.equal(card.supportedInterfaces[0]?.protocolVersion, '1.0');
  assert.equal(card.protocolVersion, undefined);
});
