import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { testHeaderAuthenticator } from '../src/auth.js';
import { signSandboxWebhook } from '../src/crypto.js';
import { PostgresLifecyclePlatformStore } from '../src/db/store-postgres-lifecycle.js';
import { PassportSigner } from '../src/domain.js';
import { SandboxPaymentProvider } from '../src/payments/sandbox.js';
import { registerPayoutRoutes } from '../src/payouts/routes.js';
import { SandboxPayoutProvider } from '../src/payouts/sandbox.js';
import { PostgresPayoutStore } from '../src/payouts/store-postgres.js';
import { buildApp } from '../src/server.js';

const databaseUrl = process.env.DATABASE_URL;
const paymentSecret = 'db-payout-payment-secret-012345678901234';
const payoutSecret = 'db-payout-webhook-secret-012345678901234';

test('PostgreSQL payout reservation is concurrency-safe and preserves chargeback debt while payout is in flight', { skip: !databaseUrl }, async (t) => {
  const platform = new PostgresLifecyclePlatformStore(databaseUrl!);
  const payoutStore = new PostgresPayoutStore(databaseUrl!);
  const authenticate = testHeaderAuthenticator();
  const app = await buildApp({
    store: platform,
    signer: PassportSigner.ephemeral('https://credalyx.db.test'),
    authenticate,
    paymentProvider: new SandboxPaymentProvider(),
    config: {
      nodeEnv: 'test',
      publicBaseUrl: 'https://credalyx.db.test',
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
    platform,
    store: payoutStore,
    provider: new SandboxPayoutProvider(),
    authenticate,
    config: {
      publicBaseUrl: 'https://credalyx.db.test',
      minPayoutMinor: 100n,
      autoApproveMaxMinor: 10_000n,
      maxPayoutsPer24h: 3,
      sandboxPayoutWebhookSecret: payoutSecret,
    },
  });
  app.addHook('onClose', async () => payoutStore.close());
  t.after(async () => app.close());

  async function paymentWebhook(event: Record<string, unknown>) {
    const timestamp = Math.floor(Date.now() / 1000);
    return app.inject({
      method: 'POST',
      url: '/v1/webhooks/payment-provider',
      headers: {
        'x-sandbox-timestamp': String(timestamp),
        'x-sandbox-signature': signSandboxWebhook(paymentSecret, timestamp, event),
      },
      payload: event,
    });
  }

  async function payoutWebhook(event: Record<string, unknown>) {
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

  async function registerVerifyPay(owner: string, suffix: string, referralCode?: string) {
    const pair = generateKeyPairSync('ed25519');
    const publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
    const created = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: { 'x-test-subject': owner },
      payload: {
        public_key_pem: publicKeyPem,
        endpoint: `https://${owner}.db.example/a2a`,
        capabilities: ['payout.db.test'],
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
    const verified = await app.inject({
      method: 'POST',
      url: `/v1/agents/${createdBody.agent_id}/verify-control`,
      headers: { 'x-test-subject': owner },
      payload: {
        challenge: challenge.challenge,
        signature: sign(null, Buffer.from(challenge.signing_payload), pair.privateKey).toString('base64url'),
      },
    });
    assert.equal(verified.statusCode, 200, verified.body);

    const checkout = await app.inject({
      method: 'POST',
      url: `/v1/agents/${createdBody.agent_id}/passport-checkout`,
      headers: { 'x-test-subject': owner, 'idempotency-key': `db-payout-checkout-${suffix}-0001` },
    });
    assert.equal(checkout.statusCode, 201, checkout.body);
    const purchaseId = checkout.json<{ purchase_id: string }>().purchase_id;
    const paid = await paymentWebhook({
      event_id: `db_payout_paid_${suffix}`,
      type: 'payment.succeeded',
      purchase_id: purchaseId,
      agent_id: createdBody.agent_id,
      amount_minor: 200,
      currency: 'USD',
    });
    assert.equal(paid.statusCode, 201, paid.body);
    return { ...createdBody, purchaseId };
  }

  const runId = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const referrerOwner = `db-payout-referrer-${runId}`;
  const referrer = await registerVerifyPay(referrerOwner, `referrer-${runId}`);
  const referredOne = await registerVerifyPay(`db-payout-referred-one-${runId}`, `referred-one-${runId}`, referrer.referral_code);
  await registerVerifyPay(`db-payout-referred-two-${runId}`, `referred-two-${runId}`, referrer.referral_code);

  const release = await platform.releaseEligibleCommissions(new Date(Date.now() + 31 * 86_400_000), 100);
  assert.equal(release.released >= 2, true);
  const referrerRecord = await platform.getAgent(referrer.agent_id);
  assert.ok(referrerRecord);
  const before = await payoutStore.getRiskContext(referrerRecord.id, new Date());
  assert.equal(before.availableMinor >= 200n, true);
  assert.equal(before.debtMinor, 0n);

  const onboarding = await app.inject({
    method: 'POST',
    url: '/v1/payouts/onboarding',
    headers: { 'x-test-subject': referrerOwner, 'idempotency-key': `db-payout-onboarding-${runId}` },
    payload: { agent_id: referrer.agent_id },
  });
  assert.equal(onboarding.statusCode, 201, onboarding.body);

  const requestA = app.inject({
    method: 'POST',
    url: '/v1/payouts',
    headers: { 'x-test-subject': referrerOwner, 'idempotency-key': `db-payout-concurrent-a-${runId}` },
    payload: { agent_id: referrer.agent_id, amount_minor: '100' },
  });
  const requestB = app.inject({
    method: 'POST',
    url: '/v1/payouts',
    headers: { 'x-test-subject': referrerOwner, 'idempotency-key': `db-payout-concurrent-b-${runId}` },
    payload: { agent_id: referrer.agent_id, amount_minor: '100' },
  });
  const concurrent = await Promise.all([requestA, requestB]);
  const successes = concurrent.filter((response) => response.statusCode === 201);
  const rejected = concurrent.filter((response) => response.statusCode === 409);
  assert.equal(successes.length, 1, concurrent.map((response) => `${response.statusCode}:${response.body}`).join('\n'));
  assert.equal(rejected.length, 1, concurrent.map((response) => `${response.statusCode}:${response.body}`).join('\n'));

  const firstPayout = successes[0]!.json<{ payout: { payout_id: string; provider_payout_id: string; status: string } }>().payout;
  assert.equal(firstPayout.status, 'processing');
  assert.equal((await payoutStore.getPayoutSummary(referrerRecord.id)).reservedMinor, 100n);

  const firstPaid = await payoutWebhook({
    event_id: `db_payout_provider_paid_1_${runId}`,
    type: 'payout.paid',
    payout_id: firstPayout.payout_id,
    provider_payout_id: firstPayout.provider_payout_id,
    amount_minor: '100',
    currency: 'USD',
  });
  assert.equal(firstPaid.statusCode, 200, firstPaid.body);
  assert.equal((await payoutStore.getPayoutSummary(referrerRecord.id)).reservedMinor, 0n);

  const second = await app.inject({
    method: 'POST',
    url: '/v1/payouts',
    headers: { 'x-test-subject': referrerOwner, 'idempotency-key': `db-payout-inflight-${runId}` },
    payload: { agent_id: referrer.agent_id, amount_minor: '100' },
  });
  assert.equal(second.statusCode, 201, second.body);
  const secondPayout = second.json<{ payout: { payout_id: string; provider_payout_id: string; status: string } }>().payout;
  assert.equal(secondPayout.status, 'processing');

  const chargeback = await paymentWebhook({
    event_id: `db_payout_chargeback_${runId}`,
    type: 'payment.chargeback',
    purchase_id: referredOne.purchaseId,
    amount_minor: 200,
    currency: 'USD',
    reason_code: 'provider_chargeback',
  });
  assert.equal(chargeback.statusCode, 200, chargeback.body);
  const during = await payoutStore.getRiskContext(referrerRecord.id, new Date());
  assert.equal(during.debtMinor >= 100n, true, `expected debt after chargeback, got ${during.debtMinor}`);

  const secondPaid = await payoutWebhook({
    event_id: `db_payout_provider_paid_2_${runId}`,
    type: 'payout.paid',
    payout_id: secondPayout.payout_id,
    provider_payout_id: secondPayout.provider_payout_id,
    amount_minor: '100',
    currency: 'USD',
  });
  assert.equal(secondPaid.statusCode, 200, secondPaid.body);
  const after = await payoutStore.getRiskContext(referrerRecord.id, new Date());
  assert.equal(after.debtMinor >= 100n, true, 'settlement must not erase debt created after reservation');
  assert.equal((await payoutStore.getPayoutSummary(referrerRecord.id)).reservedMinor, 0n);

  const blocked = await app.inject({
    method: 'POST',
    url: '/v1/payouts',
    headers: { 'x-test-subject': referrerOwner, 'idempotency-key': `db-payout-blocked-${runId}` },
    payload: { agent_id: referrer.agent_id, amount_minor: '100' },
  });
  assert.equal(blocked.statusCode, 409, blocked.body);
  assert.equal(blocked.json<{ code: string }>().code, 'PAYOUT_DENIED');
});
