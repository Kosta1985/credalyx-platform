import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { testHeaderAuthenticator } from '../src/auth.js';
import { signSandboxWebhook } from '../src/crypto.js';
import { PostgresPlatformStore } from '../src/db/store-postgres.js';
import { PassportSigner } from '../src/domain.js';
import { SandboxPaymentProvider } from '../src/payments/sandbox.js';
import { buildApp } from '../src/server.js';

const databaseUrl = process.env.DATABASE_URL;
const secret = 'db-commerce-test-secret-0123456789012345';

test('PostgreSQL commerce flow persists checkout, sale, referral release and reversal atomically', { skip: !databaseUrl }, async (t) => {
  const store = new PostgresPlatformStore(databaseUrl!);
  const app = await buildApp({
    store,
    signer: PassportSigner.ephemeral('https://credalyx.db.test'),
    authenticate: testHeaderAuthenticator(),
    paymentProvider: new SandboxPaymentProvider(),
    config: {
      nodeEnv: 'test',
      publicBaseUrl: 'https://credalyx.db.test',
      passportPriceMinor: 200n,
      referralCommissionMinor: 100n,
      referralHoldDays: 30,
      minPayoutMinor: 2500n,
      passportTtlDays: 30,
      sandboxWebhookSecret: secret,
    },
  });
  t.after(async () => app.close());

  async function registerVerify(owner: string, referralCode?: string) {
    const pair = generateKeyPairSync('ed25519');
    const publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
    const created = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: { 'x-test-subject': owner },
      payload: {
        public_key_pem: publicKeyPem,
        endpoint: `https://${owner}.db.example/a2a`,
        capabilities: ['commerce.test'],
        ...(referralCode ? { referral_code: referralCode } : {}),
      },
    });
    assert.equal(created.statusCode, 201, created.body);
    const body = created.json<{ agent_id: string; referral_code: string }>();
    const challengeResponse = await app.inject({
      method: 'POST',
      url: `/v1/agents/${body.agent_id}/challenge`,
      headers: { 'x-test-subject': owner },
    });
    assert.equal(challengeResponse.statusCode, 200, challengeResponse.body);
    const challenge = challengeResponse.json<{ challenge: string; signing_payload: string }>();
    const signature = sign(null, Buffer.from(challenge.signing_payload), pair.privateKey).toString('base64url');
    const verified = await app.inject({
      method: 'POST',
      url: `/v1/agents/${body.agent_id}/verify-control`,
      headers: { 'x-test-subject': owner },
      payload: { challenge: challenge.challenge, signature },
    });
    assert.equal(verified.statusCode, 200, verified.body);
    return body;
  }

  async function checkout(owner: string, agentId: string, suffix: string) {
    const response = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/passport-checkout`,
      headers: { 'x-test-subject': owner, 'idempotency-key': `db-commerce-${suffix}-0001` },
    });
    assert.equal(response.statusCode, 201, response.body);
    return response.json<{ purchase_id: string }>().purchase_id;
  }

  async function webhook(event: Record<string, unknown>) {
    const timestamp = Math.floor(Date.now() / 1000);
    return app.inject({
      method: 'POST',
      url: '/v1/webhooks/payment-provider',
      headers: {
        'x-sandbox-timestamp': String(timestamp),
        'x-sandbox-signature': signSandboxWebhook(secret, timestamp, event),
      },
      payload: event,
    });
  }

  const runId = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const referrerOwner = `db-referrer-${runId}`;
  const referrer = await registerVerify(referrerOwner);
  const referrerPurchase = await checkout(referrerOwner, referrer.agent_id, `referrer-${runId}`);
  const referrerPaid = await webhook({
    event_id: `db_evt_referrer_${runId}`,
    type: 'payment.succeeded',
    purchase_id: referrerPurchase,
    agent_id: referrer.agent_id,
    amount_minor: 200,
    currency: 'USD',
  });
  assert.equal(referrerPaid.statusCode, 201, referrerPaid.body);
  const referrerRecord = await store.getAgent(referrer.agent_id);
  assert.ok(referrerRecord);

  const referredOwner = `db-referred-${runId}`;
  const referred = await registerVerify(referredOwner, referrer.referral_code);
  const referredPurchase = await checkout(referredOwner, referred.agent_id, `referred-${runId}`);
  const referredPaid = await webhook({
    event_id: `db_evt_referred_${runId}`,
    type: 'payment.succeeded',
    purchase_id: referredPurchase,
    agent_id: referred.agent_id,
    amount_minor: 200,
    currency: 'USD',
  });
  assert.equal(referredPaid.statusCode, 201, referredPaid.body);
  const referredPassportId = referredPaid.json<{ passport_id: string }>().passport_id;

  const beforeRelease = await store.getWallet(referrerRecord.id, 2500n);
  assert.equal(beforeRelease.pendingMinor, 100n);
  assert.equal(beforeRelease.availableMinor, 0n);
  const released = await store.releaseEligibleCommissions(new Date(Date.now() + 31 * 86_400_000), 100);
  assert.ok(released.released >= 1);
  const afterRelease = await store.getWallet(referrerRecord.id, 2500n);
  assert.equal(afterRelease.pendingMinor, 0n);
  assert.equal(afterRelease.availableMinor, 100n);

  const chargeback = await webhook({
    event_id: `db_evt_chargeback_${runId}`,
    type: 'payment.chargeback',
    purchase_id: referredPurchase,
    amount_minor: 200,
    currency: 'USD',
    reason_code: 'integration_test_chargeback',
  });
  assert.equal(chargeback.statusCode, 200, chargeback.body);
  const afterChargeback = await store.getWallet(referrerRecord.id, 2500n);
  assert.equal(afterChargeback.pendingMinor, 0n);
  assert.equal(afterChargeback.availableMinor, 0n);
  assert.equal(afterChargeback.reversedMinor, 100n);

  const verification = await app.inject({ method: 'POST', url: `/v1/passports/${referredPassportId}/verify` });
  assert.equal(verification.statusCode, 200, verification.body);
  assert.equal(verification.json<{ valid: boolean }>().valid, false);
});
