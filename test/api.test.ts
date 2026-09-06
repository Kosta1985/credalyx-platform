import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { testHeaderAuthenticator } from '../src/auth.js';
import { signSandboxWebhook } from '../src/crypto.js';
import { PassportSigner } from '../src/domain.js';
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
    config: {
      nodeEnv: 'test',
      publicBaseUrl: 'https://credalyx.test',
      passportPriceMinor: 200n,
      referralCommissionMinor: 100n,
      referralHoldDays: 30,
      passportTtlDays: 30,
      sandboxWebhookSecret: secret,
    },
  });
  return { app, store };
}

test('vertical MVP: register -> signed control proof -> payment -> passport -> verify -> revoke', async (t) => {
  const { app, store } = await createFixture();
  t.after(async () => app.close());
  const pair = generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();

  const created = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: { 'x-test-subject': 'owner-a' },
    payload: { public_key_pem: publicKeyPem, endpoint: 'https://agent.example/a2a', capabilities: ['orders.create'] },
  });
  assert.equal(created.statusCode, 201, created.body);
  const { agent_id: agentId } = created.json<{ agent_id: string }>();

  const forbidden = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/challenge`,
    headers: { 'x-test-subject': 'owner-b' },
  });
  assert.equal(forbidden.statusCode, 403);

  const challengeResponse = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/challenge`,
    headers: { 'x-test-subject': 'owner-a' },
  });
  assert.equal(challengeResponse.statusCode, 200, challengeResponse.body);
  const challenge = challengeResponse.json<{ challenge: string; signing_payload: string }>();
  const signature = sign(null, Buffer.from(challenge.signing_payload), pair.privateKey).toString('base64url');

  const invalidSignature = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/verify-control`,
    headers: { 'x-test-subject': 'owner-a' },
    payload: { challenge: challenge.challenge, signature: Buffer.from('invalid').toString('base64url').padEnd(40, 'A') },
  });
  assert.equal(invalidSignature.statusCode, 401);

  const verified = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/verify-control`,
    headers: { 'x-test-subject': 'owner-a' },
    payload: { challenge: challenge.challenge, signature },
  });
  assert.equal(verified.statusCode, 200, verified.body);

  const replay = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/verify-control`,
    headers: { 'x-test-subject': 'owner-a' },
    payload: { challenge: challenge.challenge, signature },
  });
  assert.equal(replay.statusCode, 401);

  const payment = {
    event_id: 'evt_001',
    type: 'payment.succeeded',
    purchase_id: 'purchase_001',
    agent_id: agentId,
    amount_minor: 200,
    currency: 'USD',
  } as const;
  const timestamp = Math.floor(Date.now() / 1000);
  const webhookSignature = signSandboxWebhook(secret, timestamp, payment);
  const paid = await app.inject({
    method: 'POST',
    url: '/v1/webhooks/payment-provider',
    headers: { 'x-sandbox-timestamp': String(timestamp), 'x-sandbox-signature': webhookSignature },
    payload: payment,
  });
  assert.equal(paid.statusCode, 201, paid.body);
  const { passport_id: passportId } = paid.json<{ passport_id: string }>();
  assert.equal(store.ledgerTransactions.size, 1);

  const duplicate = await app.inject({
    method: 'POST',
    url: '/v1/webhooks/payment-provider',
    headers: { 'x-sandbox-timestamp': String(timestamp), 'x-sandbox-signature': webhookSignature },
    payload: payment,
  });
  assert.equal(duplicate.statusCode, 200);
  assert.equal(store.ledgerTransactions.size, 1);

  const valid = await app.inject({ method: 'POST', url: `/v1/passports/${passportId}/verify` });
  assert.deepEqual(valid.json<{ valid: boolean }>().valid, true);

  const revoked = await app.inject({
    method: 'POST',
    url: `/v1/passports/${passportId}/revoke`,
    headers: { 'x-test-subject': 'owner-a' },
    payload: { reason_code: 'owner_requested' },
  });
  assert.equal(revoked.statusCode, 200, revoked.body);

  const invalidAfterRevoke = await app.inject({ method: 'POST', url: `/v1/passports/${passportId}/verify` });
  assert.equal(invalidAfterRevoke.json<{ valid: boolean }>().valid, false);
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
