import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { testHeaderAuthenticator } from '../src/auth.js';
import { agentKeyId, signSandboxWebhook } from '../src/crypto.js';
import { PostgresCredentialLifecycleStore } from '../src/credentials/store-postgres.js';
import { PostgresLifecyclePlatformStore } from '../src/db/store-postgres-lifecycle.js';
import { PassportSigner } from '../src/domain.js';
import { SandboxPaymentProvider } from '../src/payments/sandbox.js';
import { buildApp } from '../src/server.js';

const databaseUrl = process.env.DATABASE_URL;
const secret = 'db-key-lifecycle-secret-012345678901234';

test('PostgreSQL rotates an agent key atomically and reissues the paid passport', { skip: !databaseUrl }, async (t) => {
  const store = new PostgresLifecyclePlatformStore(databaseUrl!);
  const credentials = new PostgresCredentialLifecycleStore(databaseUrl!);
  const app = await buildApp({
    store,
    credentials,
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

  const runId = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const owner = `db-key-owner-${runId}`;
  const firstPair = generateKeyPairSync('ed25519');
  const firstPublicKeyPem = firstPair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const firstKeyId = agentKeyId(firstPublicKeyPem);

  const created = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: { 'x-test-subject': owner },
    payload: {
      public_key_pem: firstPublicKeyPem,
      endpoint: `https://${owner}.example/a2a`,
      capabilities: ['key.rotation.test'],
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
  const challenge = challengeResponse.json<{ challenge: string; signing_payload: string; key_id: string }>();
  assert.equal(challenge.key_id, firstKeyId);
  const verified = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/verify-control`,
    headers: { 'x-test-subject': owner },
    payload: {
      challenge: challenge.challenge,
      signature: sign(null, Buffer.from(challenge.signing_payload), firstPair.privateKey).toString('base64url'),
    },
  });
  assert.equal(verified.statusCode, 200, verified.body);

  const checkout = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/passport-checkout`,
    headers: {
      'x-test-subject': owner,
      'idempotency-key': `db-key-lifecycle-${runId}-0001`,
    },
  });
  assert.equal(checkout.statusCode, 201, checkout.body);
  const purchaseId = checkout.json<{ purchase_id: string }>().purchase_id;
  const event = {
    event_id: `db_key_evt_${runId}`,
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
      'x-sandbox-signature': signSandboxWebhook(secret, timestamp, event),
    },
    payload: event,
  });
  assert.equal(paid.statusCode, 201, paid.body);
  const oldPassportId = paid.json<{ passport_id: string }>().passport_id;
  const oldPassport = await app.inject({ method: 'GET', url: `/v1/passports/${oldPassportId}` });
  assert.equal(oldPassport.statusCode, 200, oldPassport.body);
  const oldClaims = oldPassport.json<{ expires_at: string; passport_version?: number }>();
  assert.equal(oldClaims.passport_version ?? 1, 1);

  const secondPair = generateKeyPairSync('ed25519');
  const secondPublicKeyPem = secondPair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const secondKeyId = agentKeyId(secondPublicKeyPem);
  const rotationStart = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/keys/rotation-challenge`,
    headers: { 'x-test-subject': owner },
    payload: { new_public_key_pem: secondPublicKeyPem },
  });
  assert.equal(rotationStart.statusCode, 201, rotationStart.body);
  const rotation = rotationStart.json<{
    rotation_id: string;
    challenge: string;
    signing_payload: string;
    old_key_id: string;
    new_key_id: string;
  }>();
  assert.equal(rotation.old_key_id, firstKeyId);
  assert.equal(rotation.new_key_id, secondKeyId);

  const completed = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/keys/rotation-complete`,
    headers: { 'x-test-subject': owner },
    payload: {
      rotation_id: rotation.rotation_id,
      challenge: rotation.challenge,
      current_key_signature: sign(null, Buffer.from(rotation.signing_payload), firstPair.privateKey).toString('base64url'),
      new_key_signature: sign(null, Buffer.from(rotation.signing_payload), secondPair.privateKey).toString('base64url'),
    },
  });
  assert.equal(completed.statusCode, 200, completed.body);
  const completion = completed.json<{ new_key_id: string; reissued_passport_id: string }>();
  assert.equal(completion.new_key_id, secondKeyId);
  assert.ok(completion.reissued_passport_id);

  const oldKey = await credentials.getKey((await store.getAgent(agentId))!, firstKeyId);
  assert.ok(oldKey?.revokedAt);
  const currentAgent = await store.getAgent(agentId);
  assert.ok(currentAgent);
  assert.equal(agentKeyId(currentAgent.publicKeyPem), secondKeyId);
  const currentKey = await credentials.getCurrentKey(currentAgent);
  assert.equal(currentKey.keyId, secondKeyId);

  const oldPassportVerify = await app.inject({ method: 'POST', url: `/v1/passports/${oldPassportId}/verify` });
  assert.equal(oldPassportVerify.json<{ valid: boolean }>().valid, false);
  const replacement = await app.inject({ method: 'GET', url: `/v1/passports/${completion.reissued_passport_id}` });
  assert.equal(replacement.statusCode, 200, replacement.body);
  const replacementClaims = replacement.json<{ passport_version: number; expires_at: string; public_key_reference: string }>();
  assert.equal(replacementClaims.passport_version, 2);
  assert.equal(replacementClaims.expires_at, oldClaims.expires_at);
  assert.match(replacementClaims.public_key_reference, /key_ed25519_/);
});

test('PostgreSQL emergency active-key revocation keeps suspended agent readable and blocks new passport checkout', { skip: !databaseUrl }, async (t) => {
  const store = new PostgresLifecyclePlatformStore(databaseUrl!);
  const credentials = new PostgresCredentialLifecycleStore(databaseUrl!);
  const app = await buildApp({
    store,
    credentials,
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

  const runId = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const owner = `db-emergency-key-owner-${runId}`;
  const pair = generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const keyId = agentKeyId(publicKeyPem);
  const created = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: { 'x-test-subject': owner },
    payload: {
      public_key_pem: publicKeyPem,
      endpoint: `https://${owner}.example/a2a`,
      capabilities: ['emergency.revoke.test'],
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

  const revoked = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/keys/${encodeURIComponent(keyId)}/revoke`,
    headers: { 'x-test-subject': owner },
    payload: { reason_code: 'suspected_key_compromise' },
  });
  assert.equal(revoked.statusCode, 200, revoked.body);
  assert.equal(revoked.json<{ revoked: boolean }>().revoked, true);

  const agentResponse = await app.inject({ method: 'GET', url: `/v1/agents/${agentId}` });
  assert.equal(agentResponse.statusCode, 200, agentResponse.body);
  assert.equal(agentResponse.json<{ status: string }>().status, 'suspended');

  const historicalKey = await app.inject({
    method: 'GET',
    url: `/v1/agents/${agentId}/keys/${encodeURIComponent(keyId)}`,
  });
  assert.equal(historicalKey.statusCode, 200, historicalKey.body);
  assert.equal(historicalKey.json<{ active: boolean }>().active, false);

  const currentKey = await app.inject({ method: 'GET', url: `/v1/agents/${agentId}/keys/current` });
  assert.equal(currentKey.statusCode, 404, currentKey.body);

  const checkout = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/passport-checkout`,
    headers: { 'x-test-subject': owner, 'idempotency-key': `db-emergency-${runId}-0001` },
  });
  assert.equal(checkout.statusCode, 409, checkout.body);
  assert.equal(checkout.json<{ code: string }>().code, 'AGENT_NOT_ELIGIBLE_FOR_PASSPORT');
});
