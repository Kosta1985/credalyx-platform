import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { testHeaderAuthenticator } from '../src/auth.js';
import { agentKeyId, signSandboxWebhook } from '../src/crypto.js';
import { MemoryCredentialLifecycleStore } from '../src/credentials/store.js';
import { PassportSigner } from '../src/domain.js';
import { SandboxPaymentProvider } from '../src/payments/sandbox.js';
import { buildApp } from '../src/server.js';
import { MemoryPlatformStore } from '../src/store.js';

const secret = '01234567890123456789012345678901';

async function fixture() {
  const store = new MemoryPlatformStore();
  const credentials = new MemoryCredentialLifecycleStore(store);
  const signer = PassportSigner.ephemeral('https://credalyx.test');
  const app = await buildApp({
    store,
    credentials,
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
  return { app, store, credentials };
}

async function registerAndVerify(app: Awaited<ReturnType<typeof buildApp>>, owner: string) {
  const pair = generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const created = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: { 'x-test-subject': owner },
    payload: {
      public_key_pem: publicKeyPem,
      endpoint: `https://${owner}.example/a2a`,
      capabilities: ['passport.verify'],
    },
  });
  assert.equal(created.statusCode, 201, created.body);
  const createdBody = created.json<{ agent_id: string }>();
  const challengeResponse = await app.inject({
    method: 'POST',
    url: `/v1/agents/${createdBody.agent_id}/challenge`,
    headers: { 'x-test-subject': owner },
  });
  assert.equal(challengeResponse.statusCode, 200, challengeResponse.body);
  const challenge = challengeResponse.json<{ challenge: string; signing_payload: string; key_id: string }>();
  assert.equal(challenge.key_id, agentKeyId(publicKeyPem));
  const signature = sign(null, Buffer.from(challenge.signing_payload), pair.privateKey).toString('base64url');
  const verified = await app.inject({
    method: 'POST',
    url: `/v1/agents/${createdBody.agent_id}/verify-control`,
    headers: { 'x-test-subject': owner },
    payload: { challenge: challenge.challenge, signature },
  });
  assert.equal(verified.statusCode, 200, verified.body);
  assert.equal(verified.json<{ key_id: string }>().key_id, challenge.key_id);
  return { agentId: createdBody.agent_id, pair, publicKeyPem, keyId: challenge.key_id };
}

async function issuePaidPassport(
  app: Awaited<ReturnType<typeof buildApp>>,
  owner: string,
  agentId: string,
) {
  const checkout = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/passport-checkout`,
    headers: { 'x-test-subject': owner, 'idempotency-key': `idem-${owner}-credential-lifecycle-0001` },
  });
  assert.equal(checkout.statusCode, 201, checkout.body);
  const purchase = checkout.json<{ purchase_id: string }>();
  const event = {
    event_id: `evt-${owner}-credential-lifecycle`,
    type: 'payment.succeeded',
    purchase_id: purchase.purchase_id,
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
  return paid.json<{ passport_id: string }>().passport_id;
}

test('key rotation requires both old and new Ed25519 proofs and reissues passport without payment', async (t) => {
  const { app } = await fixture();
  t.after(async () => app.close());
  const owner = 'owner-key-rotation';
  const registered = await registerAndVerify(app, owner);
  const oldPassportId = await issuePaidPassport(app, owner, registered.agentId);
  const oldPassportResponse = await app.inject({ method: 'GET', url: `/v1/passports/${oldPassportId}` });
  assert.equal(oldPassportResponse.statusCode, 200, oldPassportResponse.body);
  const oldPassport = oldPassportResponse.json<{ expires_at: string; passport_version: number }>();
  assert.equal(oldPassport.passport_version, 1);

  const newPair = generateKeyPairSync('ed25519');
  const newPublicKeyPem = newPair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const rotationStart = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agentId}/keys/rotation-challenge`,
    headers: { 'x-test-subject': owner },
    payload: { new_public_key_pem: newPublicKeyPem },
  });
  assert.equal(rotationStart.statusCode, 201, rotationStart.body);
  const rotation = rotationStart.json<{
    rotation_id: string;
    challenge: string;
    signing_payload: string;
    old_key_id: string;
    new_key_id: string;
  }>();
  assert.equal(rotation.old_key_id, registered.keyId);
  assert.equal(rotation.new_key_id, agentKeyId(newPublicKeyPem));

  const oldSignature = sign(null, Buffer.from(rotation.signing_payload), registered.pair.privateKey).toString('base64url');
  const badNewSignature = sign(null, Buffer.from(rotation.signing_payload), registered.pair.privateKey).toString('base64url');
  const rejected = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agentId}/keys/rotation-complete`,
    headers: { 'x-test-subject': owner },
    payload: {
      rotation_id: rotation.rotation_id,
      challenge: rotation.challenge,
      current_key_signature: oldSignature,
      new_key_signature: badNewSignature,
    },
  });
  assert.equal(rejected.statusCode, 401, rejected.body);
  assert.equal(rejected.json<{ code: string }>().code, 'INVALID_NEW_KEY_SIGNATURE');

  const newSignature = sign(null, Buffer.from(rotation.signing_payload), newPair.privateKey).toString('base64url');
  const completed = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agentId}/keys/rotation-complete`,
    headers: { 'x-test-subject': owner },
    payload: {
      rotation_id: rotation.rotation_id,
      challenge: rotation.challenge,
      current_key_signature: oldSignature,
      new_key_signature: newSignature,
    },
  });
  assert.equal(completed.statusCode, 200, completed.body);
  const completion = completed.json<{ new_key_id: string; reissued_passport_id: string }>();
  assert.equal(completion.new_key_id, rotation.new_key_id);
  assert.ok(completion.reissued_passport_id);
  assert.notEqual(completion.reissued_passport_id, oldPassportId);

  const oldVerification = await app.inject({ method: 'POST', url: `/v1/passports/${oldPassportId}/verify` });
  assert.equal(oldVerification.statusCode, 200, oldVerification.body);
  assert.equal(oldVerification.json<{ valid: boolean }>().valid, false);

  const replacement = await app.inject({ method: 'GET', url: `/v1/passports/${completion.reissued_passport_id}` });
  assert.equal(replacement.statusCode, 200, replacement.body);
  const replacementBody = replacement.json<{
    passport_version: number;
    expires_at: string;
    public_key_reference: string;
    status: string;
  }>();
  assert.equal(replacementBody.passport_version, 2);
  assert.equal(replacementBody.expires_at, oldPassport.expires_at);
  assert.equal(replacementBody.status, 'active');
  assert.match(replacementBody.public_key_reference, new RegExp(encodeURIComponent(rotation.new_key_id).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  const currentKey = await app.inject({ method: 'GET', url: `/v1/agents/${registered.agentId}/keys/current` });
  assert.equal(currentKey.statusCode, 200, currentKey.body);
  assert.equal(currentKey.json<{ key_id: string }>().key_id, rotation.new_key_id);

  const oldKey = await app.inject({ method: 'GET', url: `/v1/agents/${registered.agentId}/keys/${encodeURIComponent(rotation.old_key_id)}` });
  assert.equal(oldKey.statusCode, 200, oldKey.body);
  assert.equal(oldKey.json<{ active: boolean }>().active, false);
});

test('challenge bound to an old key cannot verify after rotation', async (t) => {
  const { app } = await fixture();
  t.after(async () => app.close());
  const owner = 'owner-stale-challenge';
  const registered = await registerAndVerify(app, owner);

  const staleChallengeResponse = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agentId}/challenge`,
    headers: { 'x-test-subject': owner },
  });
  assert.equal(staleChallengeResponse.statusCode, 200, staleChallengeResponse.body);
  const stale = staleChallengeResponse.json<{ challenge: string; signing_payload: string }>();
  const staleOldSignature = sign(null, Buffer.from(stale.signing_payload), registered.pair.privateKey).toString('base64url');

  const newPair = generateKeyPairSync('ed25519');
  const newPublicKeyPem = newPair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const rotationStart = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agentId}/keys/rotation-challenge`,
    headers: { 'x-test-subject': owner },
    payload: { new_public_key_pem: newPublicKeyPem },
  });
  assert.equal(rotationStart.statusCode, 201, rotationStart.body);
  const rotation = rotationStart.json<{ rotation_id: string; challenge: string; signing_payload: string }>();
  const complete = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agentId}/keys/rotation-complete`,
    headers: { 'x-test-subject': owner },
    payload: {
      rotation_id: rotation.rotation_id,
      challenge: rotation.challenge,
      current_key_signature: sign(null, Buffer.from(rotation.signing_payload), registered.pair.privateKey).toString('base64url'),
      new_key_signature: sign(null, Buffer.from(rotation.signing_payload), newPair.privateKey).toString('base64url'),
    },
  });
  assert.equal(complete.statusCode, 200, complete.body);

  const staleVerify = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agentId}/verify-control`,
    headers: { 'x-test-subject': owner },
    payload: { challenge: stale.challenge, signature: staleOldSignature },
  });
  assert.equal(staleVerify.statusCode, 401, staleVerify.body);
});

test('emergency current-key revocation suspends agent and revokes active passport', async (t) => {
  const { app } = await fixture();
  t.after(async () => app.close());
  const owner = 'owner-emergency-revoke';
  const registered = await registerAndVerify(app, owner);
  const passportId = await issuePaidPassport(app, owner, registered.agentId);

  const revoked = await app.inject({
    method: 'POST',
    url: `/v1/agents/${registered.agentId}/keys/${encodeURIComponent(registered.keyId)}/revoke`,
    headers: { 'x-test-subject': owner },
    payload: { reason_code: 'suspected_key_compromise' },
  });
  assert.equal(revoked.statusCode, 200, revoked.body);
  const revokedBody = revoked.json<{ revoked: boolean; passport_revoked: boolean }>();
  assert.equal(revokedBody.revoked, true);
  assert.equal(revokedBody.passport_revoked, true);

  const agent = await app.inject({ method: 'GET', url: `/v1/agents/${registered.agentId}` });
  assert.equal(agent.statusCode, 200, agent.body);
  assert.equal(agent.json<{ status: string }>().status, 'suspended');

  const passportVerification = await app.inject({ method: 'POST', url: `/v1/passports/${passportId}/verify` });
  assert.equal(passportVerification.statusCode, 200, passportVerification.body);
  assert.equal(passportVerification.json<{ valid: boolean }>().valid, false);

  const currentKey = await app.inject({ method: 'GET', url: `/v1/agents/${registered.agentId}/keys/current` });
  assert.equal(currentKey.statusCode, 404, currentKey.body);
});
