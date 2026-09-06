import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { testHeaderAuthenticator } from '../src/auth.js';
import { signSandboxWebhook } from '../src/crypto.js';
import { LocalEd25519IssuerBackend } from '../src/issuer/backend.js';
import { PassportIssuerService } from '../src/issuer/service.js';
import { MemoryIssuerKeyRegistryStore } from '../src/issuer/store.js';
import { SandboxPaymentProvider } from '../src/payments/sandbox.js';
import { buildApp } from '../src/server.js';
import { MemoryPlatformStore } from '../src/store.js';

const secret = 'issuer-api-test-secret-01234567890123456';

function signingPair() {
  const pair = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    privateKeyPem: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };
}

test('issuer discovery exposes public keys and verification survives issuer rotation', async (t) => {
  const initialIssuerPair = signingPair();
  const backend = LocalEd25519IssuerBackend.fromPem(initialIssuerPair);
  const issuer = new PassportIssuerService(
    'https://credalyx.test',
    backend,
    new MemoryIssuerKeyRegistryStore(),
  );
  await issuer.initialize();
  const store = new MemoryPlatformStore();
  const app = await buildApp({
    store,
    issuer,
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
  t.after(async () => app.close());

  const metadata = await app.inject({ method: 'GET', url: '/.well-known/agent-passport-issuer.json' });
  assert.equal(metadata.statusCode, 200, metadata.body);
  const metadataBody = metadata.json<{ active_key_id: string; jwks_uri: string; schema_versions: string[] }>();
  assert.match(metadataBody.active_key_id, /^issuer_ed25519_/);
  assert.equal(metadataBody.jwks_uri, 'https://credalyx.test/.well-known/jwks.json');
  assert.deepEqual(metadataBody.schema_versions, ['1.0', '1.1']);

  const jwks = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
  assert.equal(jwks.statusCode, 200, jwks.body);
  const jwksBody = jwks.json<{ keys: Array<Record<string, unknown>> }>();
  assert.equal(jwksBody.keys.length, 1);
  assert.equal(jwksBody.keys[0]?.kid, metadataBody.active_key_id);
  assert.equal('d' in jwksBody.keys[0]!, false);

  const exactKey = await app.inject({ method: 'GET', url: `/v1/issuer/keys/${encodeURIComponent(metadataBody.active_key_id)}` });
  assert.equal(exactKey.statusCode, 200, exactKey.body);
  assert.doesNotMatch(exactKey.body, /PRIVATE KEY/);

  const agentPair = generateKeyPairSync('ed25519');
  const publicKeyPem = agentPair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const owner = 'owner-issuer-api';
  const created = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: { 'x-test-subject': owner },
    payload: {
      public_key_pem: publicKeyPem,
      endpoint: 'https://issuer-api-agent.example/a2a',
      capabilities: ['passport.verify'],
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
      signature: sign(null, Buffer.from(challenge.signing_payload), agentPair.privateKey).toString('base64url'),
    },
  });
  assert.equal(verified.statusCode, 200, verified.body);

  const checkout = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/passport-checkout`,
    headers: { 'x-test-subject': owner, 'idempotency-key': 'issuer-api-checkout-0001' },
  });
  assert.equal(checkout.statusCode, 201, checkout.body);
  const purchaseId = checkout.json<{ purchase_id: string }>().purchase_id;
  const event = {
    event_id: 'issuer_api_payment_001',
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
  const passportId = paid.json<{ passport_id: string }>().passport_id;

  const passport = await app.inject({ method: 'GET', url: `/v1/passports/${passportId}` });
  assert.equal(passport.statusCode, 200, passport.body);
  const passportBody = passport.json<{ schema_version: string; issuer_key_id: string }>();
  assert.equal(passportBody.schema_version, '1.1');
  assert.equal(passportBody.issuer_key_id, metadataBody.active_key_id);

  backend.rotateTo(signingPair());
  await issuer.initialize('system:test-api-rotation', new Date());

  const oldPassportVerification = await app.inject({ method: 'POST', url: `/v1/passports/${passportId}/verify` });
  assert.equal(oldPassportVerification.statusCode, 200, oldPassportVerification.body);
  assert.equal(oldPassportVerification.json<{ valid: boolean }>().valid, true);

  const rotatedJwks = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
  assert.equal(rotatedJwks.statusCode, 200, rotatedJwks.body);
  assert.equal(rotatedJwks.json<{ keys: unknown[] }>().keys.length, 2);
});
