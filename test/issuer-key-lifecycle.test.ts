import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { issuerKeyId } from '../src/crypto.js';
import type { AgentRecord } from '../src/domain.js';
import { LocalEd25519IssuerBackend } from '../src/issuer/backend.js';
import { PassportIssuerService } from '../src/issuer/service.js';
import { MemoryIssuerKeyRegistryStore } from '../src/issuer/store.js';

const agentPair = generateKeyPairSync('ed25519');
const agent: AgentRecord = {
  id: '01900000-0000-7000-8000-000000000401',
  publicId: 'apn_issuer_lifecycle_test',
  ownerSubject: 'owner-issuer-lifecycle',
  publicKeyPem: agentPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  capabilities: ['passport.verify'],
  endpoint: 'https://issuer-lifecycle-agent.example/a2a',
  verificationLevel: 1,
  status: 'active',
  controlVerifiedAt: new Date().toISOString(),
  referralCode: 'ref_issuer_lifecycle',
  version: 1,
};

function pair() {
  const value = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: value.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    privateKeyPem: value.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };
}

test('issuer rotation keeps retired-key passports verifiable and new passports bind to new key', async () => {
  const first = pair();
  const backend = LocalEd25519IssuerBackend.fromPem(first);
  const registry = new MemoryIssuerKeyRegistryStore();
  const issuer = new PassportIssuerService('https://credalyx.test', backend, registry);
  await issuer.initialize();

  const firstPassport = await issuer.issue(agent, 30);
  assert.equal(firstPassport.claims.schema_version, '1.1');
  assert.equal(firstPassport.claims.issuer_key_id, issuerKeyId(first.publicKeyPem));
  assert.equal(await issuer.verify(firstPassport), true);

  const second = pair();
  const secondKey = backend.rotateTo(second);
  await issuer.initialize('system:test-rotation', new Date());

  assert.equal(await issuer.verify(firstPassport), true, 'retired issuer key must remain usable for historical verification');
  const secondPassport = await issuer.issue(agent, 30, 2);
  assert.equal(secondPassport.claims.issuer_key_id, secondKey.keyId);
  assert.notEqual(secondPassport.claims.issuer_key_id, firstPassport.claims.issuer_key_id);
  assert.equal(await issuer.verify(secondPassport), true);

  const oldKey = await issuer.getKey(firstPassport.claims.issuer_key_id!);
  assert.equal(oldKey?.status, 'retired');
  const active = await issuer.getActiveKey();
  assert.equal(active.keyId, secondKey.keyId);
});

test('revoked issuer key invalidates its passports and disappears from JWKS', async () => {
  const first = pair();
  const backend = LocalEd25519IssuerBackend.fromPem(first);
  const registry = new MemoryIssuerKeyRegistryStore();
  const issuer = new PassportIssuerService('https://credalyx.test', backend, registry);
  await issuer.initialize();
  const oldPassport = await issuer.issue(agent, 30);
  const oldKeyId = oldPassport.claims.issuer_key_id!;

  const second = pair();
  backend.rotateTo(second);
  await issuer.initialize('system:test-rotation', new Date());
  assert.equal(await issuer.verify(oldPassport), true);

  assert.equal(backend.revoke(oldKeyId), true);
  await issuer.initialize('system:test-revocation', new Date());
  assert.equal(await issuer.verify(oldPassport), false);

  const jwks = await issuer.jwks();
  assert.equal(jwks.keys.some((key) => key.kid === oldKeyId), false);
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0]?.kty, 'OKP');
  assert.equal(jwks.keys[0]?.crv, 'Ed25519');
  assert.equal(jwks.keys[0]?.alg, 'EdDSA');
  assert.equal('d' in (jwks.keys[0] as unknown as Record<string, unknown>), false, 'private JWK parameter must never be exposed');
});

test('public issuer descriptors contain no private key material', async () => {
  const signingPair = pair();
  const backend = LocalEd25519IssuerBackend.fromPem(signingPair);
  const keys = await backend.listKeys();
  assert.equal(keys.length, 1);
  const serialized = JSON.stringify(keys[0]);
  assert.doesNotMatch(serialized, /PRIVATE KEY/);
  assert.equal(Object.hasOwn(keys[0] as object, 'privateKeyPem'), false);
  assert.equal(keys[0]?.keyId, issuerKeyId(signingPair.publicKeyPem));
});
