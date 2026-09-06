import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { LocalEd25519IssuerBackend } from '../src/issuer/backend.js';
import { MemoryIssuerKeyRegistryStore } from '../src/issuer/store.js';

function pair() {
  const value = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: value.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    privateKeyPem: value.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };
}

test('revoked issuer registry state cannot be undone by backend synchronization', async () => {
  const backend = LocalEd25519IssuerBackend.fromPem(pair());
  const registry = new MemoryIssuerKeyRegistryStore();
  const initial = await backend.listKeys();
  await registry.syncKeys(initial, 'system:test', new Date());
  const keyId = initial[0]!.keyId;
  assert.equal(await registry.setStatus(keyId, 'revoked', 'compromise', 'admin:test', new Date()), true);
  assert.equal((await registry.getKey(keyId))?.status, 'revoked');

  await assert.rejects(
    registry.syncKeys(initial, 'system:stale-backend', new Date()),
    /cannot be reactivated/,
  );
  assert.equal((await registry.getKey(keyId))?.status, 'revoked');
  assert.equal((await registry.listVerificationKeys()).some((key) => key.keyId === keyId), false);
});
