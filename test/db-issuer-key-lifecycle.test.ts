import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import type { AgentRecord } from '../src/domain.js';
import { LocalEd25519IssuerBackend } from '../src/issuer/backend.js';
import { PassportIssuerService } from '../src/issuer/service.js';
import { PostgresIssuerKeyRegistryStore } from '../src/issuer/store-postgres.js';

const databaseUrl = process.env.DATABASE_URL;

function pair() {
  const value = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: value.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    privateKeyPem: value.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };
}

test('PostgreSQL issuer registry preserves retired public keys across active-key rotation', { skip: !databaseUrl }, async (t) => {
  const agentPair = generateKeyPairSync('ed25519');
  const agent: AgentRecord = {
    id: '01900000-0000-7000-8000-000000000501',
    publicId: `apn_db_issuer_${Date.now()}`,
    ownerSubject: 'owner-db-issuer',
    publicKeyPem: agentPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    capabilities: ['issuer.db.test'],
    endpoint: 'https://db-issuer-agent.example/a2a',
    verificationLevel: 1,
    status: 'active',
    controlVerifiedAt: new Date().toISOString(),
    referralCode: `ref_db_issuer_${Date.now()}`,
    version: 1,
  };

  const first = pair();
  const backend = LocalEd25519IssuerBackend.fromPem(first);
  const registry = new PostgresIssuerKeyRegistryStore(databaseUrl!);
  const issuer = new PassportIssuerService(`https://credalyx-db-${Date.now()}.test`, backend, registry);
  t.after(async () => issuer.close());

  await issuer.initialize('system:db-issuer-test');
  const firstKey = await issuer.getActiveKey();
  const firstPassport = await issuer.issue(agent, 30);
  assert.equal(firstPassport.claims.issuer_key_id, firstKey.keyId);
  assert.equal(await issuer.verify(firstPassport), true);

  const second = pair();
  const secondKey = backend.rotateTo(second);
  await issuer.initialize('system:db-issuer-rotation');

  const active = await issuer.getActiveKey();
  assert.equal(active.keyId, secondKey.keyId);
  const old = await issuer.getKey(firstKey.keyId);
  assert.equal(old?.status, 'retired');
  assert.equal(await issuer.verify(firstPassport), true);

  const secondPassport = await issuer.issue(agent, 30, 2);
  assert.equal(secondPassport.claims.issuer_key_id, secondKey.keyId);
  assert.equal(await issuer.verify(secondPassport), true);
  const keys = await issuer.listVerificationKeys();
  assert.equal(keys.some((key) => key.keyId === firstKey.keyId && key.status === 'retired'), true);
  assert.equal(keys.some((key) => key.keyId === secondKey.keyId && key.status === 'active'), true);
  assert.equal(JSON.stringify(keys).includes('PRIVATE KEY'), false);
});
