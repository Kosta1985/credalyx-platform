import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import {
  Ledger,
  PassportSigner,
  assertReferralAllowed,
  passportRefundEntries,
  passportSaleEntries,
  type AgentRecord,
} from '../src/domain.js';
import {
  agentControlMessage,
  challengeDigest,
  createChallenge,
  signSandboxWebhook,
  uuidv7,
  verifyAgentControlSignature,
  verifySandboxWebhook,
} from '../src/crypto.js';

const keyPair = generateKeyPairSync('ed25519');
const publicKeyPem = keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
const agent: AgentRecord = {
  id: '01900000-0000-7000-8000-000000000001',
  publicId: 'apn_agent_demo_001',
  ownerSubject: 'owner_demo',
  publicKeyPem,
  capabilities: ['payments.read', 'orders.create'],
  endpoint: 'https://agent.example/a2a',
  verificationLevel: 1,
  status: 'active',
  controlVerifiedAt: new Date().toISOString(),
  referralCode: 'ref_demo',
  version: 1,
};

test('uuidv7 carries version and RFC variant bits', () => {
  const id = uuidv7(1_700_000_000_000);
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('agent control requires a valid Ed25519 signature bound to agent and challenge', () => {
  const challenge = createChallenge();
  const message = agentControlMessage(agent.publicId, challenge);
  const signature = sign(null, Buffer.from(message), keyPair.privateKey).toString('base64url');
  assert.equal(verifyAgentControlSignature(publicKeyPem, agent.publicId, challenge, signature), true);
  assert.equal(verifyAgentControlSignature(publicKeyPem, 'apn_other', challenge, signature), false);
  assert.equal(challengeDigest(challenge).length, 64);
});

test('active signed passport verifies and revoked passport does not', () => {
  const signer = PassportSigner.ephemeral('https://credalyx.test');
  const passport = signer.issue(agent);
  assert.equal(signer.verify(passport), true);
  passport.status = 'revoked';
  assert.equal(signer.verify(passport), false);
});

test('passport requires verified control', () => {
  const signer = PassportSigner.ephemeral();
  assert.throws(() => signer.issue({ ...agent, verificationLevel: 0, controlVerifiedAt: undefined }), /control/);
});

test('ledger rejects an unbalanced transaction', () => {
  const ledger = new Ledger();
  assert.throws(() => ledger.post({
    idempotencyKey: 'bad',
    externalReference: 'bad',
    entries: [
      { account: 'platform_cash', scopeType: 'platform', scopeId: 'platform', amountMinor: 200n, currency: 'USD' },
      { account: 'passport_revenue', scopeType: 'platform', scopeId: 'platform', amountMinor: -199n, currency: 'USD' },
    ],
  }), /unbalanced/);
});

test('passport sale scopes referral liability to the referrer agent and balances', () => {
  const entries = passportSaleEntries(200n, 100n, '01900000-0000-7000-8000-000000000099');
  assert.equal(entries.reduce((sum, entry) => sum + entry.amountMinor, 0n), 0n);
  const pending = entries.find((entry) => entry.account === 'agent_owner_pending_balance');
  assert.equal(pending?.scopeType, 'agent');
  assert.equal(pending?.scopeId, '01900000-0000-7000-8000-000000000099');
});

test('refund reverses referral liability with a balanced compensating transaction', () => {
  const entries = passportRefundEntries(200n, 100n, '01900000-0000-7000-8000-000000000099');
  assert.equal(entries.reduce((sum, entry) => sum + entry.amountMinor, 0n), 0n);
  assert.equal(entries.some((entry) => entry.account === 'agent_owner_pending_balance' && entry.amountMinor === 100n), true);
});

test('self-referral by common owner is forbidden', () => {
  assert.throws(() => assertReferralAllowed({
    newAgentPublicId: 'apn_new',
    ownerSubject: 'owner_demo',
    referrer: agent,
  }), /self-referral/);
});

test('sandbox webhook HMAC binds timestamp and canonical payload and expires', () => {
  const secret = '01234567890123456789012345678901';
  const body = { event_id: 'evt_1', amount_minor: 200 };
  const nowMs = 1_700_000_000_000;
  const timestamp = Math.floor(nowMs / 1000);
  const signature = signSandboxWebhook(secret, timestamp, body);
  assert.equal(verifySandboxWebhook(secret, String(timestamp), signature, body, nowMs), true);
  assert.equal(verifySandboxWebhook(secret, String(timestamp), signature, { ...body, amount_minor: 201 }, nowMs), false);
  assert.equal(verifySandboxWebhook(secret, String(timestamp), signature, body, nowMs + 301_000), false);
});
