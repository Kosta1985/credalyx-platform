import assert from 'node:assert/strict';
import test from 'node:test';
import { ChallengeService, Ledger, PassportSigner, assertReferralAllowed, recordPassportSale, type AgentRecord } from '../src/domain.js';

const agent: AgentRecord = {
  id: '01900000-0000-7000-8000-000000000001',
  publicId: 'apn_agent_demo_001',
  ownerId: 'owner_demo',
  publicKeyPem: 'demo-public-key-reference',
  capabilities: ['payments.read', 'orders.create'],
  endpoint: 'https://agent.example/a2a',
  verificationLevel: 1,
  controlVerifiedAt: new Date().toISOString(),
};

test('challenge can only be consumed once', () => {
  const service = new ChallengeService();
  const challenge = service.create(agent.id);
  assert.equal(service.consume(agent.id, challenge), true);
  assert.equal(service.consume(agent.id, challenge), false);
});

test('active signed passport verifies', () => {
  const signer = new PassportSigner();
  const passport = signer.issue(agent);
  assert.equal(signer.verify(passport), true);
});

test('revoked passport never verifies', () => {
  const signer = new PassportSigner();
  const passport = signer.issue(agent);
  passport.status = 'revoked';
  assert.equal(signer.verify(passport), false);
});

test('passport requires verified control', () => {
  const signer = new PassportSigner();
  assert.throws(() => signer.issue({ ...agent, verificationLevel: 0, controlVerifiedAt: undefined }), /control/);
});

test('ledger rejects unbalanced transaction', () => {
  const ledger = new Ledger();
  assert.throws(() => ledger.post({
    idempotencyKey: 'bad',
    externalReference: 'bad',
    entries: [
      { account: 'platform_cash', amountMinor: 200n, currency: 'USD' },
      { account: 'passport_revenue', amountMinor: -199n, currency: 'USD' },
    ],
  }), /unbalanced/);
});

test('passport sale and referral commission is balanced and idempotent', () => {
  const ledger = new Ledger();
  const first = recordPassportSale(ledger, 'purchase_1', 200n, 100n, true);
  const second = recordPassportSale(ledger, 'purchase_1', 200n, 100n, true);
  assert.equal(first.id, second.id);
  assert.equal(first.entries.reduce((sum, e) => sum + e.amountMinor, 0n), 0n);
  assert.equal(ledger.transactions.length, 1);
});

test('self-referral is forbidden', () => {
  assert.throws(() => assertReferralAllowed(agent.id, agent.id), /self-referral/);
});
