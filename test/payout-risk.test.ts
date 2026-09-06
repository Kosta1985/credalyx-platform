import assert from 'node:assert/strict';
import test from 'node:test';
import { assessPayoutRisk, type PayoutRiskContext } from '../src/payouts/risk.js';

const base: PayoutRiskContext = {
  agentStatus: 'active',
  verificationLevel: 1,
  onboardingStatus: 'complete',
  amountMinor: 100n,
  availableMinor: 300n,
  debtMinor: 0n,
  minPayoutMinor: 100n,
  openPayoutCount: 0,
  payoutCount24h: 0,
  reversalMinor30d: 0n,
  autoApproveMaxMinor: 10_000n,
  maxPayoutsPer24h: 3,
};

test('clean payout is approved', () => {
  assert.deepEqual(assessPayoutRisk(base), { decision: 'approve', score: 0, reasons: [] });
});

test('debt and insufficient funds are hard payout denials', () => {
  const debt = assessPayoutRisk({ ...base, debtMinor: 1n });
  assert.equal(debt.decision, 'deny');
  assert.equal(debt.score, 100);
  assert.ok(debt.reasons.includes('wallet_has_debt'));

  const insufficient = assessPayoutRisk({ ...base, amountMinor: 400n });
  assert.equal(insufficient.decision, 'deny');
  assert.ok(insufficient.reasons.includes('insufficient_available_balance'));
});

test('minimum payout and open-payout constraints deny immediately', () => {
  const belowMinimum = assessPayoutRisk({ ...base, amountMinor: 99n });
  assert.equal(belowMinimum.decision, 'deny');
  assert.ok(belowMinimum.reasons.includes('below_minimum_payout'));

  const open = assessPayoutRisk({ ...base, openPayoutCount: 1 });
  assert.equal(open.decision, 'deny');
  assert.ok(open.reasons.includes('open_payout_exists'));
});

test('recent reversal, velocity and large amount require review', () => {
  const reversal = assessPayoutRisk({ ...base, reversalMinor30d: 100n });
  assert.equal(reversal.decision, 'review');
  assert.ok(reversal.reasons.includes('recent_refund_or_chargeback_exposure'));

  const velocity = assessPayoutRisk({ ...base, payoutCount24h: 3 });
  assert.equal(velocity.decision, 'review');
  assert.ok(velocity.reasons.includes('payout_velocity_24h'));

  const highValue = assessPayoutRisk({ ...base, amountMinor: 11_000n, availableMinor: 20_000n });
  assert.equal(highValue.decision, 'review');
  assert.ok(highValue.reasons.includes('amount_above_auto_approve_limit'));
});

test('withdrawing nearly all of a small clean balance is a soft signal, not mandatory review', () => {
  const result = assessPayoutRisk({ ...base, amountMinor: 100n, availableMinor: 100n });
  assert.equal(result.decision, 'approve');
  assert.equal(result.score, 10);
  assert.ok(result.reasons.includes('withdraws_nearly_all_available_balance'));
});
