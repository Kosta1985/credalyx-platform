import type { AgentStatus } from '../domain.js';
import type { PayoutOnboardingStatus } from './provider.js';

export type PayoutRiskDecision = 'approve' | 'review' | 'deny';

export interface PayoutRiskContext {
  agentStatus: AgentStatus;
  verificationLevel: 0 | 1 | 2 | 3;
  onboardingStatus: PayoutOnboardingStatus;
  amountMinor: bigint;
  availableMinor: bigint;
  debtMinor: bigint;
  minPayoutMinor: bigint;
  openPayoutCount: number;
  payoutCount24h: number;
  reversalMinor30d: bigint;
  autoApproveMaxMinor: bigint;
  maxPayoutsPer24h: number;
}

export interface PayoutRiskAssessment {
  decision: PayoutRiskDecision;
  score: number;
  reasons: string[];
}

/**
 * Deterministic first-line payout policy. It intentionally errs toward review
 * rather than automatic release when velocity/reversal signals are elevated.
 * A production risk service can replace or enrich this policy without changing
 * the reservation/ledger transaction model.
 */
export function assessPayoutRisk(input: PayoutRiskContext): PayoutRiskAssessment {
  const deny: string[] = [];
  const review: string[] = [];
  let score = 0;

  if (input.agentStatus !== 'active') deny.push('agent_not_active');
  if (input.verificationLevel < 1) deny.push('agent_control_not_verified');
  if (input.onboardingStatus !== 'complete') deny.push('beneficiary_onboarding_incomplete');
  if (input.amountMinor <= 0n) deny.push('invalid_amount');
  if (input.amountMinor < input.minPayoutMinor) deny.push('below_minimum_payout');
  if (input.debtMinor > 0n) deny.push('wallet_has_debt');
  if (input.amountMinor > input.availableMinor) deny.push('insufficient_available_balance');
  if (input.openPayoutCount > 0) deny.push('open_payout_exists');

  if (input.payoutCount24h >= input.maxPayoutsPer24h) {
    review.push('payout_velocity_24h');
    score += 35;
  }
  if (input.reversalMinor30d > 0n) {
    review.push('recent_refund_or_chargeback_exposure');
    score += 30;
  }
  if (input.amountMinor > input.autoApproveMaxMinor) {
    review.push('amount_above_auto_approve_limit');
    score += 40;
  }
  if (input.availableMinor > 0n && input.amountMinor * 100n >= input.availableMinor * 90n) {
    review.push('withdraws_nearly_all_available_balance');
    score += 10;
  }

  if (deny.length > 0) {
    return { decision: 'deny', score: 100, reasons: [...deny, ...review] };
  }
  score = Math.min(100, score);
  if (review.length > 0) return { decision: 'review', score, reasons: review };
  return { decision: 'approve', score, reasons: [] };
}
