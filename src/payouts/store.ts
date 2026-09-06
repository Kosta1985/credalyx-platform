import { uuidv7 } from '../crypto.js';
import {
  assertBalancedEntries,
  payoutReleaseEntries,
  payoutReservationEntries,
  payoutSettlementEntries,
  type AgentRecord,
  type Currency,
  type LedgerEntry,
} from '../domain.js';
import type { MemoryPlatformStore } from '../store.js';
import type { PayoutOnboardingSession, PayoutOnboardingStatus, ProviderPayout } from './provider.js';
import type { PayoutRiskAssessment } from './risk.js';

export type PayoutStatus = 'pending' | 'processing' | 'paid' | 'failed' | 'cancelled';

export interface PayoutAccountRecord {
  id: string;
  provider: string;
  providerAccountId: string;
  onboardingStatus: PayoutOnboardingStatus;
  onboardingUrl?: string;
  onboardingExpiresAt?: Date;
  ownerSubject?: string;
  organizationId?: string;
}

export interface PayoutRecord {
  id: string;
  payoutReference: string;
  agentId: string;
  payoutAccountId: string;
  provider: string;
  providerPayoutId?: string;
  amountMinor: bigint;
  currency: Currency;
  status: PayoutStatus;
  idempotencyKey: string;
  riskDecision: PayoutRiskAssessment['decision'];
  riskScore: number;
  reservedAt: Date;
  submittedAt?: Date;
  processedAt?: Date;
  failureReason?: string;
  createdAt: Date;
}

export interface PayoutRiskContextRecord {
  availableMinor: bigint;
  debtMinor: bigint;
  openPayoutCount: number;
  payoutCount24h: number;
  reversalMinor30d: bigint;
}

export interface PayoutSummary {
  reservedMinor: bigint;
  paidMinor: bigint;
  openPayoutCount: number;
}

export interface ReservePayoutInput {
  agent: AgentRecord;
  payoutAccount: PayoutAccountRecord;
  payoutReference: string;
  idempotencyKey: string;
  amountMinor: bigint;
  currency: Currency;
  assessment: PayoutRiskAssessment;
  reservedAt: Date;
}

export interface PayoutProviderEventInput {
  provider: string;
  eventId: string;
  eventType: 'payout.paid' | 'payout.failed';
  payloadHash: string;
  payoutReference: string;
  providerPayoutId: string;
  amountMinor: bigint;
  currency: Currency;
  failureReason?: string;
  occurredAt: Date;
}

export interface PayoutEventResult {
  duplicate: boolean;
  found: boolean;
  status?: PayoutStatus;
}

export interface PayoutStore {
  upsertPayoutAccount(agent: AgentRecord, session: PayoutOnboardingSession, now: Date): Promise<PayoutAccountRecord>;
  getPayoutAccount(agent: AgentRecord, provider: string): Promise<PayoutAccountRecord | null>;
  getRiskContext(agentId: string, now: Date): Promise<PayoutRiskContextRecord>;
  recordRiskAssessment(
    agentId: string,
    idempotencyKey: string,
    amountMinor: bigint,
    currency: Currency,
    assessment: PayoutRiskAssessment,
    now: Date,
  ): Promise<void>;
  reservePayout(input: ReservePayoutInput): Promise<{ duplicate: boolean; payout: PayoutRecord }>;
  markSubmitted(payoutReference: string, providerPayout: ProviderPayout, submittedAt: Date): Promise<PayoutRecord>;
  failSubmission(payoutReference: string, reason: string, failedAt: Date): Promise<PayoutRecord>;
  applyProviderEvent(input: PayoutProviderEventInput): Promise<PayoutEventResult>;
  getPayout(payoutReference: string): Promise<PayoutRecord | null>;
  listPayouts(agentId: string, limit: number): Promise<PayoutRecord[]>;
  getPayoutSummary(agentId: string): Promise<PayoutSummary>;
  close(): Promise<void>;
}

interface MemoryRiskAssessment {
  agentId: string;
  idempotencyKey: string;
  amountMinor: bigint;
  currency: Currency;
  assessment: PayoutRiskAssessment;
  createdAt: Date;
}

export class MemoryPayoutStore implements PayoutStore {
  readonly payoutAccounts = new Map<string, PayoutAccountRecord>();
  readonly payouts = new Map<string, PayoutRecord>();
  readonly riskAssessments: MemoryRiskAssessment[] = [];
  private readonly events = new Set<string>();
  private readonly idempotency = new Map<string, string>();

  constructor(private readonly platform: MemoryPlatformStore) {}

  async upsertPayoutAccount(agent: AgentRecord, session: PayoutOnboardingSession, _now: Date): Promise<PayoutAccountRecord> {
    const beneficiaryKey = beneficiaryKeyFor(agent, session.provider);
    const existing = this.payoutAccounts.get(beneficiaryKey);
    const record: PayoutAccountRecord = {
      id: existing?.id ?? uuidv7(),
      provider: session.provider,
      providerAccountId: session.providerAccountId,
      onboardingStatus: session.status,
      onboardingUrl: session.onboardingUrl,
      onboardingExpiresAt: session.expiresAt,
      ...(agent.organizationId ? { organizationId: agent.organizationId } : { ownerSubject: agent.ownerSubject }),
    };
    this.payoutAccounts.set(beneficiaryKey, record);
    return structuredClone(record);
  }

  async getPayoutAccount(agent: AgentRecord, provider: string): Promise<PayoutAccountRecord | null> {
    const value = this.payoutAccounts.get(beneficiaryKeyFor(agent, provider));
    return value ? structuredClone(value) : null;
  }

  async getRiskContext(agentId: string, now: Date): Promise<PayoutRiskContextRecord> {
    const availableSigned = this.sumAgentAccount(agentId, 'agent_owner_available_balance');
    const availableMinor = availableSigned < 0n ? -availableSigned : 0n;
    const debtMinor = availableSigned > 0n ? availableSigned : 0n;
    const dayAgo = now.getTime() - 86_400_000;
    const monthAgo = now.getTime() - 30 * 86_400_000;
    let payoutCount24h = 0;
    let openPayoutCount = 0;
    for (const payout of this.payouts.values()) {
      if (payout.agentId !== agentId) continue;
      if (payout.createdAt.getTime() >= dayAgo) payoutCount24h += 1;
      if (payout.status === 'pending' || payout.status === 'processing') openPayoutCount += 1;
    }
    let reversalMinor30d = 0n;
    for (const transaction of this.platform.ledgerTransactions.values()) {
      if (new Date(transaction.createdAt).getTime() < monthAgo) continue;
      if (transaction.transactionType !== 'passport_refund' && transaction.transactionType !== 'passport_chargeback') continue;
      for (const entry of transaction.entries) {
        if (entry.scopeType === 'agent' && entry.scopeId === agentId && entry.account === 'agent_owner_available_balance' && entry.amountMinor > 0n) {
          reversalMinor30d += entry.amountMinor;
        }
      }
    }
    return { availableMinor, debtMinor, openPayoutCount, payoutCount24h, reversalMinor30d };
  }

  async recordRiskAssessment(
    agentId: string,
    idempotencyKey: string,
    amountMinor: bigint,
    currency: Currency,
    assessment: PayoutRiskAssessment,
    now: Date,
  ): Promise<void> {
    this.riskAssessments.push({ agentId, idempotencyKey, amountMinor, currency, assessment: structuredClone(assessment), createdAt: now });
  }

  async reservePayout(input: ReservePayoutInput): Promise<{ duplicate: boolean; payout: PayoutRecord }> {
    const existingReference = this.idempotency.get(input.idempotencyKey);
    if (existingReference) {
      const existing = this.payouts.get(existingReference);
      if (!existing) throw new Error('payout idempotency index corrupted');
      if (existing.agentId !== input.agent.id || existing.amountMinor !== input.amountMinor || existing.currency !== input.currency) {
        throw new Error('payout idempotency key reused with different parameters');
      }
      return { duplicate: true, payout: structuredClone(existing) };
    }
    if (input.assessment.decision !== 'approve') throw new Error('payout risk decision is not approved');
    if (input.payoutAccount.onboardingStatus !== 'complete') throw new Error('payout account onboarding incomplete');
    if ([...this.payouts.values()].some((payout) => payout.agentId === input.agent.id && (payout.status === 'pending' || payout.status === 'processing'))) {
      throw new Error('open payout already exists');
    }
    const risk = await this.getRiskContext(input.agent.id, input.reservedAt);
    if (risk.debtMinor > 0n || risk.availableMinor < input.amountMinor) throw new Error('insufficient payout balance');

    const payout: PayoutRecord = {
      id: uuidv7(),
      payoutReference: input.payoutReference,
      agentId: input.agent.id,
      payoutAccountId: input.payoutAccount.id,
      provider: input.payoutAccount.provider,
      amountMinor: input.amountMinor,
      currency: input.currency,
      status: 'pending',
      idempotencyKey: input.idempotencyKey,
      riskDecision: input.assessment.decision,
      riskScore: input.assessment.score,
      reservedAt: input.reservedAt,
      createdAt: input.reservedAt,
    };
    this.postLedger(
      `payout_reservation:${payout.payoutReference}`,
      'payout_reservation',
      payout.payoutReference,
      payoutReservationEntries(payout.amountMinor, payout.agentId),
      input.reservedAt,
    );
    this.payouts.set(payout.payoutReference, payout);
    this.idempotency.set(input.idempotencyKey, payout.payoutReference);
    return { duplicate: false, payout: structuredClone(payout) };
  }

  async markSubmitted(payoutReference: string, providerPayout: ProviderPayout, submittedAt: Date): Promise<PayoutRecord> {
    const payout = this.payouts.get(payoutReference);
    if (!payout) throw new Error('payout not found');
    if (providerPayout.payoutReference !== payoutReference || providerPayout.provider !== payout.provider || providerPayout.amountMinor !== payout.amountMinor || providerPayout.currency !== payout.currency) {
      throw new Error('provider payout does not match reservation');
    }
    if (payout.status === 'processing' && payout.providerPayoutId === providerPayout.providerPayoutId) return structuredClone(payout);
    if (payout.status !== 'pending') throw new Error('payout is not pending submission');
    payout.providerPayoutId = providerPayout.providerPayoutId;
    payout.status = providerPayout.status === 'paid' ? 'paid' : providerPayout.status === 'failed' ? 'failed' : 'processing';
    payout.submittedAt = submittedAt;
    if (providerPayout.status === 'paid') {
      this.settlePayout(payout, submittedAt);
      payout.processedAt = submittedAt;
    } else if (providerPayout.status === 'failed') {
      this.releasePayout(payout, 'provider_submission_failed', submittedAt);
      payout.processedAt = submittedAt;
      payout.failureReason = 'provider_submission_failed';
    }
    return structuredClone(payout);
  }

  async failSubmission(payoutReference: string, reason: string, failedAt: Date): Promise<PayoutRecord> {
    const payout = this.payouts.get(payoutReference);
    if (!payout) throw new Error('payout not found');
    if (payout.status === 'failed') return structuredClone(payout);
    if (payout.status !== 'pending') throw new Error('only pending payout can fail before submission');
    this.releasePayout(payout, reason, failedAt);
    payout.status = 'failed';
    payout.failureReason = reason;
    payout.processedAt = failedAt;
    return structuredClone(payout);
  }

  async applyProviderEvent(input: PayoutProviderEventInput): Promise<PayoutEventResult> {
    const eventKey = `${input.provider}:${input.eventId}`;
    if (this.events.has(eventKey)) {
      const existing = this.payouts.get(input.payoutReference);
      return { duplicate: true, found: Boolean(existing), ...(existing ? { status: existing.status } : {}) };
    }
    const payout = this.payouts.get(input.payoutReference);
    if (!payout) {
      this.events.add(eventKey);
      return { duplicate: false, found: false };
    }
    if (payout.provider !== input.provider || payout.providerPayoutId !== input.providerPayoutId || payout.amountMinor !== input.amountMinor || payout.currency !== input.currency) {
      throw new Error('payout provider event mismatch');
    }
    if (payout.status === 'paid' || payout.status === 'failed' || payout.status === 'cancelled') {
      this.events.add(eventKey);
      return { duplicate: true, found: true, status: payout.status };
    }
    if (input.eventType === 'payout.paid') {
      this.settlePayout(payout, input.occurredAt);
      payout.status = 'paid';
    } else {
      this.releasePayout(payout, input.failureReason ?? 'provider_failed', input.occurredAt);
      payout.status = 'failed';
      payout.failureReason = input.failureReason ?? 'provider_failed';
    }
    payout.processedAt = input.occurredAt;
    this.events.add(eventKey);
    return { duplicate: false, found: true, status: payout.status };
  }

  async getPayout(payoutReference: string): Promise<PayoutRecord | null> {
    const value = this.payouts.get(payoutReference);
    return value ? structuredClone(value) : null;
  }

  async listPayouts(agentId: string, limit: number): Promise<PayoutRecord[]> {
    return [...this.payouts.values()]
      .filter((payout) => payout.agentId === agentId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit)
      .map((payout) => structuredClone(payout));
  }

  async getPayoutSummary(agentId: string): Promise<PayoutSummary> {
    const reservedSigned = this.sumAgentAccount(agentId, 'agent_owner_reserved_balance');
    let paidMinor = 0n;
    let openPayoutCount = 0;
    for (const payout of this.payouts.values()) {
      if (payout.agentId !== agentId) continue;
      if (payout.status === 'paid') paidMinor += payout.amountMinor;
      if (payout.status === 'pending' || payout.status === 'processing') openPayoutCount += 1;
    }
    return {
      reservedMinor: reservedSigned < 0n ? -reservedSigned : 0n,
      paidMinor,
      openPayoutCount,
    };
  }

  async close(): Promise<void> {}

  private sumAgentAccount(agentId: string, account: LedgerEntry['account']): bigint {
    let signed = 0n;
    for (const transaction of this.platform.ledgerTransactions.values()) {
      for (const entry of transaction.entries) {
        if (entry.scopeType === 'agent' && entry.scopeId === agentId && entry.account === account) signed += entry.amountMinor;
      }
    }
    return signed;
  }

  private postLedger(
    idempotencyKey: string,
    transactionType: string,
    externalReference: string,
    entries: readonly LedgerEntry[],
    occurredAt: Date,
  ): void {
    if (this.platform.ledgerTransactions.has(idempotencyKey)) return;
    assertBalancedEntries(entries);
    this.platform.ledgerTransactions.set(idempotencyKey, {
      id: uuidv7(),
      idempotencyKey,
      transactionType,
      externalReference,
      createdAt: occurredAt.toISOString(),
      entries: Object.freeze([...entries]),
    });
  }

  private settlePayout(payout: PayoutRecord, occurredAt: Date): void {
    this.postLedger(
      `payout_paid:${payout.payoutReference}`,
      'payout_paid',
      payout.payoutReference,
      payoutSettlementEntries(payout.amountMinor, payout.agentId),
      occurredAt,
    );
  }

  private releasePayout(payout: PayoutRecord, _reason: string, occurredAt: Date): void {
    this.postLedger(
      `payout_release:${payout.payoutReference}`,
      'payout_release',
      payout.payoutReference,
      payoutReleaseEntries(payout.amountMinor, payout.agentId),
      occurredAt,
    );
  }
}

function beneficiaryKeyFor(agent: AgentRecord, provider: string): string {
  return agent.organizationId
    ? `${provider}:org:${agent.organizationId}`
    : `${provider}:owner:${agent.ownerSubject}`;
}
