import { uuidv7 } from './crypto.js';
import {
  assertBalancedEntries,
  commissionReleaseEntries,
  passportReversalEntries,
  type AgentRecord,
  type CommissionStatus,
  type Currency,
  type LedgerEntry,
  type ReversalKind,
  type SignedPassport,
} from './domain.js';

export interface ChallengeRecordInput {
  agentId: string;
  digest: string;
  expiresAt: Date;
}

export interface PaymentSessionRecord {
  provider: string;
  providerSessionId: string;
  idempotencyKey: string;
  purchaseReference: string;
  agentId: string;
  agentPublicId: string;
  checkoutUrl: string;
  amountMinor: bigint;
  currency: Currency;
  status: 'pending' | 'paid' | 'expired' | 'cancelled';
  expiresAt: Date;
}

export interface FinalizePurchaseInput {
  provider: string;
  eventId: string;
  eventType: string;
  payloadHash: string;
  purchaseId: string;
  agent: AgentRecord;
  passport: SignedPassport;
  priceMinor: bigint;
  referralCommissionMinor: bigint;
  holdUntil: Date;
  ledgerEntries: readonly LedgerEntry[];
}

export interface ReversePurchaseInput {
  provider: string;
  eventId: string;
  eventType: string;
  payloadHash: string;
  purchaseId: string;
  kind: ReversalKind;
  reasonCode: string;
  occurredAt: Date;
}

export interface ReversePurchaseResult {
  duplicate: boolean;
  found: boolean;
  passportId?: string;
  commissionReversed: boolean;
}

export interface CommissionReleaseResult {
  released: number;
  amountMinor: bigint;
}

export interface WalletSnapshot {
  currency: Currency;
  pendingMinor: bigint;
  availableMinor: bigint;
  debtMinor: bigint;
  paidMinor: bigint;
  reversedMinor: bigint;
  minPayoutMinor: bigint;
  payoutEligible: boolean;
}

export interface WalletTransactionView {
  transactionId: string;
  transactionType: string;
  externalReference: string;
  createdAt: string;
  account: string;
  amountMinor: bigint;
  currency: Currency;
}

export interface PlatformStore {
  createAgent(agent: AgentRecord): Promise<void>;
  getAgent(publicId: string): Promise<AgentRecord | null>;
  getAgentByReferralCode(referralCode: string): Promise<AgentRecord | null>;
  createChallenge(input: ChallengeRecordInput): Promise<void>;
  confirmAgentControl(agent: AgentRecord, digest: string, verifiedAt: Date): Promise<boolean>;
  createPaymentSession(input: PaymentSessionRecord): Promise<PaymentSessionRecord>;
  getPaymentSessionByPurchaseReference(purchaseReference: string): Promise<PaymentSessionRecord | null>;
  getActivePassportForAgent(agentId: string): Promise<SignedPassport | null>;
  finalizePassportPurchase(input: FinalizePurchaseInput): Promise<{ duplicate: boolean }>;
  reversePassportPurchase(input: ReversePurchaseInput): Promise<ReversePurchaseResult>;
  releaseEligibleCommissions(now: Date, limit: number): Promise<CommissionReleaseResult>;
  getWallet(agentId: string, minPayoutMinor: bigint): Promise<WalletSnapshot>;
  listWalletTransactions(agentId: string, limit: number): Promise<WalletTransactionView[]>;
  getPassport(passportId: string): Promise<SignedPassport | null>;
  revokePassport(passportId: string, reason: string, actorSubject: string): Promise<boolean>;
  close(): Promise<void>;
}

interface MemoryPurchase {
  purchaseId: string;
  agentId: string;
  passportId: string;
  priceMinor: bigint;
  referrerAgentId?: string;
  referralCommissionMinor: bigint;
  status: 'paid' | 'refunded' | 'chargeback';
}

interface MemoryLedgerTransaction {
  id: string;
  idempotencyKey: string;
  transactionType: string;
  externalReference: string;
  createdAt: string;
  entries: readonly LedgerEntry[];
}

export class MemoryPlatformStore implements PlatformStore {
  readonly agents = new Map<string, AgentRecord>();
  readonly passports = new Map<string, SignedPassport>();
  readonly ledgerTransactions = new Map<string, MemoryLedgerTransaction>();
  readonly commissions = new Map<string, {
    amountMinor: bigint;
    referrerAgentId: string;
    holdUntil: Date;
    status: CommissionStatus;
  }>();
  readonly paymentSessions = new Map<string, PaymentSessionRecord>();
  readonly purchases = new Map<string, MemoryPurchase>();
  private readonly paymentSessionIdempotency = new Map<string, string>();
  private readonly referralIndex = new Map<string, string>();
  private readonly challenges = new Map<string, { digest: string; expiresAt: number; consumed: boolean }>();
  private readonly webhookEvents = new Set<string>();

  async createAgent(agent: AgentRecord): Promise<void> {
    if (this.agents.has(agent.publicId)) throw new Error('agent already exists');
    if (this.referralIndex.has(agent.referralCode)) throw new Error('referral code already exists');
    this.agents.set(agent.publicId, structuredClone(agent));
    this.referralIndex.set(agent.referralCode, agent.publicId);
  }

  async getAgent(publicId: string): Promise<AgentRecord | null> {
    const value = this.agents.get(publicId);
    return value ? structuredClone(value) : null;
  }

  async getAgentByReferralCode(referralCode: string): Promise<AgentRecord | null> {
    const publicId = this.referralIndex.get(referralCode);
    return publicId ? this.getAgent(publicId) : null;
  }

  async createChallenge(input: ChallengeRecordInput): Promise<void> {
    this.challenges.set(input.agentId, { digest: input.digest, expiresAt: input.expiresAt.getTime(), consumed: false });
  }

  async confirmAgentControl(agent: AgentRecord, digest: string, verifiedAt: Date): Promise<boolean> {
    const record = this.challenges.get(agent.id);
    if (!record || record.consumed || record.digest !== digest || record.expiresAt <= verifiedAt.getTime()) return false;
    record.consumed = true;
    const stored = this.agents.get(agent.publicId);
    if (!stored) return false;
    stored.verificationLevel = Math.max(stored.verificationLevel, 1) as 1 | 2 | 3;
    stored.controlVerifiedAt = verifiedAt.toISOString();
    stored.version += 1;
    return true;
  }

  async createPaymentSession(input: PaymentSessionRecord): Promise<PaymentSessionRecord> {
    const idempotencyKey = `${input.provider}:${input.idempotencyKey}`;
    const existingPurchaseReference = this.paymentSessionIdempotency.get(idempotencyKey);
    if (existingPurchaseReference) {
      const existing = this.paymentSessions.get(existingPurchaseReference);
      if (!existing) throw new Error('payment session index corrupted');
      if (existing.agentId !== input.agentId || existing.amountMinor !== input.amountMinor || existing.currency !== input.currency) {
        throw new Error('idempotency key reused with different checkout parameters');
      }
      return structuredClone(existing);
    }
    if (this.paymentSessions.has(input.purchaseReference)) throw new Error('purchase reference already exists');
    const record = structuredClone(input);
    this.paymentSessions.set(input.purchaseReference, record);
    this.paymentSessionIdempotency.set(idempotencyKey, input.purchaseReference);
    return structuredClone(record);
  }

  async getPaymentSessionByPurchaseReference(purchaseReference: string): Promise<PaymentSessionRecord | null> {
    const value = this.paymentSessions.get(purchaseReference);
    return value ? structuredClone(value) : null;
  }

  async getActivePassportForAgent(agentId: string): Promise<SignedPassport | null> {
    for (const passport of this.passports.values()) {
      const agent = this.agents.get(passport.claims.agent_id);
      if (agent?.id === agentId && passport.status === 'active' && Date.parse(passport.claims.expires_at) > Date.now()) {
        return structuredClone(passport);
      }
    }
    return null;
  }

  private postLedger(input: {
    idempotencyKey: string;
    transactionType: string;
    externalReference: string;
    entries: readonly LedgerEntry[];
  }): MemoryLedgerTransaction {
    const existing = this.ledgerTransactions.get(input.idempotencyKey);
    if (existing) return existing;
    assertBalancedEntries(input.entries);
    const transaction: MemoryLedgerTransaction = {
      id: uuidv7(),
      idempotencyKey: input.idempotencyKey,
      transactionType: input.transactionType,
      externalReference: input.externalReference,
      createdAt: new Date().toISOString(),
      entries: Object.freeze([...input.entries]),
    };
    this.ledgerTransactions.set(input.idempotencyKey, transaction);
    return transaction;
  }

  async finalizePassportPurchase(input: FinalizePurchaseInput): Promise<{ duplicate: boolean }> {
    const eventKey = `${input.provider}:${input.eventId}`;
    if (this.webhookEvents.has(eventKey)) return { duplicate: true };
    const session = this.paymentSessions.get(input.purchaseId);
    if (!session || session.provider !== input.provider || session.agentId !== input.agent.id || session.amountMinor !== input.priceMinor) {
      throw new Error('payment event does not match a checkout session');
    }
    const currentAgent = this.agents.get(input.agent.publicId);
    if (!currentAgent || currentAgent.verificationLevel < 1 || !currentAgent.controlVerifiedAt) {
      throw new Error('agent control is not verified');
    }
    if (this.purchases.has(input.purchaseId)) {
      this.webhookEvents.add(eventKey);
      return { duplicate: true };
    }
    assertBalancedEntries(input.ledgerEntries);
    this.passports.set(input.passport.claims.passport_id, structuredClone(input.passport));
    this.postLedger({
      idempotencyKey: `purchase:${input.purchaseId}`,
      transactionType: 'passport_sale',
      externalReference: input.purchaseId,
      entries: input.ledgerEntries,
    });
    this.purchases.set(input.purchaseId, {
      purchaseId: input.purchaseId,
      agentId: input.agent.id,
      passportId: input.passport.claims.passport_id,
      priceMinor: input.priceMinor,
      referralCommissionMinor: input.referralCommissionMinor,
      status: 'paid',
      ...(input.agent.referrerAgentId ? { referrerAgentId: input.agent.referrerAgentId } : {}),
    });
    if (input.agent.referrerAgentId && input.referralCommissionMinor > 0n) {
      this.commissions.set(input.purchaseId, {
        amountMinor: input.referralCommissionMinor,
        referrerAgentId: input.agent.referrerAgentId,
        holdUntil: input.holdUntil,
        status: 'pending',
      });
    }
    session.status = 'paid';
    currentAgent.status = 'active';
    currentAgent.version += 1;
    this.webhookEvents.add(eventKey);
    return { duplicate: false };
  }

  async reversePassportPurchase(input: ReversePurchaseInput): Promise<ReversePurchaseResult> {
    const eventKey = `${input.provider}:${input.eventId}`;
    if (this.webhookEvents.has(eventKey)) return { duplicate: true, found: true, commissionReversed: false };
    const purchase = this.purchases.get(input.purchaseId);
    if (!purchase) return { duplicate: false, found: false, commissionReversed: false };
    if (purchase.status !== 'paid') {
      this.webhookEvents.add(eventKey);
      return { duplicate: true, found: true, passportId: purchase.passportId, commissionReversed: false };
    }
    const commission = this.commissions.get(input.purchaseId);
    const entries = passportReversalEntries({
      kind: input.kind,
      priceMinor: purchase.priceMinor,
      referralCommissionMinor: commission?.amountMinor ?? 0n,
      ...(purchase.referrerAgentId ? { referrerAgentId: purchase.referrerAgentId } : {}),
      ...(commission ? { commissionStatus: commission.status } : {}),
    });
    this.postLedger({
      idempotencyKey: `${input.kind}:${input.purchaseId}`,
      transactionType: input.kind === 'refund' ? 'passport_refund' : 'passport_chargeback',
      externalReference: input.purchaseId,
      entries,
    });
    purchase.status = input.kind === 'refund' ? 'refunded' : 'chargeback';
    const passport = this.passports.get(purchase.passportId);
    if (passport) passport.status = 'revoked';
    if (commission && commission.status !== 'reversed') commission.status = 'reversed';
    this.webhookEvents.add(eventKey);
    return {
      duplicate: false,
      found: true,
      passportId: purchase.passportId,
      commissionReversed: Boolean(commission),
    };
  }

  async releaseEligibleCommissions(now: Date, limit: number): Promise<CommissionReleaseResult> {
    let released = 0;
    let amountMinor = 0n;
    for (const [purchaseId, commission] of this.commissions) {
      if (released >= limit) break;
      if (commission.status !== 'pending' || commission.holdUntil.getTime() > now.getTime()) continue;
      const entries = commissionReleaseEntries(commission.amountMinor, commission.referrerAgentId);
      this.postLedger({
        idempotencyKey: `commission_release:${purchaseId}`,
        transactionType: 'commission_release',
        externalReference: purchaseId,
        entries,
      });
      commission.status = 'available';
      released += 1;
      amountMinor += commission.amountMinor;
    }
    return { released, amountMinor };
  }

  async getWallet(agentId: string, minPayoutMinor: bigint): Promise<WalletSnapshot> {
    let pendingSigned = 0n;
    let availableSigned = 0n;
    let paidMinor = 0n;
    let reversedMinor = 0n;
    for (const transaction of this.ledgerTransactions.values()) {
      for (const entry of transaction.entries) {
        if (entry.scopeType !== 'agent' || entry.scopeId !== agentId) continue;
        if (entry.account === 'agent_owner_pending_balance') pendingSigned += entry.amountMinor;
        if (entry.account === 'agent_owner_available_balance') availableSigned += entry.amountMinor;
      }
    }
    for (const commission of this.commissions.values()) {
      if (commission.referrerAgentId !== agentId) continue;
      if (commission.status === 'paid') paidMinor += commission.amountMinor;
      if (commission.status === 'reversed') reversedMinor += commission.amountMinor;
    }
    const pendingMinor = pendingSigned < 0n ? -pendingSigned : 0n;
    const availableMinor = availableSigned < 0n ? -availableSigned : 0n;
    const debtMinor = availableSigned > 0n ? availableSigned : 0n;
    return {
      currency: 'USD',
      pendingMinor,
      availableMinor,
      debtMinor,
      paidMinor,
      reversedMinor,
      minPayoutMinor,
      payoutEligible: debtMinor === 0n && availableMinor >= minPayoutMinor,
    };
  }

  async listWalletTransactions(agentId: string, limit: number): Promise<WalletTransactionView[]> {
    const rows: WalletTransactionView[] = [];
    const transactions = [...this.ledgerTransactions.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    for (const transaction of transactions) {
      for (const entry of transaction.entries) {
        if (entry.scopeType !== 'agent' || entry.scopeId !== agentId) continue;
        rows.push({
          transactionId: transaction.id,
          transactionType: transaction.transactionType,
          externalReference: transaction.externalReference,
          createdAt: transaction.createdAt,
          account: entry.account,
          amountMinor: entry.amountMinor,
          currency: entry.currency,
        });
        if (rows.length >= limit) return rows;
      }
    }
    return rows;
  }

  async getPassport(passportId: string): Promise<SignedPassport | null> {
    const value = this.passports.get(passportId);
    return value ? structuredClone(value) : null;
  }

  async revokePassport(passportId: string, _reason: string, _actorSubject: string): Promise<boolean> {
    const passport = this.passports.get(passportId);
    if (!passport) return false;
    if (passport.status === 'revoked') return true;
    passport.status = 'revoked';
    return true;
  }

  async close(): Promise<void> {}
}
