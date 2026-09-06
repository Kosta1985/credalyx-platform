import { uuidv7 } from './crypto.js';
import { assertBalancedEntries, type AgentRecord, type LedgerEntry, type SignedPassport } from './domain.js';

export interface ChallengeRecordInput {
  agentId: string;
  digest: string;
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

export interface PlatformStore {
  createAgent(agent: AgentRecord): Promise<void>;
  getAgent(publicId: string): Promise<AgentRecord | null>;
  getAgentByReferralCode(referralCode: string): Promise<AgentRecord | null>;
  createChallenge(input: ChallengeRecordInput): Promise<void>;
  confirmAgentControl(agent: AgentRecord, digest: string, verifiedAt: Date): Promise<boolean>;
  finalizePassportPurchase(input: FinalizePurchaseInput): Promise<{ duplicate: boolean }>;
  getPassport(passportId: string): Promise<SignedPassport | null>;
  revokePassport(passportId: string, reason: string, actorSubject: string): Promise<boolean>;
  close(): Promise<void>;
}

export class MemoryPlatformStore implements PlatformStore {
  readonly agents = new Map<string, AgentRecord>();
  readonly passports = new Map<string, SignedPassport>();
  readonly ledgerTransactions = new Map<string, { id: string; entries: readonly LedgerEntry[] }>();
  readonly commissions = new Map<string, { amountMinor: bigint; status: 'pending' | 'reversed' | 'available' }>();
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

  async finalizePassportPurchase(input: FinalizePurchaseInput): Promise<{ duplicate: boolean }> {
    const eventKey = `${input.provider}:${input.eventId}`;
    if (this.webhookEvents.has(eventKey)) return { duplicate: true };
    const currentAgent = this.agents.get(input.agent.publicId);
    if (!currentAgent || currentAgent.verificationLevel < 1 || !currentAgent.controlVerifiedAt) {
      throw new Error('agent control is not verified');
    }
    assertBalancedEntries(input.ledgerEntries);
    const idempotencyKey = `purchase:${input.purchaseId}`;
    if (this.ledgerTransactions.has(idempotencyKey)) {
      this.webhookEvents.add(eventKey);
      return { duplicate: true };
    }
    this.passports.set(input.passport.claims.passport_id, structuredClone(input.passport));
    this.ledgerTransactions.set(idempotencyKey, { id: uuidv7(), entries: [...input.ledgerEntries] });
    if (input.agent.referrerAgentId && input.referralCommissionMinor > 0n) {
      this.commissions.set(input.purchaseId, { amountMinor: input.referralCommissionMinor, status: 'pending' });
    }
    currentAgent.status = 'active';
    currentAgent.version += 1;
    this.webhookEvents.add(eventKey);
    return { duplicate: false };
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
