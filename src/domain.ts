import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { canonicalize, uuidv7 } from './crypto.js';

export type Currency = 'USD';
export type VerificationLevel = 0 | 1 | 2 | 3;
export type AgentStatus = 'pending' | 'active' | 'suspended' | 'revoked';
export type PassportStatus = 'active' | 'suspended' | 'revoked' | 'expired';

export interface AgentRecord {
  id: string;
  publicId: string;
  ownerSubject: string;
  organizationId?: string;
  publicKeyPem: string;
  capabilities: string[];
  endpoint: string;
  verificationLevel: VerificationLevel;
  status: AgentStatus;
  controlVerifiedAt?: string;
  referrerAgentId?: string;
  referralCode: string;
  version: number;
}

export interface AgentPassportClaims {
  passport_id: string;
  agent_id: string;
  issuer: string;
  subject: string;
  verification_level: VerificationLevel;
  capabilities: string[];
  issued_at: string;
  expires_at: string;
  public_key_reference: string;
  status_reference: string;
  schema_version: '1.0';
}

export interface SignedPassport {
  claims: AgentPassportClaims;
  signature: string;
  status: PassportStatus;
}

export type LedgerAccount =
  | 'platform_cash'
  | 'payment_provider_clearing'
  | 'passport_revenue'
  | 'referral_commission_payable'
  | 'agent_owner_available_balance'
  | 'agent_owner_pending_balance'
  | 'refunds'
  | 'chargebacks'
  | 'provider_fees'
  | 'tax_payable';

export interface LedgerEntry {
  account: LedgerAccount;
  scopeType: 'platform' | 'agent';
  scopeId: string;
  amountMinor: bigint;
  currency: Currency;
}

export interface LedgerTransaction {
  id: string;
  idempotencyKey: string;
  externalReference: string;
  createdAt: string;
  entries: readonly LedgerEntry[];
}

export function assertBalancedEntries(entries: readonly LedgerEntry[]): void {
  if (entries.length < 2) throw new Error('ledger transaction requires at least two entries');
  const totals = new Map<Currency, bigint>();
  for (const entry of entries) totals.set(entry.currency, (totals.get(entry.currency) ?? 0n) + entry.amountMinor);
  for (const [currency, total] of totals) {
    if (total !== 0n) throw new Error(`unbalanced ledger transaction for ${currency}`);
  }
}

export class Ledger {
  readonly transactions: LedgerTransaction[] = [];
  private readonly idempotency = new Map<string, LedgerTransaction>();

  post(input: Omit<LedgerTransaction, 'id' | 'createdAt'>): LedgerTransaction {
    const existing = this.idempotency.get(input.idempotencyKey);
    if (existing) return existing;
    assertBalancedEntries(input.entries);
    const tx: LedgerTransaction = {
      ...input,
      id: uuidv7(),
      createdAt: new Date().toISOString(),
      entries: Object.freeze([...input.entries]),
    };
    this.transactions.push(tx);
    this.idempotency.set(tx.idempotencyKey, tx);
    return tx;
  }
}

export class PassportSigner {
  readonly publicKeyPem: string;
  private readonly privateKeyPem: string;
  readonly issuer: string;

  constructor(input: { privateKeyPem: string; publicKeyPem: string; issuer: string }) {
    this.privateKeyPem = input.privateKeyPem;
    this.publicKeyPem = input.publicKeyPem;
    this.issuer = input.issuer.replace(/\/$/, '');
  }

  static ephemeral(issuer = 'https://credalyx.example'): PassportSigner {
    const pair = generateKeyPairSync('ed25519');
    return new PassportSigner({
      issuer,
      publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      privateKeyPem: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    });
  }

  issue(agent: AgentRecord, ttlDays = 30): SignedPassport {
    if (agent.verificationLevel < 1 || !agent.controlVerifiedAt) {
      throw new Error('agent control must be verified before passport issuance');
    }
    if (agent.status === 'revoked' || agent.status === 'suspended') throw new Error('agent is not eligible for passport issuance');
    const issued = new Date();
    const expires = new Date(issued.getTime() + ttlDays * 86_400_000);
    const passportId = uuidv7();
    const claims: AgentPassportClaims = {
      passport_id: passportId,
      agent_id: agent.publicId,
      issuer: this.issuer,
      subject: `agent:${agent.publicId}`,
      verification_level: agent.verificationLevel,
      capabilities: [...agent.capabilities].sort(),
      issued_at: issued.toISOString(),
      expires_at: expires.toISOString(),
      public_key_reference: `${this.issuer}/v1/agents/${agent.publicId}/keys/current`,
      status_reference: `${this.issuer}/v1/passports/${passportId}/status`,
      schema_version: '1.0',
    };
    const signature = sign(null, Buffer.from(canonicalize(claims)), this.privateKeyPem).toString('base64url');
    return { claims, signature, status: 'active' };
  }

  verify(passport: SignedPassport, nowMs = Date.now()): boolean {
    if (passport.status !== 'active') return false;
    if (Date.parse(passport.claims.expires_at) <= nowMs) return false;
    if (passport.claims.issuer !== this.issuer) return false;
    return verify(
      null,
      Buffer.from(canonicalize(passport.claims)),
      this.publicKeyPem,
      Buffer.from(passport.signature, 'base64url'),
    );
  }
}

export function assertReferralAllowed(input: {
  newAgentPublicId: string;
  ownerSubject: string;
  referrer?: Pick<AgentRecord, 'publicId' | 'ownerSubject'>;
}): void {
  if (!input.referrer) return;
  if (input.newAgentPublicId === input.referrer.publicId) throw new Error('self-referral is forbidden');
  if (input.ownerSubject === input.referrer.ownerSubject) throw new Error('self-referral by common owner is forbidden');
}

export function passportSaleEntries(priceMinor: bigint, referralCommissionMinor: bigint, referrerAgentId?: string): LedgerEntry[] {
  if (priceMinor <= 0n) throw new Error('price must be positive');
  if (referralCommissionMinor < 0n) throw new Error('commission cannot be negative');
  if (referrerAgentId && referralCommissionMinor >= priceMinor) throw new Error('commission must be below price');
  const entries: LedgerEntry[] = [
    { account: 'payment_provider_clearing', scopeType: 'platform', scopeId: 'platform', amountMinor: priceMinor, currency: 'USD' },
    { account: 'passport_revenue', scopeType: 'platform', scopeId: 'platform', amountMinor: -priceMinor, currency: 'USD' },
  ];
  if (referrerAgentId && referralCommissionMinor > 0n) {
    entries.push(
      { account: 'passport_revenue', scopeType: 'platform', scopeId: 'platform', amountMinor: referralCommissionMinor, currency: 'USD' },
      { account: 'agent_owner_pending_balance', scopeType: 'agent', scopeId: referrerAgentId, amountMinor: -referralCommissionMinor, currency: 'USD' },
    );
  }
  assertBalancedEntries(entries);
  return entries;
}

export function passportRefundEntries(priceMinor: bigint, referralCommissionMinor: bigint, referrerAgentId?: string): LedgerEntry[] {
  if (priceMinor <= 0n) throw new Error('price must be positive');
  const entries: LedgerEntry[] = [
    { account: 'refunds', scopeType: 'platform', scopeId: 'platform', amountMinor: priceMinor, currency: 'USD' },
    { account: 'payment_provider_clearing', scopeType: 'platform', scopeId: 'platform', amountMinor: -priceMinor, currency: 'USD' },
  ];
  if (referrerAgentId && referralCommissionMinor > 0n) {
    entries.push(
      { account: 'agent_owner_pending_balance', scopeType: 'agent', scopeId: referrerAgentId, amountMinor: referralCommissionMinor, currency: 'USD' },
      { account: 'refunds', scopeType: 'platform', scopeId: 'platform', amountMinor: -referralCommissionMinor, currency: 'USD' },
    );
  }
  assertBalancedEntries(entries);
  return entries;
}
