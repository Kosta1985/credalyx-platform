import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto';

export type Currency = 'USD';
export type VerificationLevel = 0 | 1 | 2 | 3;
export type PassportStatus = 'active' | 'suspended' | 'revoked' | 'expired';

export interface AgentRecord {
  id: string;
  publicId: string;
  ownerId: string;
  organizationId?: string;
  publicKeyPem: string;
  capabilities: string[];
  endpoint: string;
  verificationLevel: VerificationLevel;
  controlVerifiedAt?: string;
  referrerAgentId?: string;
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

export class Ledger {
  readonly transactions: LedgerTransaction[] = [];
  private readonly idempotency = new Map<string, LedgerTransaction>();

  post(input: Omit<LedgerTransaction, 'id' | 'createdAt'>): LedgerTransaction {
    const existing = this.idempotency.get(input.idempotencyKey);
    if (existing) return existing;
    if (input.entries.length < 2) throw new Error('ledger transaction requires at least two entries');

    const totals = new Map<Currency, bigint>();
    for (const entry of input.entries) {
      totals.set(entry.currency, (totals.get(entry.currency) ?? 0n) + entry.amountMinor);
    }
    for (const [currency, total] of totals) {
      if (total !== 0n) throw new Error(`unbalanced ledger transaction for ${currency}`);
    }

    const tx: LedgerTransaction = {
      ...input,
      id: randomUUID(),
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

  constructor() {
    const pair = generateKeyPairSync('ed25519');
    this.publicKeyPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
    this.privateKeyPem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  }

  issue(agent: AgentRecord, ttlDays = 30): SignedPassport {
    if (agent.verificationLevel < 1 || !agent.controlVerifiedAt) {
      throw new Error('agent control must be verified before passport issuance');
    }
    const issued = new Date();
    const expires = new Date(issued.getTime() + ttlDays * 86_400_000);
    const claims: AgentPassportClaims = {
      passport_id: randomUUID(),
      agent_id: agent.publicId,
      issuer: 'https://credalyx.example',
      subject: `agent:${agent.publicId}`,
      verification_level: agent.verificationLevel,
      capabilities: [...agent.capabilities].sort(),
      issued_at: issued.toISOString(),
      expires_at: expires.toISOString(),
      public_key_reference: `${agent.publicId}#primary`,
      status_reference: `https://credalyx.example/v1/passports/status/${agent.publicId}`,
      schema_version: '1.0',
    };
    const payload = canonicalize(claims);
    const signature = sign(null, Buffer.from(payload), this.privateKeyPem).toString('base64url');
    return { claims, signature, status: 'active' };
  }

  verify(passport: SignedPassport): boolean {
    if (passport.status !== 'active') return false;
    if (Date.parse(passport.claims.expires_at) <= Date.now()) return false;
    return verify(
      null,
      Buffer.from(canonicalize(passport.claims)),
      this.publicKeyPem,
      Buffer.from(passport.signature, 'base64url'),
    );
  }
}

export class ChallengeService {
  private readonly challenges = new Map<string, { digest: string; expiresAt: number; consumed: boolean }>();

  create(agentId: string, ttlMs = 120_000): string {
    const challenge = randomBytes(32).toString('base64url');
    this.challenges.set(agentId, {
      digest: createHash('sha256').update(challenge).digest('hex'),
      expiresAt: Date.now() + ttlMs,
      consumed: false,
    });
    return challenge;
  }

  consume(agentId: string, challenge: string): boolean {
    const record = this.challenges.get(agentId);
    if (!record || record.consumed || record.expiresAt <= Date.now()) return false;
    const digest = createHash('sha256').update(challenge).digest('hex');
    if (digest !== record.digest) return false;
    record.consumed = true;
    return true;
  }
}

export function assertReferralAllowed(agentId: string, referrerAgentId?: string): void {
  if (!referrerAgentId) return;
  if (agentId === referrerAgentId) throw new Error('self-referral is forbidden');
}

export function recordPassportSale(
  ledger: Ledger,
  purchaseId: string,
  priceMinor: bigint,
  referralCommissionMinor: bigint,
  hasReferrer: boolean,
): LedgerTransaction {
  if (priceMinor <= 0n) throw new Error('price must be positive');
  if (referralCommissionMinor < 0n) throw new Error('commission cannot be negative');
  if (hasReferrer && referralCommissionMinor >= priceMinor) {
    throw new Error('commission must leave positive gross revenue before fees/taxes');
  }
  const entries: LedgerEntry[] = [
    { account: 'payment_provider_clearing', amountMinor: priceMinor, currency: 'USD' },
    { account: 'passport_revenue', amountMinor: -priceMinor, currency: 'USD' },
  ];
  if (hasReferrer && referralCommissionMinor > 0n) {
    entries.push(
      { account: 'passport_revenue', amountMinor: referralCommissionMinor, currency: 'USD' },
      { account: 'agent_owner_pending_balance', amountMinor: -referralCommissionMinor, currency: 'USD' },
    );
  }
  return ledger.post({
    idempotencyKey: `purchase:${purchaseId}`,
    externalReference: purchaseId,
    entries,
  });
}

function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(record[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
