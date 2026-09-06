import { and, eq, gt, isNull } from 'drizzle-orm';
import { assertBalancedEntries, type AgentPassportClaims, type AgentRecord, type LedgerAccount, type SignedPassport } from '../domain.js';
import { uuidv7 } from '../crypto.js';
import type { ChallengeRecordInput, FinalizePurchaseInput, PlatformStore } from '../store.js';
import { createDatabase, type Database } from './client.js';
import {
  agentCapabilities,
  agentChallenges,
  agentEndpoints,
  agentKeys,
  agentPassports,
  agents,
  auditEvents,
  commissions,
  ledgerAccounts,
  ledgerEntries,
  ledgerTransactions,
  organizationMembers,
  passportStatusHistory,
  paymentEvents,
  purchases,
  referrals,
  users,
  webhookEvents,
} from './schema.js';

const MANAGE_ROLES = new Set(['owner', 'admin', 'developer']);

export class PostgresPlatformStore implements PlatformStore {
  private readonly client: ReturnType<typeof createDatabase>['client'];
  private readonly db: Database;

  constructor(databaseUrl: string) {
    const connection = createDatabase(databaseUrl);
    this.client = connection.client;
    this.db = connection.db;
  }

  private async ensureUser(tx: Database, externalSubject: string): Promise<string> {
    const existing = await tx.select({ id: users.id }).from(users).where(eq(users.externalSubject, externalSubject)).limit(1);
    if (existing[0]) return existing[0].id;
    const id = uuidv7();
    await tx.insert(users).values({ id, externalSubject }).onConflictDoNothing({ target: users.externalSubject });
    const resolved = await tx.select({ id: users.id }).from(users).where(eq(users.externalSubject, externalSubject)).limit(1);
    if (!resolved[0]) throw new Error('failed to resolve owner user');
    return resolved[0].id;
  }

  private async assertOrganizationAccess(tx: Database, userId: string, organizationId?: string): Promise<void> {
    if (!organizationId) return;
    const memberships = await tx.select({ role: organizationMembers.role })
      .from(organizationMembers)
      .where(and(
        eq(organizationMembers.organizationId, organizationId),
        eq(organizationMembers.userId, userId),
        isNull(organizationMembers.revokedAt),
      ))
      .limit(1);
    const membership = memberships[0];
    if (!membership || !MANAGE_ROLES.has(membership.role)) throw new Error('organization access denied');
  }

  async createAgent(agent: AgentRecord): Promise<void> {
    await this.db.transaction(async (tx) => {
      const ownerUserId = await this.ensureUser(tx as Database, agent.ownerSubject);
      await this.assertOrganizationAccess(tx as Database, ownerUserId, agent.organizationId);
      await tx.insert(agents).values({
        id: agent.id,
        publicId: agent.publicId,
        ownerUserId,
        ...(agent.organizationId ? { organizationId: agent.organizationId } : {}),
        ...(agent.referrerAgentId ? { referrerAgentId: agent.referrerAgentId } : {}),
        referralCode: agent.referralCode,
        verificationLevel: agent.verificationLevel,
        status: agent.status,
        version: agent.version,
      });
      await tx.insert(agentKeys).values({
        id: uuidv7(),
        agentId: agent.id,
        keyId: 'primary',
        algorithm: 'Ed25519',
        publicKeyPem: agent.publicKeyPem,
      });
      await tx.insert(agentEndpoints).values({
        id: uuidv7(),
        agentId: agent.id,
        url: agent.endpoint,
        protocolBinding: 'HTTP+JSON',
        protocolVersion: '1.0',
      });
      if (agent.capabilities.length > 0) {
        await tx.insert(agentCapabilities).values(agent.capabilities.map((capability) => ({
          id: uuidv7(),
          agentId: agent.id,
          capability,
        })));
      }
      if (agent.referrerAgentId) {
        await tx.insert(referrals).values({
          id: uuidv7(),
          referredAgentId: agent.id,
          referrerAgentId: agent.referrerAgentId,
          referralCode: 'attributed',
        });
      }
      await tx.insert(auditEvents).values({
        id: uuidv7(),
        actorType: 'owner',
        actorSubject: agent.ownerSubject,
        ...(agent.organizationId ? { organizationId: agent.organizationId } : {}),
        action: 'agent.created',
        targetType: 'agent',
        targetId: agent.publicId,
      });
    });
  }

  async getAgent(publicId: string): Promise<AgentRecord | null> {
    const rows = await this.db.select({
      id: agents.id,
      publicId: agents.publicId,
      organizationId: agents.organizationId,
      referrerAgentId: agents.referrerAgentId,
      referralCode: agents.referralCode,
      verificationLevel: agents.verificationLevel,
      status: agents.status,
      controlVerifiedAt: agents.controlVerifiedAt,
      version: agents.version,
      ownerSubject: users.externalSubject,
      publicKeyPem: agentKeys.publicKeyPem,
      endpoint: agentEndpoints.url,
    })
      .from(agents)
      .innerJoin(users, eq(users.id, agents.ownerUserId))
      .innerJoin(agentKeys, and(eq(agentKeys.agentId, agents.id), isNull(agentKeys.revokedAt)))
      .innerJoin(agentEndpoints, and(eq(agentEndpoints.agentId, agents.id), isNull(agentEndpoints.disabledAt)))
      .where(and(eq(agents.publicId, publicId), isNull(agents.deletedAt)))
      .limit(1);
    const row = rows[0];
    if (!row) return null;
    const capabilities = await this.db.select({ capability: agentCapabilities.capability })
      .from(agentCapabilities)
      .where(eq(agentCapabilities.agentId, row.id));
    return {
      id: row.id,
      publicId: row.publicId,
      ownerSubject: row.ownerSubject,
      publicKeyPem: row.publicKeyPem,
      endpoint: row.endpoint,
      capabilities: capabilities.map((item) => item.capability),
      verificationLevel: row.verificationLevel as 0 | 1 | 2 | 3,
      status: row.status,
      referralCode: row.referralCode,
      version: row.version,
      ...(row.organizationId ? { organizationId: row.organizationId } : {}),
      ...(row.referrerAgentId ? { referrerAgentId: row.referrerAgentId } : {}),
      ...(row.controlVerifiedAt ? { controlVerifiedAt: row.controlVerifiedAt.toISOString() } : {}),
    };
  }

  async getAgentByReferralCode(referralCode: string): Promise<AgentRecord | null> {
    const row = await this.db.select({ publicId: agents.publicId }).from(agents)
      .where(and(eq(agents.referralCode, referralCode), isNull(agents.deletedAt)))
      .limit(1);
    return row[0] ? this.getAgent(row[0].publicId) : null;
  }

  async createChallenge(input: ChallengeRecordInput): Promise<void> {
    await this.db.insert(agentChallenges).values({
      id: uuidv7(),
      agentId: input.agentId,
      digest: input.digest,
      expiresAt: input.expiresAt,
    });
  }

  async confirmAgentControl(agent: AgentRecord, digest: string, verifiedAt: Date): Promise<boolean> {
    return this.db.transaction(async (tx) => {
      const challenge = await tx.select({ id: agentChallenges.id })
        .from(agentChallenges)
        .where(and(
          eq(agentChallenges.agentId, agent.id),
          eq(agentChallenges.digest, digest),
          isNull(agentChallenges.consumedAt),
          gt(agentChallenges.expiresAt, verifiedAt),
        ))
        .limit(1);
      if (!challenge[0]) return false;
      const consumed = await tx.update(agentChallenges)
        .set({ consumedAt: verifiedAt })
        .where(and(eq(agentChallenges.id, challenge[0].id), isNull(agentChallenges.consumedAt)))
        .returning({ id: agentChallenges.id });
      if (!consumed[0]) return false;
      await tx.update(agents)
        .set({ verificationLevel: 1, controlVerifiedAt: verifiedAt, version: agent.version + 1, updatedAt: verifiedAt })
        .where(eq(agents.id, agent.id));
      await tx.update(agentEndpoints).set({ verifiedAt }).where(eq(agentEndpoints.agentId, agent.id));
      await tx.insert(auditEvents).values({
        id: uuidv7(),
        actorType: 'agent',
        actorSubject: agent.publicId,
        action: 'agent.control_verified',
        targetType: 'agent',
        targetId: agent.publicId,
      });
      return true;
    });
  }

  private async ensureLedgerAccount(tx: Database, code: LedgerAccount, scopeType: 'platform' | 'agent', scopeId: string): Promise<string> {
    const existing = await tx.select({ id: ledgerAccounts.id }).from(ledgerAccounts).where(and(eq(ledgerAccounts.code, code), eq(ledgerAccounts.scopeType, scopeType), eq(ledgerAccounts.scopeId, scopeId))).limit(1);
    if (existing[0]) return existing[0].id;
    const id = uuidv7();
    await tx.insert(ledgerAccounts).values({ id, code, accountType: accountTypeFor(code), scopeType, scopeId }).onConflictDoNothing({ target: [ledgerAccounts.code, ledgerAccounts.scopeType, ledgerAccounts.scopeId] });
    const resolved = await tx.select({ id: ledgerAccounts.id }).from(ledgerAccounts).where(and(eq(ledgerAccounts.code, code), eq(ledgerAccounts.scopeType, scopeType), eq(ledgerAccounts.scopeId, scopeId))).limit(1);
    if (!resolved[0]) throw new Error(`failed to resolve ledger account ${code}`);
    return resolved[0].id;
  }

  async finalizePassportPurchase(input: FinalizePurchaseInput): Promise<{ duplicate: boolean }> {
    assertBalancedEntries(input.ledgerEntries);
    return this.db.transaction(async (tx) => {
      const receivedAt = new Date();
      const webhookRow = await tx.insert(webhookEvents).values({
        id: uuidv7(),
        provider: input.provider,
        providerEventId: input.eventId,
        payloadHash: input.payloadHash,
        processingStatus: 'processing',
        receivedAt,
      }).onConflictDoNothing({ target: [webhookEvents.provider, webhookEvents.providerEventId] }).returning({ id: webhookEvents.id });
      if (!webhookRow[0]) return { duplicate: true };

      const existingPurchase = await tx.select({ id: purchases.id }).from(purchases).where(eq(purchases.externalReference, input.purchaseId)).limit(1);
      if (existingPurchase[0]) {
        await tx.update(webhookEvents).set({ processingStatus: 'duplicate', processedAt: receivedAt }).where(eq(webhookEvents.id, webhookRow[0].id));
        return { duplicate: true };
      }

      const currentAgent = await tx.select({ verificationLevel: agents.verificationLevel, controlVerifiedAt: agents.controlVerifiedAt })
        .from(agents).where(eq(agents.id, input.agent.id)).limit(1);
      if (!currentAgent[0] || currentAgent[0].verificationLevel < 1 || !currentAgent[0].controlVerifiedAt) {
        throw new Error('agent control is not verified');
      }

      const paymentEventId = uuidv7();
      await tx.insert(paymentEvents).values({
        id: paymentEventId,
        provider: input.provider,
        providerEventId: input.eventId,
        eventType: input.eventType,
        payloadHash: input.payloadHash,
        receivedAt,
        processedAt: receivedAt,
      });
      const purchaseInternalId = uuidv7();
      await tx.insert(purchases).values({
        id: purchaseInternalId,
        externalReference: input.purchaseId,
        agentId: input.agent.id,
        paymentEventId,
        amountMinor: input.priceMinor,
        currency: 'USD',
        status: 'paid',
      });
      const passportInternalId = uuidv7();
      await tx.insert(agentPassports).values({
        id: passportInternalId,
        passportId: input.passport.claims.passport_id,
        agentId: input.agent.id,
        schemaVersion: input.passport.claims.schema_version,
        claims: input.passport.claims,
        signature: input.passport.signature,
        status: input.passport.status,
        issuedAt: new Date(input.passport.claims.issued_at),
        expiresAt: new Date(input.passport.claims.expires_at),
      });
      await tx.insert(passportStatusHistory).values({
        id: uuidv7(),
        passportId: passportInternalId,
        toStatus: 'active',
        reasonCode: 'issued_after_payment',
      });

      const ledgerTxId = uuidv7();
      await tx.insert(ledgerTransactions).values({
        id: ledgerTxId,
        idempotencyKey: `purchase:${input.purchaseId}`,
        externalReference: input.purchaseId,
        transactionType: 'passport_sale',
      });
      for (const entry of input.ledgerEntries) {
        const accountId = await this.ensureLedgerAccount(tx as Database, entry.account, entry.scopeType, entry.scopeId);
        await tx.insert(ledgerEntries).values({
          id: uuidv7(),
          transactionId: ledgerTxId,
          accountId,
          amountMinor: entry.amountMinor,
          currency: entry.currency,
        });
      }
      await tx.update(ledgerTransactions).set({ sealedAt: receivedAt }).where(eq(ledgerTransactions.id, ledgerTxId));
      if (input.agent.referrerAgentId && input.referralCommissionMinor > 0n) {
        await tx.insert(commissions).values({
          id: uuidv7(),
          purchaseId: purchaseInternalId,
          referrerAgentId: input.agent.referrerAgentId,
          amountMinor: input.referralCommissionMinor,
          currency: 'USD',
          status: 'pending',
          holdUntil: input.holdUntil,
        });
        await tx.update(referrals).set({ lockedAt: receivedAt }).where(eq(referrals.referredAgentId, input.agent.id));
      }
      await tx.update(agents).set({ status: 'active', updatedAt: receivedAt, version: input.agent.version + 1 }).where(eq(agents.id, input.agent.id));
      await tx.update(webhookEvents).set({ processingStatus: 'processed', processedAt: receivedAt }).where(eq(webhookEvents.id, webhookRow[0].id));
      await tx.insert(auditEvents).values({
        id: uuidv7(),
        actorType: 'system',
        action: 'passport.issued_after_payment',
        targetType: 'passport',
        targetId: input.passport.claims.passport_id,
        metadata: { purchase_id: input.purchaseId, provider: input.provider },
      });
      return { duplicate: false };
    });
  }

  async getPassport(passportId: string): Promise<SignedPassport | null> {
    const rows = await this.db.select({
      claims: agentPassports.claims,
      signature: agentPassports.signature,
      status: agentPassports.status,
    }).from(agentPassports).where(eq(agentPassports.passportId, passportId)).limit(1);
    const row = rows[0];
    if (!row) return null;
    return { claims: row.claims as AgentPassportClaims, signature: row.signature, status: row.status };
  }

  async revokePassport(passportId: string, reason: string, actorSubject: string): Promise<boolean> {
    return this.db.transaction(async (tx) => {
      const rows = await tx.select({ id: agentPassports.id, status: agentPassports.status })
        .from(agentPassports).where(eq(agentPassports.passportId, passportId)).limit(1);
      const passport = rows[0];
      if (!passport) return false;
      if (passport.status === 'revoked') return true;
      await tx.update(agentPassports).set({ status: 'revoked' }).where(eq(agentPassports.id, passport.id));
      await tx.insert(passportStatusHistory).values({
        id: uuidv7(),
        passportId: passport.id,
        fromStatus: passport.status,
        toStatus: 'revoked',
        reasonCode: reason,
        actorSubject,
      });
      await tx.insert(auditEvents).values({
        id: uuidv7(),
        actorType: 'owner',
        actorSubject,
        action: 'passport.revoked',
        targetType: 'passport',
        targetId: passportId,
        reasonCode: reason,
      });
      return true;
    });
  }

  async close(): Promise<void> {
    await this.client.end();
  }
}

function accountTypeFor(account: LedgerAccount): string {
  if (account === 'platform_cash' || account === 'payment_provider_clearing') return 'asset';
  if (account === 'referral_commission_payable' || account === 'agent_owner_available_balance' || account === 'agent_owner_pending_balance' || account === 'tax_payable') return 'liability';
  if (account === 'passport_revenue') return 'revenue';
  return 'expense';
}
