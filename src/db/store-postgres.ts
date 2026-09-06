import { and, eq, gt, isNull, sql as drizzleSql } from 'drizzle-orm';
import {
  assertBalancedEntries,
  commissionReleaseEntries,
  passportReversalEntries,
  type AgentPassportClaims,
  type AgentRecord,
  type CommissionStatus,
  type LedgerAccount,
  type SignedPassport,
} from '../domain.js';
import { uuidv7 } from '../crypto.js';
import type {
  ChallengeRecordInput,
  CommissionReleaseResult,
  FinalizePurchaseInput,
  PaymentSessionRecord,
  PlatformStore,
  ReversePurchaseInput,
  ReversePurchaseResult,
  WalletSnapshot,
  WalletTransactionView,
} from '../store.js';
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
  paymentSessions,
  purchases,
  referrals,
  users,
  webhookEvents,
} from './schema.js';

const MANAGE_ROLES = new Set(['owner', 'admin', 'developer']);
type DbExecutor = Pick<Database, 'select' | 'insert'>;

type RawPaymentSessionRow = {
  provider: string;
  provider_session_id: string;
  idempotency_key: string;
  purchase_reference: string;
  agent_id: string;
  agent_public_id: string;
  checkout_url: string;
  amount_minor: string;
  currency: string;
  status: string;
  expires_at: Date;
};

export class PostgresPlatformStore implements PlatformStore {
  private readonly client: ReturnType<typeof createDatabase>['client'];
  private readonly db: Database;

  constructor(databaseUrl: string) {
    const connection = createDatabase(databaseUrl);
    this.client = connection.client;
    this.db = connection.db;
  }

  private async ensureUser(tx: DbExecutor, externalSubject: string): Promise<string> {
    const existing = await tx.select({ id: users.id }).from(users).where(eq(users.externalSubject, externalSubject)).limit(1);
    if (existing[0]) return existing[0].id;
    const id = uuidv7();
    await tx.insert(users).values({ id, externalSubject }).onConflictDoNothing({ target: users.externalSubject });
    const resolved = await tx.select({ id: users.id }).from(users).where(eq(users.externalSubject, externalSubject)).limit(1);
    if (!resolved[0]) throw new Error('failed to resolve owner user');
    return resolved[0].id;
  }

  private async assertOrganizationAccess(tx: DbExecutor, userId: string, organizationId?: string): Promise<void> {
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
      const ownerUserId = await this.ensureUser(tx, agent.ownerSubject);
      await this.assertOrganizationAccess(tx, ownerUserId, agent.organizationId);
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
        const referrer = await tx.select({ referralCode: agents.referralCode })
          .from(agents)
          .where(eq(agents.id, agent.referrerAgentId))
          .limit(1);
        if (!referrer[0]) throw new Error('referrer agent not found');
        await tx.insert(referrals).values({
          id: uuidv7(),
          referredAgentId: agent.id,
          referrerAgentId: agent.referrerAgentId,
          referralCode: referrer[0].referralCode,
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

  async createPaymentSession(input: PaymentSessionRecord): Promise<PaymentSessionRecord> {
    const inserted = await this.client<RawPaymentSessionRow[]>`
      insert into payment_sessions (
        id, agent_id, provider, provider_session_id, amount_minor, currency, status,
        expires_at, idempotency_key, purchase_reference, checkout_url
      ) values (
        ${uuidv7()}, ${input.agentId}, ${input.provider}, ${input.providerSessionId}, ${input.amountMinor},
        ${input.currency}, ${input.status}, ${input.expiresAt}, ${input.idempotencyKey},
        ${input.purchaseReference}, ${input.checkoutUrl}
      )
      on conflict (provider, idempotency_key) where idempotency_key is not null do nothing
      returning provider, provider_session_id, idempotency_key, purchase_reference, agent_id,
        ${input.agentPublicId}::text as agent_public_id, checkout_url, amount_minor::text, currency, status, expires_at
    `;
    if (inserted[0]) return parsePaymentSession(inserted[0]);
    const existing = await this.client<RawPaymentSessionRow[]>`
      select ps.provider, ps.provider_session_id, ps.idempotency_key, ps.purchase_reference,
        ps.agent_id, a.public_id as agent_public_id, ps.checkout_url, ps.amount_minor::text,
        ps.currency, ps.status, ps.expires_at
      from payment_sessions ps
      join agents a on a.id = ps.agent_id
      where ps.provider = ${input.provider} and ps.idempotency_key = ${input.idempotencyKey}
      limit 1
    `;
    const row = existing[0];
    if (!row) throw new Error('checkout idempotency conflict without existing session');
    const record = parsePaymentSession(row);
    if (record.agentId !== input.agentId || record.amountMinor !== input.amountMinor || record.currency !== input.currency) {
      throw new Error('idempotency key reused with different checkout parameters');
    }
    return record;
  }

  async getPaymentSessionByPurchaseReference(purchaseReference: string): Promise<PaymentSessionRecord | null> {
    const rows = await this.client<RawPaymentSessionRow[]>`
      select ps.provider, ps.provider_session_id, ps.idempotency_key, ps.purchase_reference,
        ps.agent_id, a.public_id as agent_public_id, ps.checkout_url, ps.amount_minor::text,
        ps.currency, ps.status, ps.expires_at
      from payment_sessions ps
      join agents a on a.id = ps.agent_id
      where ps.purchase_reference = ${purchaseReference}
      limit 1
    `;
    return rows[0] ? parsePaymentSession(rows[0]) : null;
  }

  async getActivePassportForAgent(agentId: string): Promise<SignedPassport | null> {
    const rows = await this.db.select({
      claims: agentPassports.claims,
      signature: agentPassports.signature,
      status: agentPassports.status,
    }).from(agentPassports)
      .where(and(eq(agentPassports.agentId, agentId), eq(agentPassports.status, 'active'), gt(agentPassports.expiresAt, new Date())))
      .limit(1);
    const row = rows[0];
    return row ? { claims: row.claims as AgentPassportClaims, signature: row.signature, status: row.status } : null;
  }

  private async ensureLedgerAccount(tx: DbExecutor, code: LedgerAccount, scopeType: 'platform' | 'agent', scopeId: string): Promise<string> {
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
    const checkout = await this.getPaymentSessionByPurchaseReference(input.purchaseId);
    if (!checkout || checkout.provider !== input.provider || checkout.agentId !== input.agent.id || checkout.amountMinor !== input.priceMinor || checkout.currency !== 'USD') {
      throw new Error('payment event does not match a checkout session');
    }
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

      const existingPurchase = await tx.select({ id: purchases.id }).from(purchases)
        .where(eq(purchases.externalReference, input.purchaseId)).limit(1);
      if (existingPurchase[0]) {
        await tx.update(webhookEvents).set({ processingStatus: 'duplicate', processedAt: receivedAt })
          .where(eq(webhookEvents.id, webhookRow[0].id));
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
      await tx.execute(drizzleSql`update agent_passports set purchase_id = ${purchaseInternalId} where id = ${passportInternalId}`);
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
        const accountId = await this.ensureLedgerAccount(tx, entry.account, entry.scopeType, entry.scopeId);
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
      await tx.update(paymentSessions).set({ status: 'paid' }).where(eq(paymentSessions.providerSessionId, checkout.providerSessionId));
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

  async reversePassportPurchase(input: ReversePurchaseInput): Promise<ReversePurchaseResult> {
    return this.client.begin(async (tx) => {
      const webhook = await tx<{ id: string }[]>`
        insert into webhook_events (id, provider, provider_event_id, payload_hash, processing_status, received_at)
        values (${uuidv7()}, ${input.provider}, ${input.eventId}, ${input.payloadHash}, 'processing', ${input.occurredAt})
        on conflict (provider, provider_event_id) do nothing
        returning id
      `;
      if (!webhook[0]) return { duplicate: true, found: true, commissionReversed: false };

      type PurchaseRow = {
        purchase_internal_id: string;
        agent_id: string;
        amount_minor: string;
        currency: string;
        purchase_status: string;
        passport_internal_id: string | null;
        passport_id: string | null;
        passport_status: string | null;
        referrer_agent_id: string | null;
        commission_id: string | null;
        commission_amount_minor: string | null;
        commission_status: CommissionStatus | null;
      };
      const rows = await tx<PurchaseRow[]>`
        select p.id as purchase_internal_id, p.agent_id, p.amount_minor::text, p.currency,
          p.status as purchase_status, ap.id as passport_internal_id, ap.passport_id,
          ap.status::text as passport_status, a.referrer_agent_id,
          c.id as commission_id, c.amount_minor::text as commission_amount_minor,
          c.status::text as commission_status
        from purchases p
        join agents a on a.id = p.agent_id
        left join agent_passports ap on ap.purchase_id = p.id
        left join commissions c on c.purchase_id = p.id
        where p.external_reference = ${input.purchaseId}
        for update of p
      `;
      const purchase = rows[0];
      if (!purchase) {
        await tx`update webhook_events set processing_status = 'ignored_not_found', processed_at = ${input.occurredAt} where id = ${webhook[0].id}`;
        return { duplicate: false, found: false, commissionReversed: false };
      }
      if (purchase.purchase_status !== 'paid') {
        await tx`update webhook_events set processing_status = 'duplicate', processed_at = ${input.occurredAt} where id = ${webhook[0].id}`;
        return {
          duplicate: true,
          found: true,
          ...(purchase.passport_id ? { passportId: purchase.passport_id } : {}),
          commissionReversed: false,
        };
      }

      const priceMinor = BigInt(purchase.amount_minor);
      const commissionAmountMinor = purchase.commission_amount_minor ? BigInt(purchase.commission_amount_minor) : 0n;
      const entries = passportReversalEntries({
        kind: input.kind,
        priceMinor,
        referralCommissionMinor: commissionAmountMinor,
        ...(purchase.referrer_agent_id ? { referrerAgentId: purchase.referrer_agent_id } : {}),
        ...(purchase.commission_status ? { commissionStatus: purchase.commission_status } : {}),
      });

      const paymentEventId = uuidv7();
      await tx`
        insert into payment_events (id, provider, provider_event_id, event_type, payload_hash, received_at, processed_at)
        values (${paymentEventId}, ${input.provider}, ${input.eventId}, ${input.eventType}, ${input.payloadHash}, ${input.occurredAt}, ${input.occurredAt})
      `;
      if (input.kind === 'refund') {
        await tx`
          insert into refunds (id, purchase_id, provider_refund_id, amount_minor, currency, status, provider, provider_event_id, reason_code, created_at)
          values (${uuidv7()}, ${purchase.purchase_internal_id}, ${input.eventId}, ${priceMinor}, ${purchase.currency}, 'succeeded', ${input.provider}, ${input.eventId}, ${input.reasonCode}, ${input.occurredAt})
        `;
      } else {
        await tx`
          insert into disputes (id, purchase_id, provider_dispute_id, amount_minor, currency, status, provider, provider_event_id, reason_code, created_at)
          values (${uuidv7()}, ${purchase.purchase_internal_id}, ${input.eventId}, ${priceMinor}, ${purchase.currency}, 'lost', ${input.provider}, ${input.eventId}, ${input.reasonCode}, ${input.occurredAt})
        `;
      }

      const ledgerTxId = uuidv7();
      await tx`
        insert into ledger_transactions (id, idempotency_key, external_reference, transaction_type)
        values (${ledgerTxId}, ${`${input.kind}:${input.purchaseId}`}, ${input.purchaseId}, ${input.kind === 'refund' ? 'passport_refund' : 'passport_chargeback'})
      `;
      for (const entry of entries) {
        const accountId = await ensureRawLedgerAccount(tx, entry.account, entry.scopeType, entry.scopeId);
        await tx`
          insert into ledger_entries (id, transaction_id, account_id, amount_minor, currency)
          values (${uuidv7()}, ${ledgerTxId}, ${accountId}, ${entry.amountMinor}, ${entry.currency})
        `;
      }
      await tx`update ledger_transactions set sealed_at = ${input.occurredAt} where id = ${ledgerTxId}`;
      await tx`update purchases set status = ${input.kind === 'refund' ? 'refunded' : 'chargeback'} where id = ${purchase.purchase_internal_id}`;

      if (purchase.passport_internal_id && purchase.passport_status !== 'revoked') {
        await tx`update agent_passports set status = 'revoked' where id = ${purchase.passport_internal_id}`;
        await tx`
          insert into passport_status_history (id, passport_id, from_status, to_status, reason_code, actor_subject, created_at)
          values (${uuidv7()}, ${purchase.passport_internal_id}, ${purchase.passport_status}, 'revoked', ${input.kind === 'refund' ? 'payment_refunded' : 'payment_chargeback'}, 'payment-provider', ${input.occurredAt})
        `;
      }
      let commissionReversed = false;
      if (purchase.commission_id && purchase.commission_status !== 'reversed') {
        await tx`
          update commissions set status = 'reversed', reversed_at = ${input.occurredAt},
            reversal_reason = ${input.reasonCode}, updated_at = ${input.occurredAt}
          where id = ${purchase.commission_id}
        `;
        commissionReversed = true;
      }
      await tx`update webhook_events set processing_status = 'processed', processed_at = ${input.occurredAt} where id = ${webhook[0].id}`;
      await tx`
        insert into audit_events (id, actor_type, actor_subject, action, target_type, target_id, reason_code, metadata, occurred_at)
        values (${uuidv7()}, 'payment-provider', ${input.provider}, ${input.kind === 'refund' ? 'purchase.refunded' : 'purchase.chargeback'}, 'purchase', ${input.purchaseId}, ${input.reasonCode}, ${tx.json({ event_id: input.eventId })}, ${input.occurredAt})
      `;
      return {
        duplicate: false,
        found: true,
        ...(purchase.passport_id ? { passportId: purchase.passport_id } : {}),
        commissionReversed,
      };
    });
  }

  async releaseEligibleCommissions(now: Date, limit: number): Promise<CommissionReleaseResult> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new Error('release limit out of range');
    return this.client.begin(async (tx) => {
      type CommissionRow = { id: string; purchase_id: string; referrer_agent_id: string; amount_minor: string };
      const eligible = await tx<CommissionRow[]>`
        select id, purchase_id, referrer_agent_id, amount_minor::text
        from commissions
        where status = 'pending' and hold_until <= ${now}
        order by hold_until asc, id asc
        for update skip locked
        limit ${limit}
      `;
      let amountMinor = 0n;
      for (const commission of eligible) {
        const amount = BigInt(commission.amount_minor);
        const entries = commissionReleaseEntries(amount, commission.referrer_agent_id);
        const ledgerTxId = uuidv7();
        await tx`
          insert into ledger_transactions (id, idempotency_key, external_reference, transaction_type)
          values (${ledgerTxId}, ${`commission_release:${commission.id}`}, ${commission.purchase_id}, 'commission_release')
        `;
        for (const entry of entries) {
          const accountId = await ensureRawLedgerAccount(tx, entry.account, entry.scopeType, entry.scopeId);
          await tx`
            insert into ledger_entries (id, transaction_id, account_id, amount_minor, currency)
            values (${uuidv7()}, ${ledgerTxId}, ${accountId}, ${entry.amountMinor}, ${entry.currency})
          `;
        }
        await tx`update ledger_transactions set sealed_at = ${now} where id = ${ledgerTxId}`;
        await tx`update commissions set status = 'available', released_at = ${now}, updated_at = ${now} where id = ${commission.id} and status = 'pending'`;
        await tx`
          insert into audit_events (id, actor_type, action, target_type, target_id, reason_code, occurred_at)
          values (${uuidv7()}, 'system', 'commission.released', 'commission', ${commission.id}, 'hold_period_completed', ${now})
        `;
        amountMinor += amount;
      }
      return { released: eligible.length, amountMinor };
    });
  }

  async getWallet(agentId: string, minPayoutMinor: bigint): Promise<WalletSnapshot> {
    type BalanceRow = { code: string; total: string };
    const balances = await this.client<BalanceRow[]>`
      select la.code, coalesce(sum(le.amount_minor), 0)::text as total
      from ledger_accounts la
      join ledger_entries le on le.account_id = la.id
      join ledger_transactions lt on lt.id = le.transaction_id and lt.sealed_at is not null
      where la.scope_type = 'agent' and la.scope_id = ${agentId}
        and la.code in ('agent_owner_pending_balance', 'agent_owner_available_balance')
      group by la.code
    `;
    const byCode = new Map(balances.map((row) => [row.code, BigInt(row.total)]));
    const pendingSigned = byCode.get('agent_owner_pending_balance') ?? 0n;
    const availableSigned = byCode.get('agent_owner_available_balance') ?? 0n;
    type CommissionAggregate = { paid: string; reversed: string };
    const aggregate = await this.client<CommissionAggregate[]>`
      select
        coalesce(sum(amount_minor) filter (where status = 'paid'), 0)::text as paid,
        coalesce(sum(amount_minor) filter (where status = 'reversed'), 0)::text as reversed
      from commissions where referrer_agent_id = ${agentId}
    `;
    const paidMinor = BigInt(aggregate[0]?.paid ?? '0');
    const reversedMinor = BigInt(aggregate[0]?.reversed ?? '0');
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
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('wallet transaction limit out of range');
    type TransactionRow = {
      transaction_id: string;
      transaction_type: string;
      external_reference: string;
      created_at: Date;
      account: string;
      amount_minor: string;
      currency: 'USD';
    };
    const rows = await this.client<TransactionRow[]>`
      select lt.id as transaction_id, lt.transaction_type, lt.external_reference, lt.created_at,
        la.code as account, le.amount_minor::text, le.currency
      from ledger_entries le
      join ledger_transactions lt on lt.id = le.transaction_id and lt.sealed_at is not null
      join ledger_accounts la on la.id = le.account_id
      where la.scope_type = 'agent' and la.scope_id = ${agentId}
      order by lt.created_at desc, lt.id desc, le.id desc
      limit ${limit}
    `;
    return rows.map((row) => ({
      transactionId: row.transaction_id,
      transactionType: row.transaction_type,
      externalReference: row.external_reference,
      createdAt: row.created_at.toISOString(),
      account: row.account,
      amountMinor: BigInt(row.amount_minor),
      currency: row.currency,
    }));
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

function parsePaymentSession(row: RawPaymentSessionRow): PaymentSessionRecord {
  if (row.currency !== 'USD') throw new Error(`unsupported checkout currency ${row.currency}`);
  if (!['pending', 'paid', 'expired', 'cancelled'].includes(row.status)) throw new Error(`unsupported checkout status ${row.status}`);
  return {
    provider: row.provider,
    providerSessionId: row.provider_session_id,
    idempotencyKey: row.idempotency_key,
    purchaseReference: row.purchase_reference,
    agentId: row.agent_id,
    agentPublicId: row.agent_public_id,
    checkoutUrl: row.checkout_url,
    amountMinor: BigInt(row.amount_minor),
    currency: 'USD',
    status: row.status as PaymentSessionRecord['status'],
    expiresAt: row.expires_at,
  };
}

function accountTypeFor(account: LedgerAccount): string {
  if (account === 'platform_cash' || account === 'payment_provider_clearing') return 'asset';
  if (account === 'referral_commission_payable' || account === 'agent_owner_available_balance' || account === 'agent_owner_pending_balance' || account === 'tax_payable') return 'liability';
  if (account === 'passport_revenue') return 'revenue';
  return 'expense';
}

async function ensureRawLedgerAccount(
  tx: Parameters<Parameters<ReturnType<typeof createDatabase>['client']['begin']>[0]>[0],
  code: LedgerAccount,
  scopeType: 'platform' | 'agent',
  scopeId: string,
): Promise<string> {
  const id = uuidv7();
  await tx`
    insert into ledger_accounts (id, code, account_type, scope_type, scope_id)
    values (${id}, ${code}, ${accountTypeFor(code)}, ${scopeType}, ${scopeId})
    on conflict (code, scope_type, scope_id) do nothing
  `;
  const rows = await tx<{ id: string }[]>`
    select id from ledger_accounts where code = ${code} and scope_type = ${scopeType} and scope_id = ${scopeId} limit 1
  `;
  if (!rows[0]) throw new Error(`failed to resolve ledger account ${code}`);
  return rows[0].id;
}
