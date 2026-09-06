import postgres, { type TransactionSql } from 'postgres';
import { uuidv7 } from '../crypto.js';
import {
  assertBalancedEntries,
  payoutReleaseEntries,
  payoutReservationEntries,
  payoutSettlementEntries,
  type AgentRecord,
  type LedgerAccount,
  type LedgerEntry,
} from '../domain.js';
import type { PayoutOnboardingSession, ProviderPayout } from './provider.js';
import type { PayoutRiskAssessment } from './risk.js';
import type {
  PayoutAccountRecord,
  PayoutEventResult,
  PayoutProviderEventInput,
  PayoutRecord,
  PayoutRiskContextRecord,
  PayoutStore,
  PayoutSummary,
  ReservePayoutInput,
} from './store.js';

type PayoutRow = {
  id: string;
  payout_reference: string;
  agent_id: string;
  payout_account_id: string;
  provider: string;
  provider_payout_id: string | null;
  amount_minor: string;
  currency: string;
  status: PayoutRecord['status'];
  idempotency_key: string;
  risk_decision: PayoutRiskAssessment['decision'] | null;
  risk_score: number | null;
  reserved_at: Date | null;
  submitted_at: Date | null;
  processed_at: Date | null;
  failure_reason: string | null;
  created_at: Date;
};

type PayoutAccountRow = {
  id: string;
  provider: string;
  provider_account_id: string;
  onboarding_status: string;
  onboarding_url: string | null;
  onboarding_expires_at: Date | null;
  owner_subject: string | null;
  organization_id: string | null;
};

export class PostgresPayoutStore implements PayoutStore {
  private readonly sql: ReturnType<typeof postgres>;

  constructor(databaseUrl: string) {
    this.sql = postgres(databaseUrl, {
      max: 6,
      idle_timeout: 20,
      connect_timeout: 10,
      prepare: false,
    });
  }

  async upsertPayoutAccount(agent: AgentRecord, session: PayoutOnboardingSession, now: Date): Promise<PayoutAccountRecord> {
    return this.sql.begin(async (tx) => {
      const identity = await resolveBeneficiary(tx, agent);
      const existing = await findPayoutAccount(tx, identity.ownerUserId, identity.organizationId, session.provider, true);
      const id = existing?.id ?? uuidv7();
      if (existing) {
        await tx`
          update payout_accounts
          set provider_account_id = ${session.providerAccountId}, onboarding_status = ${session.status},
              onboarding_url = ${session.onboardingUrl}, onboarding_expires_at = ${session.expiresAt}, updated_at = ${now}
          where id = ${id}
        `;
      } else {
        await tx`
          insert into payout_accounts (
            id, owner_user_id, organization_id, provider, provider_account_id, onboarding_status,
            onboarding_url, onboarding_expires_at, created_at, updated_at
          ) values (
            ${id}, ${identity.ownerUserId}, ${identity.organizationId}, ${session.provider}, ${session.providerAccountId},
            ${session.status}, ${session.onboardingUrl}, ${session.expiresAt}, ${now}, ${now}
          )
        `;
      }
      await tx`
        insert into audit_events (id, actor_type, actor_subject, action, target_type, target_id, metadata, occurred_at)
        values (
          ${uuidv7()}, 'owner', ${agent.ownerSubject}, 'payout_account.onboarding_updated', 'payout_account', ${id},
          ${tx.json({ provider: session.provider, onboarding_status: session.status, agent_id: agent.publicId })}, ${now}
        )
      `;
      return {
        id,
        provider: session.provider,
        providerAccountId: session.providerAccountId,
        onboardingStatus: session.status,
        onboardingUrl: session.onboardingUrl,
        onboardingExpiresAt: session.expiresAt,
        ...(agent.organizationId ? { organizationId: agent.organizationId } : { ownerSubject: agent.ownerSubject }),
      };
    });
  }

  async getPayoutAccount(agent: AgentRecord, provider: string): Promise<PayoutAccountRecord | null> {
    const rows = await this.sql<PayoutAccountRow[]>`
      select pa.id, pa.provider, pa.provider_account_id, pa.onboarding_status, pa.onboarding_url,
        pa.onboarding_expires_at, u.external_subject as owner_subject, pa.organization_id
      from payout_accounts pa
      left join users u on u.id = pa.owner_user_id
      where pa.provider = ${provider}
        and (
          (${agent.organizationId ?? null}::uuid is not null and pa.organization_id = ${agent.organizationId ?? null})
          or (${agent.organizationId ?? null}::uuid is null and u.external_subject = ${agent.ownerSubject})
        )
      limit 1
    `;
    return rows[0] ? parsePayoutAccount(rows[0]) : null;
  }

  async getRiskContext(agentId: string, now: Date): Promise<PayoutRiskContextRecord> {
    type BalanceRow = { total: string };
    const balance = await this.sql<BalanceRow[]>`
      select coalesce(sum(le.amount_minor), 0)::text as total
      from ledger_accounts la
      join ledger_entries le on le.account_id = la.id
      join ledger_transactions lt on lt.id = le.transaction_id and lt.sealed_at is not null
      where la.scope_type = 'agent' and la.scope_id = ${agentId}
        and la.code = 'agent_owner_available_balance'
    `;
    const signed = BigInt(balance[0]?.total ?? '0');
    const availableMinor = signed < 0n ? -signed : 0n;
    const debtMinor = signed > 0n ? signed : 0n;

    type CountRow = { open_count: string; count_24h: string };
    const counts = await this.sql<CountRow[]>`
      select
        count(*) filter (where status in ('pending', 'processing'))::text as open_count,
        count(*) filter (where created_at >= ${new Date(now.getTime() - 86_400_000)})::text as count_24h
      from payouts where agent_id = ${agentId}
    `;

    type ReversalRow = { total: string };
    const reversals = await this.sql<ReversalRow[]>`
      select coalesce(sum(le.amount_minor) filter (where le.amount_minor > 0), 0)::text as total
      from ledger_entries le
      join ledger_accounts la on la.id = le.account_id
      join ledger_transactions lt on lt.id = le.transaction_id and lt.sealed_at is not null
      where la.scope_type = 'agent' and la.scope_id = ${agentId}
        and la.code = 'agent_owner_available_balance'
        and lt.transaction_type in ('passport_refund', 'passport_chargeback')
        and lt.created_at >= ${new Date(now.getTime() - 30 * 86_400_000)}
    `;
    return {
      availableMinor,
      debtMinor,
      openPayoutCount: Number(counts[0]?.open_count ?? '0'),
      payoutCount24h: Number(counts[0]?.count_24h ?? '0'),
      reversalMinor30d: BigInt(reversals[0]?.total ?? '0'),
    };
  }

  async recordRiskAssessment(
    agentId: string,
    idempotencyKey: string,
    amountMinor: bigint,
    currency: 'USD',
    assessment: PayoutRiskAssessment,
    now: Date,
  ): Promise<void> {
    await this.sql`
      insert into payout_risk_assessments (
        id, agent_id, idempotency_key, amount_minor, currency, decision, score, reasons, created_at
      ) values (
        ${uuidv7()}, ${agentId}, ${idempotencyKey}, ${amountMinor.toString()}, ${currency}, ${assessment.decision},
        ${assessment.score}, ${this.sql.json(assessment.reasons)}, ${now}
      )
    `;
  }

  async reservePayout(input: ReservePayoutInput): Promise<{ duplicate: boolean; payout: PayoutRecord }> {
    if (input.assessment.decision !== 'approve') throw new Error('payout risk decision is not approved');
    return this.sql.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtext(${`credalyx:payout:${input.agent.id}`}))`;
      const existing = await tx<PayoutRow[]>`
        select ${payoutColumns()}
        from payouts where idempotency_key = ${input.idempotencyKey} limit 1
      `;
      if (existing[0]) {
        const payout = parsePayout(existing[0]);
        if (payout.agentId !== input.agent.id || payout.amountMinor !== input.amountMinor || payout.currency !== input.currency) {
          throw new Error('payout idempotency key reused with different parameters');
        }
        return { duplicate: true, payout };
      }

      const accountRows = await tx<{ onboarding_status: string }[]>`
        select onboarding_status from payout_accounts where id = ${input.payoutAccount.id} limit 1 for update
      `;
      if (accountRows[0]?.onboarding_status !== 'complete') throw new Error('payout account onboarding incomplete');

      const open = await tx<{ id: string }[]>`
        select id from payouts where agent_id = ${input.agent.id} and status in ('pending', 'processing') limit 1 for update
      `;
      if (open[0]) throw new Error('open payout already exists');

      const balance = await availableBalance(tx, input.agent.id);
      if (balance.debtMinor > 0n || balance.availableMinor < input.amountMinor) throw new Error('insufficient payout balance');

      const payoutId = uuidv7();
      await tx`
        insert into payouts (
          id, payout_account_id, agent_id, provider, payout_reference, amount_minor, currency, status,
          idempotency_key, risk_decision, risk_score, reserved_at, created_at
        ) values (
          ${payoutId}, ${input.payoutAccount.id}, ${input.agent.id}, ${input.payoutAccount.provider}, ${input.payoutReference},
          ${input.amountMinor.toString()}, ${input.currency}, 'pending', ${input.idempotencyKey},
          ${input.assessment.decision}, ${input.assessment.score}, ${input.reservedAt}, ${input.reservedAt}
        )
      `;
      await postLedger(tx, {
        idempotencyKey: `payout_reservation:${input.payoutReference}`,
        transactionType: 'payout_reservation',
        externalReference: input.payoutReference,
        entries: payoutReservationEntries(input.amountMinor, input.agent.id),
        occurredAt: input.reservedAt,
      });
      await tx`
        update payout_risk_assessments
        set payout_id = ${payoutId}
        where agent_id = ${input.agent.id} and idempotency_key = ${input.idempotencyKey} and payout_id is null
      `;
      await tx`
        insert into audit_events (id, actor_type, actor_subject, action, target_type, target_id, metadata, occurred_at)
        values (
          ${uuidv7()}, 'owner', ${input.agent.ownerSubject}, 'payout.reserved', 'payout', ${input.payoutReference},
          ${tx.json({ amount_minor: input.amountMinor.toString(), currency: input.currency, risk_score: input.assessment.score })},
          ${input.reservedAt}
        )
      `;
      return {
        duplicate: false,
        payout: {
          id: payoutId,
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
        },
      };
    });
  }

  async markSubmitted(payoutReference: string, providerPayout: ProviderPayout, submittedAt: Date): Promise<PayoutRecord> {
    return this.sql.begin(async (tx) => {
      const rows = await lockPayout(tx, payoutReference);
      const row = rows[0];
      if (!row) throw new Error('payout not found');
      const payout = parsePayout(row);
      if (providerPayout.payoutReference !== payoutReference || providerPayout.provider !== payout.provider || providerPayout.amountMinor !== payout.amountMinor || providerPayout.currency !== payout.currency) {
        throw new Error('provider payout does not match reservation');
      }
      if (payout.status === 'processing' && payout.providerPayoutId === providerPayout.providerPayoutId) return payout;
      if (payout.status !== 'pending') throw new Error('payout is not pending submission');

      if (providerPayout.status === 'processing') {
        await tx`
          update payouts set provider_payout_id = ${providerPayout.providerPayoutId}, status = 'processing', submitted_at = ${submittedAt}
          where id = ${payout.id}
        `;
      } else if (providerPayout.status === 'paid') {
        await settle(tx, payout, submittedAt);
        await tx`
          update payouts set provider_payout_id = ${providerPayout.providerPayoutId}, status = 'paid', submitted_at = ${submittedAt}, processed_at = ${submittedAt}
          where id = ${payout.id}
        `;
      } else {
        await release(tx, payout, submittedAt);
        await tx`
          update payouts set provider_payout_id = ${providerPayout.providerPayoutId}, status = 'failed', submitted_at = ${submittedAt}, processed_at = ${submittedAt}, failure_reason = 'provider_submission_failed'
          where id = ${payout.id}
        `;
      }
      const updated = await tx<PayoutRow[]>`select ${payoutColumns()} from payouts where id = ${payout.id}`;
      return parsePayout(updated[0]!);
    });
  }

  async failSubmission(payoutReference: string, reason: string, failedAt: Date): Promise<PayoutRecord> {
    return this.sql.begin(async (tx) => {
      const rows = await lockPayout(tx, payoutReference);
      const row = rows[0];
      if (!row) throw new Error('payout not found');
      const payout = parsePayout(row);
      if (payout.status === 'failed') return payout;
      if (payout.status !== 'pending') throw new Error('only pending payout can fail before submission');
      await release(tx, payout, failedAt);
      await tx`
        update payouts set status = 'failed', failure_reason = ${reason}, processed_at = ${failedAt}
        where id = ${payout.id}
      `;
      const updated = await tx<PayoutRow[]>`select ${payoutColumns()} from payouts where id = ${payout.id}`;
      return parsePayout(updated[0]!);
    });
  }

  async applyProviderEvent(input: PayoutProviderEventInput): Promise<PayoutEventResult> {
    return this.sql.begin(async (tx) => {
      const eventRows = await tx<{ id: string }[]>`
        insert into payout_events (
          id, provider, provider_event_id, event_type, payload_hash, processing_status, received_at
        ) values (
          ${uuidv7()}, ${input.provider}, ${input.eventId}, ${input.eventType}, ${input.payloadHash}, 'processing', ${input.occurredAt}
        ) on conflict (provider, provider_event_id) do nothing returning id
      `;
      if (!eventRows[0]) {
        const existing = await tx<PayoutRow[]>`select ${payoutColumns()} from payouts where payout_reference = ${input.payoutReference} limit 1`;
        return { duplicate: true, found: Boolean(existing[0]), ...(existing[0] ? { status: existing[0].status } : {}) };
      }
      const eventId = eventRows[0].id;
      const rows = await lockPayout(tx, input.payoutReference);
      const row = rows[0];
      if (!row) {
        await tx`update payout_events set processing_status = 'ignored_not_found', processed_at = ${input.occurredAt} where id = ${eventId}`;
        return { duplicate: false, found: false };
      }
      const payout = parsePayout(row);
      if (payout.provider !== input.provider || payout.providerPayoutId !== input.providerPayoutId || payout.amountMinor !== input.amountMinor || payout.currency !== input.currency) {
        throw new Error('payout provider event mismatch');
      }
      await tx`update payout_events set payout_id = ${payout.id} where id = ${eventId}`;
      if (['paid', 'failed', 'cancelled'].includes(payout.status)) {
        await tx`update payout_events set processing_status = 'duplicate', processed_at = ${input.occurredAt} where id = ${eventId}`;
        return { duplicate: true, found: true, status: payout.status };
      }

      if (input.eventType === 'payout.paid') {
        await settle(tx, payout, input.occurredAt);
        await tx`update payouts set status = 'paid', processed_at = ${input.occurredAt} where id = ${payout.id}`;
      } else {
        await release(tx, payout, input.occurredAt);
        await tx`
          update payouts set status = 'failed', processed_at = ${input.occurredAt}, failure_reason = ${input.failureReason ?? 'provider_failed'}
          where id = ${payout.id}
        `;
      }
      await tx`update payout_events set processing_status = 'processed', processed_at = ${input.occurredAt} where id = ${eventId}`;
      await tx`
        insert into audit_events (id, actor_type, actor_subject, action, target_type, target_id, reason_code, metadata, occurred_at)
        values (
          ${uuidv7()}, 'payout-provider', ${input.provider}, ${input.eventType}, 'payout', ${input.payoutReference},
          ${input.failureReason ?? null}, ${tx.json({ provider_event_id: input.eventId, provider_payout_id: input.providerPayoutId })}, ${input.occurredAt}
        )
      `;
      return { duplicate: false, found: true, status: input.eventType === 'payout.paid' ? 'paid' : 'failed' };
    });
  }

  async getPayout(payoutReference: string): Promise<PayoutRecord | null> {
    const rows = await this.sql<PayoutRow[]>`select ${payoutColumns()} from payouts where payout_reference = ${payoutReference} limit 1`;
    return rows[0] ? parsePayout(rows[0]) : null;
  }

  async listPayouts(agentId: string, limit: number): Promise<PayoutRecord[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('payout list limit out of range');
    const rows = await this.sql<PayoutRow[]>`
      select ${payoutColumns()} from payouts where agent_id = ${agentId}
      order by created_at desc, id desc limit ${limit}
    `;
    return rows.map(parsePayout);
  }

  async getPayoutSummary(agentId: string): Promise<PayoutSummary> {
    type ReservedRow = { total: string };
    const reserved = await this.sql<ReservedRow[]>`
      select coalesce(sum(le.amount_minor), 0)::text as total
      from ledger_accounts la
      join ledger_entries le on le.account_id = la.id
      join ledger_transactions lt on lt.id = le.transaction_id and lt.sealed_at is not null
      where la.scope_type = 'agent' and la.scope_id = ${agentId} and la.code = 'agent_owner_reserved_balance'
    `;
    type PayoutAggregate = { paid: string; open_count: string };
    const aggregate = await this.sql<PayoutAggregate[]>`
      select
        coalesce(sum(amount_minor) filter (where status = 'paid'), 0)::text as paid,
        count(*) filter (where status in ('pending', 'processing'))::text as open_count
      from payouts where agent_id = ${agentId}
    `;
    const reservedSigned = BigInt(reserved[0]?.total ?? '0');
    return {
      reservedMinor: reservedSigned < 0n ? -reservedSigned : 0n,
      paidMinor: BigInt(aggregate[0]?.paid ?? '0'),
      openPayoutCount: Number(aggregate[0]?.open_count ?? '0'),
    };
  }

  async close(): Promise<void> {
    await this.sql.end();
  }
}

async function resolveBeneficiary(tx: TransactionSql<{}>, agent: AgentRecord): Promise<{ ownerUserId: string | null; organizationId: string | null }> {
  if (agent.organizationId) return { ownerUserId: null, organizationId: agent.organizationId };
  const users = await tx<{ id: string }[]>`select id from users where external_subject = ${agent.ownerSubject} and deleted_at is null limit 1`;
  if (!users[0]) throw new Error('payout beneficiary owner not found');
  return { ownerUserId: users[0].id, organizationId: null };
}

async function findPayoutAccount(
  tx: TransactionSql<{}>,
  ownerUserId: string | null,
  organizationId: string | null,
  provider: string,
  lock: boolean,
): Promise<{ id: string } | null> {
  const rows = lock
    ? await tx<{ id: string }[]>`
        select id from payout_accounts
        where provider = ${provider}
          and ((${ownerUserId}::uuid is not null and owner_user_id = ${ownerUserId}) or (${organizationId}::uuid is not null and organization_id = ${organizationId}))
        limit 1 for update
      `
    : await tx<{ id: string }[]>`
        select id from payout_accounts
        where provider = ${provider}
          and ((${ownerUserId}::uuid is not null and owner_user_id = ${ownerUserId}) or (${organizationId}::uuid is not null and organization_id = ${organizationId}))
        limit 1
      `;
  return rows[0] ?? null;
}

async function availableBalance(tx: TransactionSql<{}>, agentId: string): Promise<{ availableMinor: bigint; debtMinor: bigint }> {
  const rows = await tx<{ total: string }[]>`
    select coalesce(sum(le.amount_minor), 0)::text as total
    from ledger_accounts la
    join ledger_entries le on le.account_id = la.id
    join ledger_transactions lt on lt.id = le.transaction_id and lt.sealed_at is not null
    where la.scope_type = 'agent' and la.scope_id = ${agentId} and la.code = 'agent_owner_available_balance'
  `;
  const signed = BigInt(rows[0]?.total ?? '0');
  return {
    availableMinor: signed < 0n ? -signed : 0n,
    debtMinor: signed > 0n ? signed : 0n,
  };
}

async function lockPayout(tx: TransactionSql<{}>, payoutReference: string): Promise<PayoutRow[]> {
  return tx<PayoutRow[]>`
    select ${payoutColumns()} from payouts where payout_reference = ${payoutReference} limit 1 for update
  `;
}

function payoutColumns() {
  return postgres`
    id, payout_reference, agent_id, payout_account_id, provider, provider_payout_id,
    amount_minor::text, currency, status, idempotency_key, risk_decision, risk_score,
    reserved_at, submitted_at, processed_at, failure_reason, created_at
  `;
}

function parsePayout(row: PayoutRow): PayoutRecord {
  if (row.currency !== 'USD') throw new Error(`unsupported payout currency ${row.currency}`);
  if (!row.payout_reference || !row.agent_id || !row.provider || !row.reserved_at) throw new Error('payout row missing lifecycle fields');
  return {
    id: row.id,
    payoutReference: row.payout_reference,
    agentId: row.agent_id,
    payoutAccountId: row.payout_account_id,
    provider: row.provider,
    ...(row.provider_payout_id ? { providerPayoutId: row.provider_payout_id } : {}),
    amountMinor: BigInt(row.amount_minor),
    currency: 'USD',
    status: row.status,
    idempotencyKey: row.idempotency_key,
    riskDecision: row.risk_decision ?? 'deny',
    riskScore: row.risk_score ?? 100,
    reservedAt: row.reserved_at,
    ...(row.submitted_at ? { submittedAt: row.submitted_at } : {}),
    ...(row.processed_at ? { processedAt: row.processed_at } : {}),
    ...(row.failure_reason ? { failureReason: row.failure_reason } : {}),
    createdAt: row.created_at,
  };
}

function parsePayoutAccount(row: PayoutAccountRow): PayoutAccountRecord {
  if (!['pending', 'complete', 'restricted'].includes(row.onboarding_status)) throw new Error('unsupported payout onboarding status');
  return {
    id: row.id,
    provider: row.provider,
    providerAccountId: row.provider_account_id,
    onboardingStatus: row.onboarding_status as PayoutAccountRecord['onboardingStatus'],
    ...(row.onboarding_url ? { onboardingUrl: row.onboarding_url } : {}),
    ...(row.onboarding_expires_at ? { onboardingExpiresAt: row.onboarding_expires_at } : {}),
    ...(row.organization_id ? { organizationId: row.organization_id } : {}),
    ...(row.owner_subject ? { ownerSubject: row.owner_subject } : {}),
  };
}

async function postLedger(
  tx: TransactionSql<{}>,
  input: {
    idempotencyKey: string;
    transactionType: string;
    externalReference: string;
    entries: readonly LedgerEntry[];
    occurredAt: Date;
  },
): Promise<void> {
  assertBalancedEntries(input.entries);
  const existing = await tx<{ id: string }[]>`select id from ledger_transactions where idempotency_key = ${input.idempotencyKey} limit 1`;
  if (existing[0]) return;
  const ledgerTxId = uuidv7();
  await tx`
    insert into ledger_transactions (id, idempotency_key, external_reference, transaction_type, created_at)
    values (${ledgerTxId}, ${input.idempotencyKey}, ${input.externalReference}, ${input.transactionType}, ${input.occurredAt})
  `;
  for (const entry of input.entries) {
    const accountId = await ensureLedgerAccount(tx, entry.account, entry.scopeType, entry.scopeId);
    await tx`
      insert into ledger_entries (id, transaction_id, account_id, amount_minor, currency, created_at)
      values (${uuidv7()}, ${ledgerTxId}, ${accountId}, ${entry.amountMinor.toString()}, ${entry.currency}, ${input.occurredAt})
    `;
  }
  await tx`update ledger_transactions set sealed_at = ${input.occurredAt} where id = ${ledgerTxId}`;
}

async function ensureLedgerAccount(
  tx: TransactionSql<{}>,
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

function accountTypeFor(account: LedgerAccount): string {
  if (account === 'platform_cash' || account === 'payment_provider_clearing') return 'asset';
  if (account === 'referral_commission_payable' || account === 'agent_owner_available_balance' || account === 'agent_owner_pending_balance' || account === 'agent_owner_reserved_balance' || account === 'tax_payable') return 'liability';
  if (account === 'passport_revenue') return 'revenue';
  return 'expense';
}

async function settle(tx: TransactionSql<{}>, payout: PayoutRecord, occurredAt: Date): Promise<void> {
  await postLedger(tx, {
    idempotencyKey: `payout_paid:${payout.payoutReference}`,
    transactionType: 'payout_paid',
    externalReference: payout.payoutReference,
    entries: payoutSettlementEntries(payout.amountMinor, payout.agentId),
    occurredAt,
  });
}

async function release(tx: TransactionSql<{}>, payout: PayoutRecord, occurredAt: Date): Promise<void> {
  await postLedger(tx, {
    idempotencyKey: `payout_release:${payout.payoutReference}`,
    transactionType: 'payout_release',
    externalReference: payout.payoutReference,
    entries: payoutReleaseEntries(payout.amountMinor, payout.agentId),
    occurredAt,
  });
}
