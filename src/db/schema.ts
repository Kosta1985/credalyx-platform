import { sql } from 'drizzle-orm';
import {
  type AnyPgColumn,
  bigint,
  check,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

const timestamptz = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const organizationRole = pgEnum('organization_role', ['owner', 'admin', 'verifier', 'developer', 'viewer']);
export const agentStatus = pgEnum('agent_status', ['pending', 'active', 'suspended', 'revoked']);
export const passportStatus = pgEnum('passport_status', ['active', 'suspended', 'revoked', 'expired']);
export const verificationStatus = pgEnum('verification_status', ['pending', 'approved', 'rejected', 'cancelled']);
export const commissionStatus = pgEnum('commission_status', ['pending', 'available', 'paid', 'reversed']);
export const payoutStatus = pgEnum('payout_status', ['pending', 'processing', 'paid', 'failed', 'cancelled']);

export const users = pgTable('users', {
  id: uuid('id').primaryKey(),
  externalSubject: text('external_subject').notNull().unique(),
  email: text('email'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  updatedAt: timestamptz('updated_at').notNull().defaultNow(),
  deletedAt: timestamptz('deleted_at'),
});

export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey(),
  name: text('name').notNull(),
  domain: text('domain'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  updatedAt: timestamptz('updated_at').notNull().defaultNow(),
  deletedAt: timestamptz('deleted_at'),
}, (table) => [uniqueIndex('organizations_domain_unique').on(table.domain)]);

export const organizationMembers = pgTable('organization_members', {
  id: uuid('id').primaryKey(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id),
  userId: uuid('user_id').notNull().references(() => users.id),
  role: organizationRole('role').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  revokedAt: timestamptz('revoked_at'),
}, (table) => [
  uniqueIndex('organization_members_org_user_unique').on(table.organizationId, table.userId),
  index('organization_members_user_idx').on(table.userId),
]);

export const agents = pgTable('agents', {
  id: uuid('id').primaryKey(),
  publicId: text('public_id').notNull().unique(),
  ownerUserId: uuid('owner_user_id').notNull().references(() => users.id),
  organizationId: uuid('organization_id').references(() => organizations.id),
  referrerAgentId: uuid('referrer_agent_id').references((): AnyPgColumn => agents.id),
  referralCode: text('referral_code').notNull().unique(),
  verificationLevel: integer('verification_level').notNull().default(0),
  status: agentStatus('status').notNull().default('pending'),
  controlVerifiedAt: timestamptz('control_verified_at'),
  version: integer('version').notNull().default(1),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  updatedAt: timestamptz('updated_at').notNull().defaultNow(),
  deletedAt: timestamptz('deleted_at'),
}, (table) => [
  index('agents_owner_idx').on(table.ownerUserId),
  index('agents_org_idx').on(table.organizationId),
  check('agents_verification_level_range', sql`${table.verificationLevel} between 0 and 3`),
  check('agents_not_self_referrer', sql`${table.referrerAgentId} is null or ${table.referrerAgentId} <> ${table.id}`),
]);

export const agentKeys = pgTable('agent_keys', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  keyId: text('key_id').notNull(),
  algorithm: text('algorithm').notNull(),
  publicKeyPem: text('public_key_pem').notNull(),
  activatedAt: timestamptz('activated_at').notNull().defaultNow(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  expiresAt: timestamptz('expires_at'),
  revokedAt: timestamptz('revoked_at'),
}, (table) => [
  uniqueIndex('agent_keys_agent_key_unique').on(table.agentId, table.keyId),
  index('agent_keys_active_idx').on(table.agentId, table.revokedAt),
  uniqueIndex('agent_keys_one_active_per_agent')
    .on(table.agentId)
    .where(sql`${table.activatedAt} is not null and ${table.revokedAt} is null`),
]);

export const agentEndpoints = pgTable('agent_endpoints', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  url: text('url').notNull(),
  protocolBinding: text('protocol_binding').notNull().default('HTTP+JSON'),
  protocolVersion: text('protocol_version').notNull().default('1.0'),
  verifiedAt: timestamptz('verified_at'),
  disabledAt: timestamptz('disabled_at'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [uniqueIndex('agent_endpoints_agent_url_unique').on(table.agentId, table.url)]);

export const agentCapabilities = pgTable('agent_capabilities', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  capability: text('capability').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [uniqueIndex('agent_capabilities_unique').on(table.agentId, table.capability)]);

export const agentChallenges = pgTable('agent_challenges', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  agentKeyId: uuid('agent_key_id').references(() => agentKeys.id),
  digest: text('digest').notNull(),
  expiresAt: timestamptz('expires_at').notNull(),
  consumedAt: timestamptz('consumed_at'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [
  index('agent_challenges_lookup_idx').on(table.agentId, table.digest, table.expiresAt),
  index('agent_challenges_key_idx').on(table.agentKeyId, table.expiresAt),
]);

export const agentKeyRotations = pgTable('agent_key_rotations', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  oldKeyId: uuid('old_key_id').notNull().references(() => agentKeys.id),
  newKeyFingerprint: text('new_key_fingerprint').notNull(),
  newPublicKeyPem: text('new_public_key_pem').notNull(),
  challengeDigest: text('challenge_digest').notNull(),
  expiresAt: timestamptz('expires_at').notNull(),
  completedAt: timestamptz('completed_at'),
  cancelledAt: timestamptz('cancelled_at'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [
  index('agent_key_rotations_agent_idx').on(table.agentId, table.createdAt),
  uniqueIndex('agent_key_rotations_one_pending_per_agent')
    .on(table.agentId)
    .where(sql`${table.completedAt} is null and ${table.cancelledAt} is null`),
]);

export const agentPassports = pgTable('agent_passports', {
  id: uuid('id').primaryKey(),
  passportId: text('passport_id').notNull().unique(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  purchaseId: uuid('purchase_id').references(() => purchases.id),
  passportVersion: integer('passport_version').notNull().default(1),
  schemaVersion: text('schema_version').notNull(),
  claims: jsonb('claims').notNull(),
  signature: text('signature').notNull(),
  status: passportStatus('status').notNull().default('active'),
  issuedAt: timestamptz('issued_at').notNull(),
  expiresAt: timestamptz('expires_at').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [
  index('agent_passports_purchase_idx').on(table.purchaseId),
  uniqueIndex('agent_passports_purchase_version_unique')
    .on(table.purchaseId, table.passportVersion)
    .where(sql`${table.purchaseId} is not null`),
  check('agent_passports_version_positive', sql`${table.passportVersion} > 0`),
]);

export const passportStatusHistory = pgTable('passport_status_history', {
  id: uuid('id').primaryKey(),
  passportId: uuid('passport_id').notNull().references(() => agentPassports.id),
  fromStatus: passportStatus('from_status'),
  toStatus: passportStatus('to_status').notNull(),
  reasonCode: text('reason_code').notNull(),
  actorSubject: text('actor_subject'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [index('passport_status_history_passport_idx').on(table.passportId, table.createdAt)]);

export const verificationRequests = pgTable('verification_requests', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  requestedLevel: integer('requested_level').notNull(),
  status: verificationStatus('status').notNull().default('pending'),
  provider: text('provider'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  decidedAt: timestamptz('decided_at'),
}, (table) => [check('verification_requested_level_range', sql`${table.requestedLevel} between 1 and 3`)]);

export const verificationEvidence = pgTable('verification_evidence', {
  id: uuid('id').primaryKey(),
  verificationRequestId: uuid('verification_request_id').notNull().references(() => verificationRequests.id),
  evidenceType: text('evidence_type').notNull(),
  storageReference: text('storage_reference'),
  metadata: jsonb('metadata').notNull().default({}),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
});

export const verificationDecisions = pgTable('verification_decisions', {
  id: uuid('id').primaryKey(),
  verificationRequestId: uuid('verification_request_id').notNull().references(() => verificationRequests.id),
  decision: text('decision').notNull(),
  reasonCode: text('reason_code').notNull(),
  actorSubject: text('actor_subject'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
});

export const referrals = pgTable('referrals', {
  id: uuid('id').primaryKey(),
  referredAgentId: uuid('referred_agent_id').notNull().references(() => agents.id).unique(),
  referrerAgentId: uuid('referrer_agent_id').notNull().references(() => agents.id),
  referralCode: text('referral_code').notNull(),
  attributedAt: timestamptz('attributed_at').notNull().defaultNow(),
  lockedAt: timestamptz('locked_at'),
}, (table) => [
  index('referrals_referrer_idx').on(table.referrerAgentId),
  check('referrals_not_self', sql`${table.referredAgentId} <> ${table.referrerAgentId}`),
]);

export const paymentCustomers = pgTable('payment_customers', {
  id: uuid('id').primaryKey(),
  ownerUserId: uuid('owner_user_id').notNull().references(() => users.id),
  provider: text('provider').notNull(),
  providerCustomerId: text('provider_customer_id').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [uniqueIndex('payment_customers_provider_unique').on(table.provider, table.providerCustomerId)]);

export const paymentSessions = pgTable('payment_sessions', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  provider: text('provider').notNull(),
  providerSessionId: text('provider_session_id').notNull(),
  idempotencyKey: text('idempotency_key'),
  purchaseReference: text('purchase_reference'),
  checkoutUrl: text('checkout_url'),
  amountMinor: bigint('amount_minor', { mode: 'bigint' }).notNull(),
  currency: text('currency').notNull(),
  status: text('status').notNull(),
  expiresAt: timestamptz('expires_at'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [
  uniqueIndex('payment_sessions_provider_unique').on(table.provider, table.providerSessionId),
  uniqueIndex('payment_sessions_idempotency_unique').on(table.provider, table.idempotencyKey).where(sql`${table.idempotencyKey} is not null`),
  uniqueIndex('payment_sessions_purchase_reference_unique').on(table.purchaseReference).where(sql`${table.purchaseReference} is not null`),
]);

export const paymentEvents = pgTable('payment_events', {
  id: uuid('id').primaryKey(),
  provider: text('provider').notNull(),
  providerEventId: text('provider_event_id').notNull(),
  eventType: text('event_type').notNull(),
  payloadHash: text('payload_hash').notNull(),
  receivedAt: timestamptz('received_at').notNull().defaultNow(),
  processedAt: timestamptz('processed_at'),
}, (table) => [uniqueIndex('payment_events_provider_event_unique').on(table.provider, table.providerEventId)]);

export const purchases = pgTable('purchases', {
  id: uuid('id').primaryKey(),
  externalReference: text('external_reference').notNull().unique(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  paymentEventId: uuid('payment_event_id').notNull().references(() => paymentEvents.id),
  amountMinor: bigint('amount_minor', { mode: 'bigint' }).notNull(),
  currency: text('currency').notNull(),
  status: text('status').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
});

export const ledgerAccounts = pgTable('ledger_accounts', {
  id: uuid('id').primaryKey(),
  code: text('code').notNull(),
  accountType: text('account_type').notNull(),
  scopeType: text('scope_type').notNull(),
  scopeId: text('scope_id').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [uniqueIndex('ledger_accounts_scope_unique').on(table.code, table.scopeType, table.scopeId)]);

export const ledgerTransactions = pgTable('ledger_transactions', {
  id: uuid('id').primaryKey(),
  idempotencyKey: text('idempotency_key').notNull().unique(),
  externalReference: text('external_reference').notNull(),
  transactionType: text('transaction_type').notNull(),
  sealedAt: timestamptz('sealed_at'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
});

export const ledgerEntries = pgTable('ledger_entries', {
  id: uuid('id').primaryKey(),
  transactionId: uuid('transaction_id').notNull().references(() => ledgerTransactions.id),
  accountId: uuid('account_id').notNull().references(() => ledgerAccounts.id),
  amountMinor: bigint('amount_minor', { mode: 'bigint' }).notNull(),
  currency: text('currency').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [index('ledger_entries_transaction_idx').on(table.transactionId), index('ledger_entries_account_idx').on(table.accountId)]);

export const commissions = pgTable('commissions', {
  id: uuid('id').primaryKey(),
  purchaseId: uuid('purchase_id').notNull().references(() => purchases.id).unique(),
  referrerAgentId: uuid('referrer_agent_id').notNull().references(() => agents.id),
  amountMinor: bigint('amount_minor', { mode: 'bigint' }).notNull(),
  currency: text('currency').notNull(),
  status: commissionStatus('status').notNull().default('pending'),
  holdUntil: timestamptz('hold_until').notNull(),
  releasedAt: timestamptz('released_at'),
  reversedAt: timestamptz('reversed_at'),
  reversalReason: text('reversal_reason'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  updatedAt: timestamptz('updated_at').notNull().defaultNow(),
});

export const payoutAccounts = pgTable('payout_accounts', {
  id: uuid('id').primaryKey(),
  ownerUserId: uuid('owner_user_id').notNull().references(() => users.id),
  provider: text('provider').notNull(),
  providerAccountId: text('provider_account_id').notNull(),
  onboardingStatus: text('onboarding_status').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [uniqueIndex('payout_accounts_provider_unique').on(table.provider, table.providerAccountId)]);

export const payouts = pgTable('payouts', {
  id: uuid('id').primaryKey(),
  payoutAccountId: uuid('payout_account_id').notNull().references(() => payoutAccounts.id),
  amountMinor: bigint('amount_minor', { mode: 'bigint' }).notNull(),
  currency: text('currency').notNull(),
  status: payoutStatus('status').notNull().default('pending'),
  providerPayoutId: text('provider_payout_id'),
  idempotencyKey: text('idempotency_key').notNull().unique(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
});

export const refunds = pgTable('refunds', {
  id: uuid('id').primaryKey(),
  purchaseId: uuid('purchase_id').notNull().references(() => purchases.id),
  providerRefundId: text('provider_refund_id'),
  provider: text('provider'),
  providerEventId: text('provider_event_id'),
  reasonCode: text('reason_code'),
  amountMinor: bigint('amount_minor', { mode: 'bigint' }).notNull(),
  currency: text('currency').notNull(),
  status: text('status').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [
  uniqueIndex('refunds_provider_event_unique').on(table.provider, table.providerEventId)
    .where(sql`${table.provider} is not null and ${table.providerEventId} is not null`),
]);

export const disputes = pgTable('disputes', {
  id: uuid('id').primaryKey(),
  purchaseId: uuid('purchase_id').notNull().references(() => purchases.id),
  providerDisputeId: text('provider_dispute_id').notNull().unique(),
  provider: text('provider'),
  providerEventId: text('provider_event_id'),
  reasonCode: text('reason_code'),
  amountMinor: bigint('amount_minor', { mode: 'bigint' }).notNull(),
  currency: text('currency').notNull(),
  status: text('status').notNull(),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [
  uniqueIndex('disputes_provider_event_unique').on(table.provider, table.providerEventId)
    .where(sql`${table.provider} is not null and ${table.providerEventId} is not null`),
]);

export const webhookEvents = pgTable('webhook_events', {
  id: uuid('id').primaryKey(),
  provider: text('provider').notNull(),
  providerEventId: text('provider_event_id').notNull(),
  payloadHash: text('payload_hash').notNull(),
  processingStatus: text('processing_status').notNull(),
  receivedAt: timestamptz('received_at').notNull().defaultNow(),
  processedAt: timestamptz('processed_at'),
}, (table) => [uniqueIndex('webhook_events_provider_event_unique').on(table.provider, table.providerEventId)]);

export const apiClients = pgTable('api_clients', {
  id: uuid('id').primaryKey(),
  organizationId: uuid('organization_id').references(() => organizations.id),
  name: text('name').notNull(),
  clientId: text('client_id').notNull().unique(),
  secretHash: text('secret_hash'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  revokedAt: timestamptz('revoked_at'),
});

export const accessTokens = pgTable('access_tokens', {
  id: uuid('id').primaryKey(),
  apiClientId: uuid('api_client_id').notNull().references(() => apiClients.id),
  tokenHash: text('token_hash').notNull().unique(),
  scopes: jsonb('scopes').notNull().default([]),
  expiresAt: timestamptz('expires_at').notNull(),
  revokedAt: timestamptz('revoked_at'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
});

export const consents = pgTable('consents', {
  id: uuid('id').primaryKey(),
  subjectUserId: uuid('subject_user_id').references(() => users.id),
  agentId: uuid('agent_id').references(() => agents.id),
  purpose: text('purpose').notNull(),
  scopes: jsonb('scopes').notNull().default([]),
  grantedAt: timestamptz('granted_at').notNull().defaultNow(),
  revokedAt: timestamptz('revoked_at'),
});

export const auditEvents = pgTable('audit_events', {
  id: uuid('id').primaryKey(),
  occurredAt: timestamptz('occurred_at').notNull().defaultNow(),
  actorType: text('actor_type').notNull(),
  actorSubject: text('actor_subject'),
  organizationId: uuid('organization_id'),
  action: text('action').notNull(),
  targetType: text('target_type').notNull(),
  targetId: text('target_id').notNull(),
  reasonCode: text('reason_code'),
  correlationId: text('correlation_id'),
  metadata: jsonb('metadata').notNull().default({}),
}, (table) => [index('audit_events_target_idx').on(table.targetType, table.targetId, table.occurredAt)]);

export const riskSignals = pgTable('risk_signals', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').references(() => agents.id),
  signalType: text('signal_type').notNull(),
  score: integer('score'),
  metadata: jsonb('metadata').notNull().default({}),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
});

export const securityIncidents = pgTable('security_incidents', {
  id: uuid('id').primaryKey(),
  severity: text('severity').notNull(),
  status: text('status').notNull(),
  title: text('title').notNull(),
  description: text('description').notNull(),
  detectedAt: timestamptz('detected_at').notNull().defaultNow(),
  resolvedAt: timestamptz('resolved_at'),
});
