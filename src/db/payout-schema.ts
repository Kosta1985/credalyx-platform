import { index, jsonb, pgTable, text, timestamp, uniqueIndex, uuid, bigint, integer } from 'drizzle-orm/pg-core';
import { agents, payouts } from './schema.js';

const timestamptz = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const payoutEvents = pgTable('payout_events', {
  id: uuid('id').primaryKey(),
  provider: text('provider').notNull(),
  providerEventId: text('provider_event_id').notNull(),
  payoutId: uuid('payout_id').references(() => payouts.id),
  eventType: text('event_type').notNull(),
  payloadHash: text('payload_hash').notNull(),
  processingStatus: text('processing_status').notNull(),
  receivedAt: timestamptz('received_at').notNull().defaultNow(),
  processedAt: timestamptz('processed_at'),
}, (table) => [
  uniqueIndex('payout_events_provider_event_unique').on(table.provider, table.providerEventId),
  index('payout_events_payout_idx').on(table.payoutId, table.receivedAt),
]);

export const payoutRiskAssessments = pgTable('payout_risk_assessments', {
  id: uuid('id').primaryKey(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  payoutId: uuid('payout_id').references(() => payouts.id),
  idempotencyKey: text('idempotency_key').notNull(),
  amountMinor: bigint('amount_minor', { mode: 'bigint' }).notNull(),
  currency: text('currency').notNull(),
  decision: text('decision').notNull(),
  score: integer('score').notNull(),
  reasons: jsonb('reasons').notNull().default([]),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
}, (table) => [index('payout_risk_assessments_agent_idx').on(table.agentId, table.createdAt)]);
