import { sql } from 'drizzle-orm';
import { index, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core';

const timestamptz = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const issuerSigningKeys = pgTable('issuer_signing_keys', {
  id: uuid('id').primaryKey(),
  keyId: text('key_id').notNull().unique(),
  algorithm: text('algorithm').notNull(),
  publicKeyPem: text('public_key_pem').notNull(),
  publicJwk: jsonb('public_jwk').notNull(),
  provider: text('provider').notNull(),
  providerKeyReference: text('provider_key_reference'),
  status: text('status').notNull(),
  activatedAt: timestamptz('activated_at').notNull(),
  retiredAt: timestamptz('retired_at'),
  revokedAt: timestamptz('revoked_at'),
  createdAt: timestamptz('created_at').notNull().defaultNow(),
  updatedAt: timestamptz('updated_at').notNull().defaultNow(),
}, (table) => [
  uniqueIndex('issuer_signing_keys_one_active')
    .on(sql`(1)`)
    .where(sql`${table.status} = 'active'`),
  index('issuer_signing_keys_status_idx').on(table.status, table.activatedAt),
]);

export const issuerKeyStatusHistory = pgTable('issuer_key_status_history', {
  id: uuid('id').primaryKey(),
  issuerKeyId: uuid('issuer_key_id').notNull().references(() => issuerSigningKeys.id),
  fromStatus: text('from_status'),
  toStatus: text('to_status').notNull(),
  reasonCode: text('reason_code').notNull(),
  actorSubject: text('actor_subject'),
  occurredAt: timestamptz('occurred_at').notNull().defaultNow(),
}, (table) => [index('issuer_key_status_history_key_idx').on(table.issuerKeyId, table.occurredAt)]);
