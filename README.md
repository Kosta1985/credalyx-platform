# CREDALYX Agent Passport Network

Production-oriented identity, verification, trust and commerce infrastructure for AI agents.

> An **Agent Passport** is an internal cryptographically signed CREDALYX credential. It is not a government passport, licence, accreditation, KYC result or regulatory approval.

## Current implementation

The repository now implements the secure MVP path through the referral lifecycle:

`owner auth -> register agent -> Ed25519 challenge-response -> server-created checkout -> signed payment event -> Agent Passport issuance -> public verification -> sealed double-entry ledger -> referral hold -> commission release -> refund/chargeback compensation -> wallet read model`

### Security and financial invariants enforced

- Agent control is proven by Ed25519 signature over a one-time, agent-bound challenge.
- Invalid signatures do not consume a challenge; valid challenges are atomic and single-use.
- Production startup requires PostgreSQL, trusted JWT verification configuration and stable issuer keys.
- The current sandbox payment adapter is explicitly non-production and production refuses to start with it.
- A payment-success event must match a persisted server-created checkout session by purchase, agent, provider, amount and currency.
- Checkout creation requires owner/tenant authorization, Level 1 agent control and an `Idempotency-Key`.
- Payment/refund/chargeback events are signature-checked and idempotent by provider/event ID.
- Passport issuance requires verified control and a correlated confirmed payment event.
- Passports are Ed25519 signed, expiry-aware and live-revocation-aware.
- Refunds and chargebacks never mutate sale history; they create sealed compensating transactions and revoke the linked passport.
- Ledger entries use integer minor units, are scoped to platform or agent, and must balance per currency.
- Ledger transactions are sealed once; sealed transactions and entries are immutable in PostgreSQL.
- Referral rewards begin as pending liabilities, move to available only after the configurable hold period, and reverse on refund/chargeback.
- Wallet balances are derived from ledger entries; mutable cached balances are not the source of truth.
- Same-owner self-referral is rejected and referral attribution is locked at purchase.
- Tenant mutations use authenticated subject/organization context.
- Security-sensitive financial state changes produce audit events.

## Commercial policy defaults

These values are configuration, not hard-coded product assumptions:

- Passport price: `PASSPORT_PRICE_MINOR=200` (USD 2.00)
- Referral commission: `REFERRAL_COMMISSION_MINOR=100` (USD 1.00)
- Commission hold: `REFERRAL_HOLD_DAYS=30`
- Minimum payout threshold: `MIN_PAYOUT_MINOR=2500` (USD 25.00)

The payout threshold is an operational batching default. It exists to avoid turning every USD 1 reward into a separate provider payout. Product/legal/finance review may change any of these values without changing ledger logic.

## Stack

- Node.js 24 + TypeScript
- Fastify
- PostgreSQL 16
- Drizzle ORM + postgres.js
- Zod
- JOSE/JWT verification adapter
- GitHub Actions
- OpenAPI 3.1
- Docker Compose for PostgreSQL and Redis

Redis is provisioned for upcoming distributed jobs/rate controls. The critical payment and ledger transaction path remains PostgreSQL-transactional.

## Local database

```bash
cp .env.example .env
docker compose up -d postgres redis
pnpm install
pnpm db:migrate
pnpm db:check
pnpm test
```

Release eligible commissions manually in development/test:

```bash
pnpm jobs:release-commissions
```

The API does **not** silently fall back to in-memory persistence. `MemoryPlatformStore` is an injected test implementation only.

## A2A compatibility

Discovery uses the A2A Protocol **1.0** Agent Card shape at:

`/.well-known/agent-card.json`

The platform is not claiming full A2A server conformance yet. Current support is discovery metadata and the Agent Passport verification skill; task/message protocol bindings remain a later compatibility milestone.

## Repository map

- `src/server.ts` — HTTP API, checkout, webhook and wallet routes
- `src/domain.ts` — passport, ledger, release, reversal and payout invariants
- `src/crypto.ts` — UUIDv7, agent proof and sandbox webhook cryptography
- `src/auth.ts` — trusted JWT auth adapter and authorization predicates
- `src/payments/provider.ts` — payment-provider contract
- `src/payments/sandbox.ts` — deterministic no-money sandbox checkout adapter
- `src/store.ts` — persistence/commerce contract + test-only memory implementation
- `src/db/schema.ts` — base Drizzle schema
- `src/db/store-postgres.ts` — transactional PostgreSQL implementation
- `src/db/migrate.ts` — ordered migration runner with `schema_migrations`
- `db/migrations/0001_foundation.sql` — initial schema + immutable ledger guards
- `db/migrations/0002_commerce_lifecycle.sql` — checkout correlation, purchase/passport link and reversal/release metadata
- `src/jobs/release-commissions.ts` — concurrency-safe commission release worker entrypoint
- `openapi/openapi.yaml` — OpenAPI 3.1 contract
- `docs/architecture.md` — system architecture and boundaries
- `docs/threat-model.md` — threat model
- `docs/adr/` — architecture decisions

## Production blockers still open

- licensed provider-specific hosted checkout adapter with provider-native **raw-body** webhook verification;
- provider-managed recipient onboarding and real payouts;
- payout request/reservation transaction and payout reconciliation;
- partial-refund policy (current MVP reversal treats a passport purchase as a full reversal event);
- issuer signing via managed KMS/HSM rather than PEM environment material;
- organization lifecycle/UI and external Level 2/3 verification providers;
- SSRF-safe active endpoint ownership probing;
- fraud velocity/device/graph controls and manual review queue;
- Redis-backed distributed scheduling for release/reconciliation jobs;
- OpenTelemetry exporters, backup/restore tests and operational runbooks;
- privacy retention/anonymisation workflows and jurisdiction-specific payment/tax/sanctions review;
- A2A TCK/conformance work for task/message interfaces;
- TypeScript/Python SDKs and Owner/Admin/Developer web interfaces.

No real secrets, card data or customer personal information belong in source, fixtures or logs.
