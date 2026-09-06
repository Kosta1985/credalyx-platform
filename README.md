# CREDALYX Agent Passport Network

Production-oriented identity, verification and trust infrastructure for AI agents.

> An **Agent Passport** is an internal cryptographically signed CREDALYX credential. It is not a government passport, licence, accreditation, KYC result or regulatory approval.

## Current implementation

The repository contains the secure foundation for the MVP vertical flow:

`owner auth -> register agent -> Ed25519 challenge-response -> signed payment webhook -> Agent Passport issuance -> public verification -> sealed double-entry ledger -> pending referral commission -> revocation`

### Security invariants already enforced

- Agent control is proven by Ed25519 signature over a one-time, agent-bound challenge.
- Invalid signatures do not consume a challenge; valid challenges are atomic and single-use.
- Production startup requires PostgreSQL, trusted JWT verification configuration and stable issuer keys.
- Payment events are accepted only after timestamped HMAC verification in the sandbox adapter.
- Payment events are idempotent by provider/event ID.
- Passport issuance requires verified agent control and a confirmed payment event.
- Passports are Ed25519 signed, expiry-aware and revocation-aware.
- Ledger entries are integer minor units, scoped to platform or agent, and must balance per currency.
- Ledger transactions are sealed once; sealed transactions and entries are immutable in PostgreSQL.
- Corrections are represented by compensating entries, not edits.
- Self-referral by the same owner is rejected.
- Tenant mutation checks use authenticated subject/organization context.
- Administrative/security-sensitive changes create audit records in the PostgreSQL store.

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

Redis is provisioned for the next queue/rate-limit/reconciliation phase; the critical transaction path does not depend on asynchronous jobs.

## Local database

```bash
cp .env.example .env
docker compose up -d postgres redis
pnpm install
pnpm db:migrate
pnpm db:check
pnpm test
```

The API intentionally does **not** silently fall back to in-memory persistence. `MemoryPlatformStore` exists only as an injected test implementation.

## A2A compatibility

Discovery uses the A2A Protocol **1.0** Agent Card shape at:

`/.well-known/agent-card.json`

The platform is not claiming full A2A server conformance yet. Current support is discovery metadata and the Agent Passport verification skill; task/message protocol bindings are a later compatibility milestone.

## Repository map

- `src/server.ts` — HTTP API and dependency wiring
- `src/domain.ts` — passports and ledger invariants
- `src/crypto.ts` — UUIDv7, agent proof and sandbox webhook cryptography
- `src/auth.ts` — trusted JWT auth adapter and authorization predicates
- `src/store.ts` — persistence contract + test-only memory implementation
- `src/db/schema.ts` — Drizzle schema
- `src/db/store-postgres.ts` — transactional PostgreSQL implementation
- `db/migrations/0001_foundation.sql` — initial schema + immutable ledger guards
- `openapi/openapi.yaml` — OpenAPI 3.1 contract
- `docs/architecture.md` — system architecture and boundaries
- `docs/threat-model.md` — threat model
- `docs/adr/0001-secure-modular-monolith.md` — first architecture decision record

## Production blockers still open

- provider-specific hosted checkout + raw-body webhook adapter;
- refund/chargeback persistence and compensating ledger automation;
- commission hold-release worker and provider-managed payouts;
- organization lifecycle/UI and external verification providers;
- issuer signing via managed KMS/HSM rather than PEM environment material;
- Redis-backed distributed replay/rate controls where required;
- full OpenTelemetry exporter configuration;
- data retention/anonymisation workflows and jurisdiction-specific legal review;
- A2A TCK/conformance work for task/message interfaces.

No real secrets, card data or customer personal information belong in source, fixtures or logs.
