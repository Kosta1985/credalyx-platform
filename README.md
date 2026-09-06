# CREDALYX Agent Passport Network

Production-oriented identity, verification, trust and commerce infrastructure for AI agents.

> An **Agent Passport** is an internal cryptographically signed CREDALYX credential. It is not a government passport, licence, accreditation, KYC result or regulatory approval.

## Current implementation

The repository now implements the secure MVP path through commerce and credential lifecycle:

`owner auth -> register agent -> key-bound Ed25519 challenge-response -> server-created checkout -> signed payment event -> Agent Passport issuance -> public verification -> sealed double-entry ledger -> referral hold/release -> refund/chargeback compensation -> wallet read model -> dual-proof agent key rotation -> passport reissue`

### Security and financial invariants enforced

- Agent control is proven by Ed25519 signature over a one-time challenge bound to the exact active verification key.
- Active Ed25519 keys use deterministic SHA-256 SPKI fingerprint identifiers (`key_ed25519_*`).
- Invalid signatures do not consume a challenge; valid challenges are atomic and single-use.
- A challenge bound to an old key cannot be used after key rotation.
- Key rotation requires valid signatures from **both** the currently active private key and the proposed new private key over the same rotation-specific payload.
- A proposed rotation key is not activated until the database transaction commits; only one active key and one pending rotation are allowed per agent.
- Rotating a key does not require a second passport payment. An active passport is revoked and replaced with the next passport version while preserving the original expiry.
- Historical keys and passports remain queryable for audit/verification history instead of being overwritten.
- Emergency revocation of the current key suspends the agent and revokes active passports.
- Production startup requires PostgreSQL, trusted JWT verification configuration and stable issuer keys.
- The current sandbox payment adapter is explicitly non-production and production refuses to start with it.
- A payment-success event must match a persisted server-created checkout session by purchase, agent, provider, amount and currency.
- Checkout creation requires owner/tenant authorization, Level 1 agent control and an `Idempotency-Key`.
- Payment/refund/chargeback events are signature-checked and idempotent by provider/event ID.
- Passport issuance requires verified control and a correlated confirmed payment event.
- Passports are Ed25519 signed, expiry-aware and live-revocation-aware.
- Passport claims reference an exact immutable agent key version, not a floating `current` alias.
- Refunds and chargebacks never mutate sale history; they create sealed compensating transactions and revoke the linked passport.
- Ledger entries use integer minor units, are scoped to platform or agent, and must balance per currency.
- Ledger transactions are sealed once; sealed transactions and entries are immutable in PostgreSQL.
- Referral rewards begin as pending liabilities, move to available only after the configurable hold period, and reverse on refund/chargeback.
- Wallet balances are derived from ledger entries; mutable cached balances are not the source of truth.
- Same-owner self-referral is rejected and referral attribution is locked at purchase.
- Tenant mutations use authenticated subject/organization context.
- Security-sensitive credential and financial state changes produce audit events.

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

Redis is provisioned for upcoming distributed jobs/rate controls. Critical payment, ledger and credential-rotation transaction paths remain PostgreSQL-transactional.

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

The API does **not** silently fall back to in-memory persistence. `MemoryPlatformStore` and `MemoryCredentialLifecycleStore` are injected test implementations only.

## Agent key lifecycle

The current-key endpoint exposes the active key fingerprint and public key:

```text
GET /v1/agents/{agent_id}/keys/current
```

Historical key versions can be resolved directly:

```text
GET /v1/agents/{agent_id}/keys/{key_id}
```

Rotation is a two-step protocol:

```text
POST /v1/agents/{agent_id}/keys/rotation-challenge
POST /v1/agents/{agent_id}/keys/rotation-complete
```

The completion request must contain signatures from the old and new private keys over the exact `signing_payload` returned by the rotation challenge. Private keys are never sent to CREDALYX.

Emergency owner-controlled key revocation is exposed at:

```text
POST /v1/agents/{agent_id}/keys/{key_id}/revoke
```

If the revoked key is the active key, the agent is suspended and active passports are revoked until a controlled recovery flow is completed.

## A2A compatibility

Discovery uses the A2A Protocol **1.0** Agent Card shape at:

`/.well-known/agent-card.json`

The platform is not claiming full A2A server conformance yet. Current support is discovery metadata and the Agent Passport verification skill; task/message protocol bindings remain a later compatibility milestone.

## Repository map

- `src/server.ts` — HTTP API, checkout, webhook, wallet and credential route integration
- `src/domain.ts` — passport, ledger, release, reversal and payout invariants
- `src/crypto.ts` — UUIDv7, key fingerprints, proof/rotation payloads and sandbox webhook cryptography
- `src/credentials/routes.ts` — key history, dual-proof rotation and emergency revoke HTTP routes
- `src/credentials/store.ts` — credential lifecycle persistence contract + test memory adapter
- `src/credentials/store-postgres.ts` — atomic PostgreSQL key lifecycle implementation
- `src/auth.ts` — trusted JWT auth adapter and authorization predicates
- `src/payments/provider.ts` — payment-provider contract
- `src/payments/sandbox.ts` — deterministic no-money sandbox checkout adapter
- `src/store.ts` — persistence/commerce contract + test-only memory implementation
- `src/db/schema.ts` — Drizzle schema
- `src/db/store-postgres.ts` — transactional commerce/ledger PostgreSQL implementation
- `src/db/migrate.ts` — ordered migration runner with `schema_migrations`
- `db/migrations/0001_foundation.sql` — initial schema + immutable ledger guards
- `db/migrations/0002_commerce_lifecycle.sql` — checkout correlation, purchase/passport link and reversal/release metadata
- `db/migrations/0003_credential_key_lifecycle.sql` — key versioning, rotation state and passport version history
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
- formal owner/account recovery controls for a lost active agent private key, including step-up authentication/manual review policy;
- organization lifecycle/UI and external Level 2/3 verification providers;
- SSRF-safe active endpoint ownership probing;
- fraud velocity/device/graph controls and manual review queue;
- Redis-backed distributed scheduling for release/reconciliation jobs;
- OpenTelemetry exporters, backup/restore tests and operational runbooks;
- privacy retention/anonymisation workflows and jurisdiction-specific payment/tax/sanctions review;
- A2A TCK/conformance work for task/message interfaces;
- TypeScript/Python SDKs and Owner/Admin/Developer web interfaces.

No real secrets, card data, private agent keys or customer personal information belong in source, fixtures or logs.
