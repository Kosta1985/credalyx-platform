# CREDALYX Agent Passport Network

Production-oriented identity, verification, trust and commerce infrastructure for AI agents.

> An **Agent Passport** is an internal cryptographically signed CREDALYX credential. It is not a government passport, licence, accreditation, KYC result or regulatory approval.

## Current secure flow

`owner auth -> register agent -> key-bound Ed25519 proof -> server-created checkout -> signed payment event -> Agent Passport -> public issuer/key/status verification -> sealed double-entry ledger -> referral hold/release -> refund/chargeback compensation -> wallet -> dual-proof agent-key rotation -> passport reissue`

## Key invariants

- Agent control uses one-time Ed25519 challenges bound to the exact active agent key.
- Agent key IDs are deterministic SHA-256 SPKI fingerprints (`key_ed25519_*`).
- Normal agent-key rotation requires signatures from both the old and proposed new private keys.
- Only one active agent key and one pending rotation are permitted per agent.
- Agent-key rotation preserves paid passport expiry and purchase association and creates no second charge/referral reward.
- Emergency current-key revocation suspends the agent and revokes active passports.
- A payment-success event cannot issue a passport unless it matches a persisted server-created checkout.
- Refunds/chargebacks create compensating ledger transactions; historical financial rows are not rewritten.
- Sealed ledger transactions are PostgreSQL-protected and must balance per currency.
- Referral rewards move pending -> available only after the configured hold and reverse on purchase reversal.
- Wallet values are derived from the sealed ledger, not mutable balance columns.

## Issuer signing-key lifecycle

New passports use schema **1.1** and include a signed `issuer_key_id`:

`issuer_ed25519_<base64url(SHA-256(SPKI DER))>`

Passport signing is routed through the asynchronous `IssuerSigningBackend` interface. The application asks the backend to sign bytes using a key ID; the interface never exposes a private key. This is the boundary intended for a managed KMS/HSM adapter.

The current `LocalEd25519IssuerBackend` exists for development/tests only. Production configuration requires `PASSPORT_ISSUER_BACKEND=managed` and an opaque `PASSPORT_ISSUER_KEY_REFERENCE`; a concrete managed provider adapter is still a production blocker.

PostgreSQL stores only issuer **public** metadata: public PEM/JWK, key ID, provider, opaque provider key reference, and active/retired/revoked status. There is no private-key field.

Normal issuer rotation retires the old key and activates the new key. Retired keys remain available for historical verification, so old passports stay valid. Revoked issuer keys are excluded from JWKS and passports attributed to them fail live verification.

Public discovery:

```text
GET /.well-known/agent-passport-issuer.json
GET /.well-known/jwks.json
GET /v1/issuer/keys/{issuer_key_id}
```

Schema 1.0 passports issued before `issuer_key_id` existed are verified against retained non-revoked historical issuer keys.

## Agent key lifecycle

```text
GET  /v1/agents/{agent_id}/keys/current
GET  /v1/agents/{agent_id}/keys/{key_id}
POST /v1/agents/{agent_id}/keys/rotation-challenge
POST /v1/agents/{agent_id}/keys/rotation-complete
POST /v1/agents/{agent_id}/keys/{key_id}/revoke
```

Private agent keys are never submitted to CREDALYX.

## Commercial policy defaults

These are configuration rather than hard-coded ledger assumptions:

- Passport price: `PASSPORT_PRICE_MINOR=200` (USD 2.00)
- Referral commission: `REFERRAL_COMMISSION_MINOR=100` (USD 1.00)
- Commission hold: `REFERRAL_HOLD_DAYS=30`
- Minimum payout threshold: `MIN_PAYOUT_MINOR=2500` (USD 25.00)

## Stack

- Node.js 24 + TypeScript
- Fastify
- PostgreSQL 16
- Drizzle ORM + postgres.js
- Zod
- JOSE/JWT auth verification
- OpenAPI 3.1
- GitHub Actions
- Docker Compose (PostgreSQL + Redis)

## Local development

```bash
cp .env.example .env
docker compose up -d postgres redis
pnpm install
pnpm db:migrate
pnpm db:check
pnpm test
pnpm build
```

The API does **not** silently fall back to memory persistence. Memory stores are injected test implementations only.

## A2A compatibility

`/.well-known/agent-card.json` uses the A2A Protocol 1.0 Agent Card shape. Current support is discovery metadata plus the Agent Passport verification skill; full task/message protocol conformance is a later milestone.

## Repository map

- `src/server.ts` — API composition, checkout/webhooks, verification and runtime issuer integration
- `src/domain.ts` — passport and ledger/referral invariants
- `src/crypto.ts` — deterministic fingerprints, challenges and signature helpers
- `src/credentials/` — agent key lifecycle, rotation and emergency revoke
- `src/issuer/backend.ts` — KMS/HSM-compatible signing backend contract + dev/test local backend
- `src/issuer/service.ts` — schema 1.1 issuance and multi-version issuer verification
- `src/issuer/routes.ts` — issuer metadata/JWKS/exact-key discovery
- `src/issuer/store*.ts` — public issuer-key registry adapters
- `src/payments/` — payment provider abstraction and no-money sandbox provider
- `src/db/` — PostgreSQL/Drizzle persistence and schema checks
- `db/migrations/0001_foundation.sql` — core schema and immutable ledger guards
- `db/migrations/0002_commerce_lifecycle.sql` — checkout/reversal/referral lifecycle
- `db/migrations/0003_credential_key_lifecycle.sql` — versioned agent keys/passports
- `db/migrations/0004_issuer_key_lifecycle.sql` — public issuer key registry/status history
- `openapi/openapi.yaml` — OpenAPI 3.1 contract
- `docs/adr/` — architecture decisions

## Production blockers still open

- licensed payment provider hosted-checkout + native raw-body webhook adapter;
- concrete managed KMS/HSM issuer backend and operational issuer rotation/revocation runbook;
- provider-managed payout onboarding, payout reservation and reconciliation;
- partial-refund policy;
- high-assurance owner recovery when the current agent private key is lost;
- Level 2/3 verification provider integrations;
- SSRF-safe active endpoint ownership probing;
- fraud velocity/device/graph controls and manual review;
- distributed scheduling/reconciliation, OpenTelemetry exporters and backup/restore drills;
- privacy retention/anonymisation and jurisdiction-specific payment/tax/sanctions review;
- full A2A task/message TCK work;
- TypeScript/Python SDKs and Owner/Admin/Developer web applications.

No real card data, production secrets, private agent keys or customer personal information belong in source, fixtures or logs.
