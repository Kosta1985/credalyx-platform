# ADR-0001: Secure modular monolith for the transactional core

Status: Accepted

## Context

Passport issuance, payment confirmation, ledger posting and referral commission creation share strict atomicity requirements. Splitting these into independent services at MVP stage would require distributed transactions or complex compensation before the business invariants are stable.

## Decision

Use a TypeScript/Fastify modular monolith backed by PostgreSQL for the transactional core. Define provider and storage interfaces so modules can later be extracted without exposing database tables as public contracts.

Use:

- Ed25519 proof of agent key possession;
- Ed25519 passport signatures;
- PostgreSQL transaction boundaries for purchase finalization;
- append-only sealed double-entry ledger;
- externally verified owner JWTs;
- hosted payment/provider-managed payouts;
- A2A v1.0 discovery shape.

## Consequences

Positive: fewer distributed failure modes, easier invariant testing, clear audit transaction boundary.

Tradeoff: one deployment has broader code surface. Mitigations are module boundaries, least-privilege database role, explicit adapters, CI security testing and future extraction only when operational need justifies it.
