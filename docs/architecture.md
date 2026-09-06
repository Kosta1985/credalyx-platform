# Architecture — Agent Passport Network

## Product boundary

CREDALYX provides a private-sector trust credential for software agents. The credential communicates platform-observed verification state; it does not assert governmental identity, licensing or regulatory approval.

## Architecture style

The MVP is a **modular monolith with explicit domain boundaries** and one PostgreSQL transaction boundary for critical financial operations. This is intentional: passport issuance, purchase finalization, referral commission creation and ledger posting must be atomic. Premature service separation would increase distributed-transaction risk.

Logical modules:

1. Identity / tenancy
2. Agent registry
3. Agent key and endpoint control verification
4. Verification workflow
5. Passport issuer / status registry
6. Payment provider adapters
7. Ledger
8. Referrals / payouts
9. Audit / risk / incidents
10. Public API and A2A discovery

A future monorepo split may separate deployables and SDKs without changing domain interfaces.

## Trust boundaries

- **Owner -> API:** signed JWT from trusted IdP; tenant data is selected from verified claims and server-side membership state.
- **Agent -> API:** Ed25519 proof of possession; static API keys are not accepted as proof of agent identity.
- **Payment provider -> API:** provider-specific signed webhook; sandbox currently uses timestamp + canonical payload HMAC.
- **API -> PostgreSQL:** least-privilege application role; financial writes occur inside transactions.
- **Passport issuer key:** production target is KMS/HSM. Repository contains no issuer secret.
- **Agent endpoint:** untrusted network destination. Endpoint fetching/probing must use SSRF-safe egress policy when introduced.

## Agent control protocol

1. Owner registers an Ed25519 public key and HTTPS A2A endpoint.
2. API returns 256-bit random challenge plus exact canonical signing payload.
3. Agent signs `CREDALYX_AGENT_CONTROL_V1 + agent_id + challenge`.
4. API verifies signature against registered public key.
5. PostgreSQL atomically consumes the challenge and raises verification to Level 1.
6. Replay or expired challenge fails.

## Passport

Current passport uses Ed25519 over deterministic canonical JSON claims. Claims contain no owner email/name. Public status is resolved separately so suspension/revocation takes effect without reissuing old credentials.

Production key requirements:

- stable key ID/version;
- managed private-key custody;
- rotation overlap;
- public verification-key endpoint/JWKS or equivalent;
- incident revocation procedure.

## Payments and ledger

The platform stores accounting facts, not card credentials and not a self-built bank account.

Payment provider flow:

1. hosted checkout session at licensed provider;
2. signed provider webhook;
3. idempotent event reservation;
4. verified-agent precondition;
5. atomic purchase + passport + ledger + commission;
6. commission held until configured risk window ends;
7. refunds/chargebacks use compensating transactions;
8. payouts use provider-managed connected-account/onboarding capability.

Ledger convention: positive amounts are debits, negative amounts are credits. Every transaction sums to zero per currency.

Ledger accounts are scoped:

- platform accounts use scope `(platform, platform)`;
- referral balances use `(agent, <referrer internal id>)`.

PostgreSQL seals a transaction only after checking it contains at least two entries and balances. After sealing, entries cannot be added, updated or deleted.

## A2A interoperability

A2A v1.0 discovery is exposed with `supportedInterfaces[]`, not the removed v0.3 top-level transport fields. Current Agent Card advertises only the passport-verification skill. Full task/message handling is intentionally not claimed yet.

## Data minimization

Public agent and passport responses contain agent technical metadata only. Owner identity is not embedded into passports. Verification evidence is referenced rather than copied into public objects. Payment card data is never accepted by CREDALYX endpoints.

## Evolution

The persistence and payment layers are interfaces. Provider, price, commission amount, hold window and issuer implementation are configuration/injected adapters rather than hard-coded business assumptions.
