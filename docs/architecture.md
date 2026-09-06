# Architecture — Agent Passport Network

## Product boundary

CREDALYX provides a private-sector trust credential for software agents. The credential communicates platform-observed verification state; it does not assert governmental identity, licensing, KYC or regulatory approval. The internal wallet is a double-entry accounting view, not a bank account or stored-value product.

## Architecture style

The MVP is a **modular monolith with explicit domain boundaries** and PostgreSQL transaction boundaries for critical financial operations. Passport issuance, purchase finalization, referral commission creation and ledger posting are atomic. Refunds and chargebacks are separate compensating transactions rather than mutations of historical finance rows.

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
- **Payment provider -> API:** provider-specific signed webhook; sandbox uses timestamp + canonical-payload HMAC.
- **API -> PostgreSQL:** financial writes occur inside transactions; sealed ledger history is DB-protected.
- **Passport issuer key:** production target is KMS/HSM. Repository contains no production issuer secret.
- **Agent endpoint:** untrusted network destination. Endpoint probing must use SSRF-safe egress policy before it is introduced.

## Agent control protocol

1. Owner registers an Ed25519 public key and HTTPS A2A endpoint.
2. API returns a 256-bit random challenge plus exact canonical signing payload.
3. Agent signs `CREDALYX_AGENT_CONTROL_V1 + agent_id + challenge`.
4. API verifies the signature against the registered public key.
5. PostgreSQL atomically consumes the challenge and raises verification to Level 1.
6. Replay or expired challenges fail.

## Passport

The passport uses Ed25519 over deterministic canonical JSON claims. Claims contain no owner email/name. Public status is resolved separately, so revocation takes effect without modifying the signed historical credential.

Production key requirements:

- stable key ID/version;
- managed private-key custody;
- rotation overlap;
- public verification-key endpoint/JWKS or equivalent;
- emergency compromise/revocation procedure.

## Checkout and payment correlation

A valid provider signature is necessary but not sufficient to issue a passport.

1. Authenticated owner requests `passport-checkout` for a Level 1-controlled agent.
2. Server chooses price/currency and creates a purchase reference.
3. Provider adapter creates hosted checkout; CREDALYX persists the provider session, purchase reference and idempotency key.
4. `payment.succeeded` must match the persisted provider, purchase, agent, amount and currency.
5. PostgreSQL re-checks that the agent does not already have an active unexpired passport.
6. Purchase + passport + sale ledger + pending referral commission are committed atomically.

The current adapter is no-money sandbox only. Production startup fails closed until a licensed-provider adapter is configured with provider-native signature verification.

## Ledger and referral lifecycle

Ledger convention: positive amounts are debits, negative amounts are credits. Every transaction sums to zero per currency.

Accounts are scoped:

- platform accounts use `(platform, platform)`;
- referral balances use `(agent, <referrer internal id>)`.

PostgreSQL seals a transaction only after checking it contains at least two entries and balances. After sealing, entries cannot be added, updated or deleted.

Referral lifecycle:

1. Successful referred sale credits `agent_owner_pending_balance`.
2. Reward remains pending until `hold_until`.
3. Release worker selects eligible rows using `FOR UPDATE SKIP LOCKED` and posts a new balanced `commission_release` transaction moving pending -> available.
4. Refund or chargeback posts a new balanced reversal transaction, revokes the linked passport and marks the commission reversed.
5. If a reward was already released, reversal debits available balance. Future payout logic must block withdrawal while ledger-derived debt is positive.

Wallet APIs derive balances from sealed ledger entries. Commission rows provide lifecycle metadata but are not the authoritative mutable balance.

## Payout policy boundary

`MIN_PAYOUT_MINOR` is configurable and defaults to USD 25.00 for batching. It is an operational default, not a legal conclusion. Real payout onboarding, sanctions/eligibility checks, payout initiation and reconciliation are not enabled until a provider-managed payout adapter exists.

## A2A interoperability

A2A v1.0 discovery is exposed with `supportedInterfaces[]`. The current Agent Card advertises only the passport-verification skill. Full task/message handling and TCK conformance are intentionally not claimed yet.

## Data minimization

Public agent and passport responses contain technical agent metadata only. Owner identity is not embedded into passports. Verification evidence is referenced rather than copied into public objects. Payment card data is never accepted by CREDALYX endpoints.

## Evolution

Persistence and payment layers are interfaces. Provider, price, commission, hold window, payout threshold and issuer implementation are configuration/injected adapters rather than hard-coded business assumptions. Cursor pagination, payout orchestration, Level 2/3 verification, KMS signing and UI/SDKs are subsequent milestones.
