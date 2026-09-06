# Architecture — Agent Passport Network

## Product boundary

CREDALYX provides a private-sector trust credential for software agents. The credential communicates platform-observed verification state; it does not assert governmental identity, licensing, KYC or regulatory approval. The internal wallet is a double-entry accounting view, not a bank account or stored-value product.

## Architecture style

The MVP is a **modular monolith with explicit domain boundaries** and PostgreSQL transaction boundaries for critical financial and credential operations. Passport issuance, purchase finalization, referral commission creation and ledger posting are atomic. Refunds and chargebacks are separate compensating transactions rather than mutations of historical finance rows. Agent key rotation is also transactional: a new key is not activated until dual cryptographic proof succeeds and all passport/version updates can commit together.

Logical modules:

1. Identity / tenancy
2. Agent registry
3. Agent credential lifecycle and endpoint control verification
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
- **API -> PostgreSQL:** financial and credential-state writes occur inside transactions; sealed ledger history is DB-protected.
- **Passport issuer key:** production target is KMS/HSM. Repository contains no production issuer secret.
- **Agent endpoint:** untrusted network destination. Endpoint probing must use SSRF-safe egress policy before it is introduced.

## Agent key identity

Every Ed25519 verification key has a deterministic external key ID:

`key_ed25519_<base64url(SHA-256(SPKI DER))>`

The public fingerprint, rather than a mutable label such as `primary`, is the identity exposed in challenge responses and passport claims. Database rows retain internal UUIDs for referential integrity.

Historical key rows are never overwritten. Rotation marks the previous key revoked and appends the replacement key. A historical passport can therefore resolve the exact verification key it originally referenced.

## Agent control protocol

1. Owner registers an Ed25519 public key and HTTPS A2A endpoint.
2. API resolves the exact current key and returns a 256-bit random challenge plus canonical signing payload containing `agent_id`, `key_id` and challenge.
3. Agent signs the payload with the private key matching that exact key ID.
4. API verifies the signature against the bound public key.
5. PostgreSQL atomically consumes the challenge only if the bound key is still the current active key and raises verification to Level 1.
6. Replay, expired, stale-key or revoked-key challenges fail.

## Agent key rotation

Normal rotation is intentionally stronger than authenticated account access alone.

1. Authenticated owner submits a proposed new Ed25519 public key.
2. Server validates the key, computes its deterministic fingerprint and creates one pending rotation with a random challenge and expiry.
3. Rotation signing payload includes the agent ID, rotation ID, old key ID, new key ID and one-time challenge.
4. Client produces **two signatures over the same payload**: one using the current private key and one using the proposed new private key.
5. Both signatures are verified before the persistence transaction starts.
6. PostgreSQL locks the rotation/current key, confirms it has not changed, revokes the old key and activates the new key atomically.
7. A partial unique index allows only one active key per agent, and another allows only one pending rotation.

A proposed key is not inserted as active before completion. This prevents a half-created rotation from changing live trust state.

## Emergency key revocation and recovery boundary

Emergency revocation is allowed for an authenticated owner when a specific key is suspected compromised. If that key is currently active:

- the key is marked revoked;
- the agent status becomes `suspended`;
- all active passports are revoked;
- the agent remains publicly/readably addressable using historical metadata;
- no replacement key is trusted automatically.

The lifecycle-aware PostgreSQL runtime store deliberately falls back to the latest historical key when no active key exists so audit/status/recovery routes can still resolve the suspended agent. Credential-issuing routes separately require an eligible non-suspended state and an active key.

Installing a replacement key after loss of the old private key is **not** normal rotation and remains a future high-assurance recovery workflow requiring step-up authentication and/or manual review.

## Passport

The passport uses Ed25519 over deterministic canonical JSON claims. Claims contain no owner email/name. Public status is resolved separately, so revocation takes effect without modifying the signed historical credential.

Each passport includes:

- immutable `passport_id`;
- monotonically increasing `passport_version` for non-commercial credential reissue;
- exact agent key reference containing the deterministic key ID;
- issuer, verification level, capabilities, issue/expiry timestamps and status reference.

### Passport reissue after agent key rotation

Normal agent key rotation must not silently leave an active passport pointing at a revoked key. If an active passport exists, the same database transaction:

1. locks the active passport;
2. verifies the proposed replacement is the next passport version;
3. verifies the replacement preserves the original expiry;
4. revokes the old passport version and appends status history;
5. inserts the replacement passport referencing the new key;
6. preserves the original purchase association;
7. does **not** create a second payment, purchase or referral commission.

Production issuer-key requirements remain separate:

- stable issuer key ID/version;
- managed private-key custody;
- rotation overlap;
- public verification-key endpoint/JWKS or equivalent;
- emergency issuer compromise/revocation procedure.

## Checkout and payment correlation

A valid provider signature is necessary but not sufficient to issue a passport.

1. Authenticated owner requests `passport-checkout` for a Level 1-controlled, non-suspended agent.
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

Public agent and passport responses contain technical agent metadata only. Owner identity is not embedded into passports. Verification evidence is referenced rather than copied into public objects. Payment card data and agent private keys are never accepted by CREDALYX endpoints.

## Evolution

Persistence, credential lifecycle, payment and issuer layers are interfaces/adapters. Provider, price, commission, hold window, payout threshold and issuer implementation are configuration/injected dependencies rather than hard-coded business assumptions. Cursor pagination, payout orchestration, Level 2/3 verification, issuer KMS/HSM key versioning, account recovery and UI/SDKs are subsequent milestones.
