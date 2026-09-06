# Architecture — Agent Passport Network

## Product boundary

CREDALYX provides a private-sector trust credential for software agents. It does not assert governmental identity, licensing, KYC or regulatory approval. The internal wallet is an accounting view, not a bank account or stored-value product.

## Architecture style

The MVP is a **modular monolith with explicit domain boundaries** and PostgreSQL transaction boundaries for financial and credential state. Critical modules are intentionally adapter-driven so payment, issuer custody and verification providers can change without rewriting domain rules.

Logical modules:

1. Identity / tenancy
2. Agent registry
3. Agent credential lifecycle
4. Verification workflow
5. Agent Passport issuer + issuer key registry
6. Payment provider adapters
7. Double-entry ledger
8. Referrals / payouts
9. Audit / risk / incidents
10. Public verification and A2A discovery

## Trust boundaries

- **Owner -> API:** verified JWT and server-side tenant authorization.
- **Agent -> API:** Ed25519 proof of possession; static API keys are not proof of agent identity.
- **Payment provider -> API:** provider-specific signed webhook; current sandbox uses timestamped HMAC.
- **API -> PostgreSQL:** transactional financial/credential writes; sealed ledger history is DB-protected.
- **API -> issuer signing backend:** key ID + payload in, signature out. Production target is non-exportable KMS/HSM custody.
- **Public verifier -> issuer registry/JWKS:** public key/status only, with no access to signing custody.
- **Agent endpoint:** untrusted network destination; active probing requires future SSRF-safe egress policy.

## Agent keys

Agent Ed25519 keys use deterministic external IDs:

`key_ed25519_<base64url(SHA-256(SPKI DER))>`

Control challenges bind to the exact active key. Normal rotation requires signatures from both the old and proposed new private keys over one rotation-specific payload. PostgreSQL permits one active key and one pending rotation per agent.

Historical keys are retained. Emergency current-key revocation suspends the agent and revokes active passports without silently trusting a replacement key.

## Passport issuance

Payment and agent-control preconditions are checked before issuance. A successful payment event must correlate to a persisted checkout by provider, purchase, agent, amount and currency. Purchase + passport + sealed sale ledger + pending referral commission commit atomically.

Normal agent-key rotation reissues an active passport without a second commercial purchase. The new passport version preserves original expiry and purchase association and references the replacement agent key.

## Issuer signing key architecture

### Key identity

Issuer Ed25519 keys use a separate deterministic namespace:

`issuer_ed25519_<base64url(SHA-256(SPKI DER))>`

New passports use schema 1.1 and sign `issuer_key_id` into the claims.

### Custody adapter

`IssuerSigningBackend` is asynchronous and exposes:

- current public key descriptor;
- historical public descriptors;
- `sign(keyId, payload)`;
- lifecycle close hook.

There is deliberately no private-key export method. `LocalEd25519IssuerBackend` is development/test only. A production provider can map the same interface to AWS KMS, Google Cloud KMS, Azure Key Vault, an HSM or another non-exportable signing service.

### Public registry

`issuer_signing_keys` stores only public metadata and opaque provider references:

- deterministic key ID;
- public PEM/JWK;
- algorithm;
- provider + provider key reference;
- `active | retired | revoked` status and timestamps.

`issuer_key_status_history` records transitions. A partial unique index guarantees one active issuer key.

At startup the issuer service synchronizes backend public metadata to the registry and verifies that backend/registry agree on the active key before issuing.

### Verification continuity

For schema 1.1, verification resolves the signed exact issuer key ID. `active` and `retired` keys can verify historical credentials; `revoked` keys cannot.

For legacy schema 1.0, which lacked signed issuer key attribution, the verifier tests the signature against retained non-revoked historical issuer keys.

Public discovery:

```text
/.well-known/agent-passport-issuer.json
/.well-known/jwks.json
/v1/issuer/keys/{issuer_key_id}
```

JWKS includes active and retired non-revoked keys only.

## Ledger/referrals

Ledger convention: positive amounts are debits, negative amounts are credits. Every transaction must sum to zero per currency. Sealed transactions/entries cannot be edited or deleted.

Referral lifecycle:

1. referred sale -> pending agent-scoped balance;
2. hold window;
3. concurrency-safe release (`FOR UPDATE SKIP LOCKED`) -> available;
4. refund/chargeback -> compensating transaction and commission reversal;
5. debt blocks future payout eligibility.

Wallet values are derived from sealed ledger entries.

## Production fail-closed behavior

Production requires PostgreSQL, trusted JWT verification, a licensed payment provider adapter and managed issuer custody. The current build intentionally rejects production use because the real payment adapter and concrete managed issuer backend are not yet installed.

Selecting `PASSPORT_ISSUER_BACKEND=managed` requires an opaque provider key reference and currently fails explicitly rather than silently falling back to local/ephemeral PEM signing.

## A2A interoperability

A2A Protocol 1.0 discovery is exposed at `/.well-known/agent-card.json`. The current Agent Card advertises passport verification; full task/message TCK conformance remains later work.

## Data minimization

Passports contain technical agent metadata, not owner email/name. Payment card data, private agent keys and production issuer private keys are never accepted into the public registry/API. Production issuer signing should occur inside managed custody.

## Evolution

Next infrastructure milestones are real payment/payout provider adapters, managed issuer backend implementation/runbook, Level 2/3 verification, SSRF-safe endpoint verification, fraud/risk controls, operational telemetry/recovery, and SDK/web applications.
