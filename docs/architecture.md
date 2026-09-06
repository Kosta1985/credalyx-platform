# Architecture — Agent Passport Network

## Product understanding

The platform is a trust layer for software agents. Owners register agents, prove control of an agent key/endpoint, optionally complete stronger organization verification, purchase an internal Agent Passport, and use the passport as a signed, revocable credential during Agent-to-Agent interactions.

The passport is not a legal identity document or regulatory licence. Payment custody, recipient onboarding and payouts remain with a licensed payment provider; CREDALYX keeps an immutable accounting ledger of platform obligations and events.

## Proposed bounded contexts

1. Identity & tenancy — users, organizations, memberships, RBAC/ABAC.
2. Agent registry — agents, endpoints, capabilities, keys and key rotation.
3. Verification — control challenges, evidence and decisions.
4. Passport issuer — signed credential issuance, expiry, suspension and revocation.
5. Trust gateway — A2A discovery, request signing, nonce/timestamp replay defense and scoped authorization.
6. Commerce — checkout sessions, payment events, refunds and disputes.
7. Ledger — immutable double-entry accounting and reconciliation.
8. Referral & payouts — attribution, hold periods, reversals, risk controls and provider-managed payouts.
9. Audit & risk — append-only privileged events, fraud signals and incident handling.

## Trust boundaries

- Browser/client data is always untrusted.
- Agent endpoints are untrusted until challenge-response ownership is proven.
- Payment state is authoritative only after verified provider webhooks.
- Internal services do not trust tenant identifiers supplied by clients; tenant scope is derived from authenticated membership.
- Public passport verification exposes minimal credential status only.

## Initial deployment shape

Start as a modular monolith with strict domain boundaries. This minimizes distributed-system complexity while keeping modules separable later. PostgreSQL is the source of truth; Redis is reserved for short-lived replay data, jobs and rate-limiting coordination. S3-compatible storage is used only for evidence artifacts that cannot remain in PostgreSQL.

## Cryptography

- Passport signing: Ed25519.
- Agent control: agent signs server-issued random challenge with registered public key.
- Request authentication: canonical request signature covering method, path, body digest, timestamp and nonce.
- Replay window: short timestamp window plus nonce uniqueness.
- Key material: production issuer private keys belong in cloud KMS/HSM-backed key management, never source code or database plaintext.

## Financial model

Amounts are integer minor units with explicit currency. Each ledger transaction is immutable, idempotent and balanced. Refunds, disputes and corrections are represented with compensating entries. Referral commission first enters pending liability and can become available only after configurable risk hold and eligibility checks.

Price and referral commission are configuration/policy data, not hard-coded commercial assumptions in the final production implementation.

## MVP vertical slice

1. Register agent.
2. Create one-time challenge.
3. Verify agent control.
4. Receive verified sandbox `payment.succeeded` webhook.
5. Issue Ed25519-signed passport.
6. Record balanced sale and pending referral commission.
7. Publicly verify passport status/signature.
8. Revoke passport and make further verification fail.

## Known MVP limitations

Current sandbox foundation uses in-memory repositories and a simplified sandbox webhook signature seam. It is intentionally not production persistence. PostgreSQL migrations, real asymmetric agent challenge verification, provider SDK integration, authentication/tenant middleware, audit persistence, hold/reversal jobs and KMS-backed issuer keys are the next implementation steps before any production use.
