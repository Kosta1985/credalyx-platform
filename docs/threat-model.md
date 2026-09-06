# Threat Model

## Assets

- agent identity and versioned agent-key state;
- pending agent-key rotation challenges/proofs;
- issuer signing authority and issuer public-key history;
- passport signatures, issuer-key attribution and passport version history;
- verification decisions/evidence references;
- checkout/payment-event integrity;
- immutable ledger history;
- referral attribution, commission state and payout entitlement;
- tenant/private owner data;
- administrative audit history.

## Primary threats and current controls

### Agent impersonation
Threat: attacker claims control of another agent.
Controls: Ed25519 public-key validation, one-time proof-of-possession challenge, agent/key-bound payload, expiry/replay protection, exact key reference in passports.

### Stale agent challenge after key rotation
Threat: proof created under an old agent key is submitted after rotation.
Controls: challenge stores the exact `agent_key_id`; verification requires that key to still be current and active.

### Unauthorized agent-key replacement
Threat: account/session compromise replaces the agent key without cryptographic proof.
Controls: normal rotation requires signatures from both current and proposed new private keys over one rotation-specific payload; activation occurs atomically after both proofs pass.

### Agent-key rotation race
Threat: concurrent rotations create multiple active keys.
Controls: PostgreSQL one-active-key and one-pending-rotation partial unique indexes plus row locking/re-checks.

### Agent key-history substitution
Threat: historical passport resolves against a newer agent public key.
Controls: deterministic SHA-256 SPKI key IDs, signed exact key references and retained historical key rows.

### Tenant breakout / IDOR
Threat: owner mutates another tenant's agent/credential/commerce state.
Controls: JWT subject/organization authorization and resource ownership checks on control, checkout, wallet, agent-key rotation/revoke and passport revoke routes.
Remaining: full organization/admin/payout authorization matrix.

### Forged or stale passport
Threat: fabricated, expired or revoked credential remains trusted.
Controls: Ed25519 signature, issuer binding, issuer-key resolution, expiry, public live passport status, revocation history and transactional issuance preconditions.

### Issuer key substitution
Threat: a passport signed by issuer key A is silently verified with key B after issuer rotation.
Controls: schema 1.1 signs `issuer_key_id`; IDs are SHA-256 SPKI fingerprints; verification resolves the exact registered key.

### Issuer key rotation destroys historical verification
Threat: old passports stop verifying after normal issuer rotation.
Controls: old issuer keys become `retired`, not deleted; public PEM/JWK remains in PostgreSQL/JWKS; retired non-revoked keys remain valid for verification.

### Issuer private-key exfiltration from application/database
Threat: production private key is copied from source, DB, logs or API responses.
Controls: `IssuerSigningBackend` exposes sign-by-key-ID and public metadata only; issuer registry schema has no private-key field; JWKS/public descriptors expose public parameters only; production configuration rejects local PEM custody.
Remaining: concrete managed KMS/HSM provider adapter and operational access policy.

### Issuer key compromise
Threat: signatures from a stolen/misused issuer key remain trusted.
Controls: issuer keys have active/retired/revoked lifecycle; a revoked key is excluded from JWKS and passports naming it fail live verification; status transitions are persisted.
Remaining: authenticated operational rotation/revocation tooling, incident runbook and managed-provider audit integration.

### Split-brain issuer signing keys
Threat: multiple issuer keys are simultaneously considered active.
Controls: backend initialization requires exactly one active key; PostgreSQL has a global one-active-issuer-key partial unique index; service compares registry active key with backend active key before issuing.

### Registry/backend mismatch
Threat: signing backend uses a key whose public metadata is missing or different from the registry.
Controls: initialization syncs public keys, issue path re-checks active key ID/public PEM/status before signing.

### Schema 1.0 ambiguity
Threat: legacy passports do not contain a signed issuer key ID.
Controls: legacy verification tries all retained non-revoked issuer verification keys and still verifies the original signature/issuer/expiry/live status. New issuance is schema 1.1 only.
Limitation: schema 1.0 cannot provide the same exact signed issuer-key attribution as 1.1.

### Passport/agent-key mismatch after agent rotation
Threat: active passport continues pointing at a revoked agent key.
Controls: normal agent-key rotation atomically revokes the old passport and creates next passport version against the new key while preserving original purchase/expiry.

### Lost/compromised active agent private key
Threat: normal dual-proof rotation is impossible or unsafe.
Controls: emergency owner revocation suspends agent and revokes active passports without auto-trusting a replacement key.
Remaining: high-assurance recovery with step-up/manual review.

### Fabricated payment success
Threat: attacker invents payment success and receives a passport.
Controls: server-created checkout, persisted purchase reference, server-selected price/currency, provider/session/agent/amount/currency correlation and provider-event idempotency.
Remaining: real provider raw-body signature verification.

### Webhook replay / duplicate financial action
Controls: unique `(provider, provider_event_id)`, unique purchase reference, deterministic ledger idempotency keys and source purchase status checks.

### Ledger tampering
Controls: integer minor units, balance checks, one-time sealing, database insert/update/delete guards, compensating corrections only.

### Refund/chargeback leaves usable credential/reward
Controls: reversal locks source purchase, posts compensating ledger transaction, revokes linked passport and reverses referral commission according to pending/available state.

### Referral abuse
Controls: same-owner self-referral rejection, one attribution per referred agent, attribution lock at purchase, reward hold and reversal.
Remaining: device/IP/velocity/graph signals and manual payout review.

### Commission release races
Controls: `FOR UPDATE SKIP LOCKED`, deterministic release idempotency key and same-transaction state change.

### SSRF through agent endpoint
Controls now: HTTPS required in production and no server-side endpoint probe exists yet.
Required before probing: DNS/IP policy, private/link-local/metadata deny list, redirect revalidation, egress proxy and response limits.

## Abuse cases to test continuously

- wrong-key agent signature / wrong agent ID;
- expired/replayed/stale-key challenge;
- agent rotation missing either old-key or new-key proof;
- simultaneous agent rotations;
- old agent passport remains valid after agent-key rotation;
- agent-key reissue extends paid expiry;
- emergency active-key revoke without agent suspension/passport revoke;
- cross-tenant credential mutation;
- issuer backend exposes private key/JWK `d` parameter;
- issuer registry contains private key material;
- issuer rotation removes retired key or breaks old-passport verification;
- new passport lacks `issuer_key_id`;
- multiple active issuer keys;
- registry active key differs from backend active key;
- passport naming revoked issuer key verifies successfully;
- revoked issuer key appears in JWKS;
- schema 1.0 historical passport cannot verify against retained key set;
- signed payment without persisted checkout;
- payment agent/amount/currency mismatch;
- duplicate payment/refund/chargeback events;
- concurrent payment success for one agent;
- unbalanced or mutated sealed ledger transaction;
- refund/chargeback after commission pending/available;
- simultaneous commission release workers;
- same-owner referral;
- future simultaneous chargeback and payout reservation.
