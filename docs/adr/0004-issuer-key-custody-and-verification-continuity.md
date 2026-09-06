# ADR-0004: Issuer key custody and verification continuity

Status: Accepted

## Context

CREDALYX Agent Passports are platform-signed credentials. A single process-local PEM key is not an acceptable long-term production custody model, and replacing that key without versioning would make previously issued passports unverifiable.

Two separate concerns must therefore be modeled explicitly:

1. **signing custody** — the component permitted to use the issuer private key; and
2. **public verification registry** — durable metadata required to verify credentials after the active signing key changes.

The public registry must never become a private-key store.

## Decision

### Signing backend boundary

Passport signing uses an asynchronous `IssuerSigningBackend` interface. Callers provide a key ID and payload and receive a signature. The interface exposes public key metadata but has no method that exports private-key material.

The current `LocalEd25519IssuerBackend` is development/test only. It proves the contract and permits deterministic tests. Production configuration requires a managed backend suitable for cloud KMS, HSM or another non-exportable signing service.

### Issuer key identity

Every Ed25519 issuer key receives a deterministic external ID:

`issuer_ed25519_<base64url(SHA-256(SPKI DER))>`

The identifier is derived from public key material, so it can be independently recomputed and cannot be reassigned to different public key bytes without a collision.

### Public registry

PostgreSQL stores only:

- key ID;
- algorithm;
- public PEM;
- public JWK;
- provider name;
- opaque provider key reference;
- active/retired/revoked status and timestamps.

It contains no private-key column. Status changes are recorded in append-only `issuer_key_status_history`.

Exactly one issuer key may have `active` status.

### Passport schema 1.1

New Agent Passports include signed `issuer_key_id` and use `schema_version = 1.1`.

Verification of schema 1.1 credentials resolves that exact key. A retired issuer key remains valid for historical verification. A revoked issuer key fails verification, because revocation represents loss of trust in signatures attributed to that key.

Schema 1.0 credentials created before the signed issuer-key claim remain supported by testing the signature against all retained non-revoked verification keys.

### Rotation continuity

Rotation does not rewrite existing credentials. The old issuer key becomes `retired`, remains publicly discoverable, and the new key becomes `active`. New passports bind to the new key while old passports continue to verify against the retired key.

If an issuer key is later marked `revoked`, it is removed from JWKS and credentials that identify it fail live verification.

### Public discovery

The service exposes:

- `/.well-known/agent-passport-issuer.json` — issuer metadata and active key ID;
- `/.well-known/jwks.json` — active and retired non-revoked Ed25519 public JWKs;
- `/v1/issuer/keys/{key_id}` — exact key metadata/status.

No discovery response exposes provider credentials or private key bytes.

## Consequences

### Positive

- runtime signing can migrate to KMS/HSM without redesigning passport issuance;
- old credentials remain verifiable after normal rotation;
- exact issuer key provenance is cryptographically bound into new passports;
- public verification can be performed without access to signing custody;
- key compromise can invalidate credentials by revoking the affected issuer key;
- source code and PostgreSQL do not need production issuer private keys.

### Costs and limitations

- production still needs a concrete managed signing-provider adapter;
- issuer-key rotation/revocation requires operational authorization and runbooks before production;
- schema 1.0 verification is necessarily less precise because it did not sign an issuer key identifier;
- JWKS consumers must respect live key status/revocation rather than caching indefinitely.
