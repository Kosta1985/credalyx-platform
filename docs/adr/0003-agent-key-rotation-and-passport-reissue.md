# ADR-0003: Agent key rotation and passport reissue

Status: Accepted

## Context

An Agent Passport references an agent verification key. A long-lived system cannot treat that key as an immutable `current` pointer: keys are rotated operationally, may be suspected compromised, and must remain historically resolvable for audit and verification.

A naive public-key overwrite creates several security failures:

- an attacker with only the account session could replace the agent key without proving control of either key;
- an attacker with only the proposed new private key could attempt to seize an agent record;
- an old challenge could be replayed after a key change;
- existing passports could silently resolve to a different key than the one they originally referenced;
- destructive updates would erase the evidence needed to investigate compromises.

## Decision

CREDALYX uses versioned Ed25519 agent keys with deterministic public identifiers derived from the SHA-256 fingerprint of the SPKI DER representation.

### Control challenges

Agent-control challenges bind to the exact active key ID. A challenge issued for a previous key is invalid after rotation.

### Normal rotation

Normal key rotation is a two-proof protocol:

1. The authenticated owner requests a rotation challenge and supplies the proposed Ed25519 public key.
2. CREDALYX persists a pending rotation containing the current key, proposed fingerprint, proposed public key, one-time challenge digest and expiry.
3. The client signs the exact canonical rotation payload with both the current private key and the proposed new private key.
4. CREDALYX validates both signatures before any key state changes.
5. PostgreSQL atomically revokes the previous key and inserts the new active key.

Only one active key and one pending rotation are permitted per agent.

### Passport impact

An Agent Passport references a specific immutable key ID. It never references a floating `current` alias.

If a valid active passport exists during key rotation, the rotation transaction also:

- revokes the previous passport version;
- creates a new signed passport version referencing the new key;
- preserves the original passport expiry;
- preserves the original purchase association;
- requires no second payment;
- records passport status history and an audit event.

Historical passport rows remain available for audit and status verification.

### Emergency revocation

An authenticated owner can emergency-revoke a known key. If the revoked key is currently active, the system suspends the agent and revokes active passports. Emergency revocation deliberately does not auto-install a replacement key.

A future account-recovery workflow will define the stronger step-up/manual controls required when the current private key has been lost and normal dual-proof rotation is impossible.

## Consequences

### Positive

- key takeover requires stronger evidence than ordinary account possession;
- old challenges cannot authorize a new key;
- passports remain cryptographically bound to the key version they were issued against;
- rotation does not create a second commercial purchase;
- compromise response is explicit and auditable;
- historical verification material is retained.

### Costs and limitations

- normal rotation requires access to both old and new private keys;
- owner recovery after loss of the old private key needs a separate high-assurance process;
- credential lifecycle has its own transactional persistence boundary in addition to the commerce store;
- production issuer signing still needs to move behind KMS/HSM key versioning.
