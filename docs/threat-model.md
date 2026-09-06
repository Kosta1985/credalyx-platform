# Threat Model

## Assets

- agent identity and key state;
- passport signing authority;
- verification decisions/evidence references;
- payment event integrity;
- immutable ledger history;
- referral attribution and payout entitlement;
- tenant/private owner data;
- administrative audit history.

## Primary threats and current controls

### Agent impersonation
Threat: attacker registers or presents an API key and claims control of another agent.
Controls: Ed25519 key validation, proof-of-possession challenge, agent-bound signed payload, single-use/expiry, key reference in passport.

### Challenge replay / race
Threat: reuse a previously valid proof or submit concurrent verification calls.
Controls: hashed challenges, expiry, atomic consume condition in PostgreSQL, signature verified before challenge consume.

### Tenant breakout / IDOR
Threat: authenticated owner mutates another owner/organization's agent.
Controls: owner subject bound from trusted auth adapter; organization ID is authorization-checked; resource mutation re-checks ownership.
Remaining: persist and enforce full organization membership matrix for every upcoming endpoint.

### Forged or stale passport
Threat: fabricated credential or revoked passport remains trusted.
Controls: Ed25519 signature, issuer binding, expiry, public live status, revocation history.
Remaining: managed issuer-key rotation and public key-version discovery.

### Webhook forgery/replay
Threat: frontend calls payment-success route or repeats a real provider event.
Controls: no frontend payment confirmation; sandbox timestamped HMAC; provider/event unique idempotency; purchase/ledger transaction in DB transaction.
Remaining: implement raw-body verification per selected real provider.

### Ledger tampering
Threat: edit/delete historical finance rows or append later entries to alter a past transaction.
Controls: minor-unit integers; application balance checks; PostgreSQL one-time sealing balance check; sealed entry insert guard; UPDATE/DELETE triggers; idempotency key.

### Referral abuse
Threat: self-referral, same-owner farming, repeated refunds, synthetic agent farms.
Controls: common-owner self-referral rejection, single attribution record, locked attribution at purchase, pending commission status and hold timestamp.
Remaining: IP/device/velocity signals, graph/ring detection, refund/chargeback reversal, payout onboarding/risk review.

### SSRF through agent endpoint
Threat: platform probes internal/cloud metadata endpoint supplied by owner.
Controls now: registration stores endpoint only and requires HTTPS in production; no server-side fetch exists yet.
Required before endpoint probing: DNS/IP resolution policy, private/link-local/metadata deny list, redirect revalidation, egress proxy and response limits.

### Key compromise
Threat: issuer or agent private key stolen.
Controls: no private agent keys stored; production refuses ephemeral issuer key configuration.
Remaining: KMS/HSM issuer operations, key versioning, rotation and emergency revocation runbook.

## Abuse cases to test continuously

- wrong-key agent signature;
- valid signature bound to wrong agent ID;
- expired/replayed challenge;
- cross-tenant mutation;
- duplicate payment event;
- payment amount mismatch;
- unbalanced ledger transaction;
- append to sealed ledger transaction;
- revoked passport verification;
- same-owner referral;
- refund after commission becomes pending/available;
- simultaneous refund and payout attempts.
