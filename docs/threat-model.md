# Threat Model

## Assets

- agent identity and key state;
- passport signing authority;
- verification decisions/evidence references;
- checkout intent and payment-event integrity;
- immutable ledger history;
- referral attribution, commission state and payout entitlement;
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
Threat: authenticated owner mutates or monetizes another owner/organization's agent.
Controls: owner subject bound from trusted auth adapter; organization ID is authorization-checked; challenge, checkout, wallet and revocation routes re-check resource ownership.
Remaining: complete organization lifecycle and authorization matrix for all future admin/payout endpoints.

### Forged or stale passport
Threat: fabricated credential, double issuance, or revoked passport remains trusted.
Controls: Ed25519 signature, issuer binding, expiry, public live status, revocation history, active-passport precondition at checkout and re-check inside purchase transaction.
Remaining: managed issuer-key rotation and public key-version discovery.

### Fabricated payment success
Threat: attacker with frontend access or leaked webhook capability invents a payment event and gets a passport without a real checkout intent.
Controls: server-created checkout, persisted purchase reference, server-selected price/currency, provider/session/agent/amount/currency correlation, webhook signature verification and provider-event idempotency.
Remaining: selected production provider must verify its native signature over the required raw request representation.

### Webhook replay / duplicate financial action
Threat: provider retry or attacker repeats success/refund/chargeback event.
Controls: unique `(provider, provider_event_id)`, unique purchase reference, unique ledger idempotency keys, source-purchase status checks and transactional processing.

### Ledger tampering
Threat: edit/delete historical finance rows or append later entries to alter a past transaction.
Controls: minor-unit integers; application balance checks; PostgreSQL one-time sealing balance check; sealed-entry insert guard; UPDATE/DELETE triggers; corrections use new compensating transactions.

### Refund / chargeback leaves usable credential
Threat: refunded purchase still has valid passport or referral reward.
Controls: explicit passport-to-purchase link; reversal locks source purchase, posts balanced compensating ledger transaction, revokes linked passport and marks associated commission reversed.

### Referral abuse
Threat: self-referral, same-owner farming, repeated refunds, synthetic agent farms or ring referrals.
Controls: common-owner self-referral rejection, one attribution record per referred agent, attribution lock at purchase, pending commission hold, refund/chargeback reversal and payout threshold.
Remaining: device/IP/velocity signals, graph/ring detection, recipient onboarding and manual payout-risk review.

### Commission release races
Threat: multiple workers release the same pending reward twice.
Controls: eligibility query uses `FOR UPDATE SKIP LOCKED`; ledger release has deterministic idempotency key; commission state changes inside the same PostgreSQL transaction.

### Post-release chargeback / negative withdrawable balance
Threat: reward becomes available, then underlying purchase reverses.
Controls: reversal debits the ledger account matching current commission state; wallet derives available/debt from ledger; payout eligibility requires zero debt.
Remaining: payout reservation must atomically lock available funds before provider payout initiation.

### SSRF through agent endpoint
Threat: platform probes internal/cloud metadata endpoint supplied by owner.
Controls now: registration stores endpoint only and requires HTTPS in production; no server-side fetch exists yet.
Required before endpoint probing: DNS/IP resolution policy, private/link-local/metadata deny list, redirect revalidation, egress proxy and response limits.

### Key compromise
Threat: issuer or agent private key stolen.
Controls: no private agent keys stored; production refuses ephemeral issuer keys and sandbox payment provider.
Remaining: KMS/HSM issuer operations, key versioning, rotation and emergency revocation runbook.

### Payment/payout economics abuse
Threat: many low-value rewards create disproportionate payout fees or automated payout churn.
Controls: configurable hold and minimum payout threshold; no real payout endpoint is enabled yet.
Remaining: batching policy, provider fee reconciliation, recipient eligibility and country/tax policy.

## Abuse cases to test continuously

- wrong-key agent signature;
- valid signature bound to wrong agent ID;
- expired/replayed challenge;
- cross-tenant checkout/wallet/revocation;
- signed payment without a persisted checkout;
- payment agent/amount/currency mismatch;
- duplicate payment event;
- concurrent payment success for one agent;
- unbalanced ledger transaction;
- append/update/delete sealed ledger entries;
- refund/chargeback after commission pending or available;
- duplicate refund/chargeback event;
- simultaneous commission release workers;
- revoked passport verification;
- same-owner referral;
- future simultaneous chargeback and payout reservation.
