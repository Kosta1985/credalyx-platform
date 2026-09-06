# Payout Threat Model

This document extends the platform threat model for the payout boundary.

## Assets

- referral reward entitlement;
- available, reserved and debt ledger state;
- payout beneficiary/provider account association;
- payout provider identifiers and lifecycle status;
- payout idempotency keys;
- provider webhook authenticity/idempotency;
- risk decisions and audit history.

## Threats and controls

### Double withdrawal / concurrent payout requests

**Threat:** two requests observe the same available balance and both send provider payouts.

**Controls:** provider submission occurs only after PostgreSQL reservation; per-agent advisory transaction lock; in-transaction available/debt re-check; one-open-payout partial unique index; sealed `available -> reserved` ledger transaction.

### Idempotent retry becomes a second request

**Threat:** retry is evaluated against changed risk/open-payout state or creates another reservation.

**Controls:** deterministic payout reference from agent + client idempotency key is resolved before new risk evaluation; existing payout is returned/resubmitted idempotently rather than creating a second reservation.

### Beneficiary substitution

**Threat:** attacker supplies another owner/organization's provider payout account.

**Controls:** payout account lookup is tenant-scoped; PostgreSQL trigger independently verifies payout account owner/organization matches the agent and provider matches the payout row.

### Provider payout submission failure

**Threat:** internal available balance is consumed although provider never accepted the payout.

**Controls:** internal funds are first reserved, not paid; submission exception creates `reserved -> available` compensating ledger transaction and marks payout failed.

### Forged payout success/failure webhook

**Threat:** attacker settles or releases reserved funds without provider authority.

**Controls:** current sandbox uses timestamped canonical HMAC with a payout-specific secret; provider/event deduplication; payout reference/provider payout ID/amount/currency correlation. Production requires provider-native signature verification.

### Webhook replay

**Threat:** duplicate `payout.paid` or `payout.failed` posts multiple settlement/release transactions.

**Controls:** unique `(provider, provider_event_id)`, final-state checks, deterministic ledger idempotency keys.

### Chargeback while payout is processing

**Threat:** referral entitlement is reversed after money was reserved, hiding debt or allowing another withdrawal.

**Controls:** chargeback posts to available balance independently; reserved balance remains isolated; payout success consumes only reserved funds; resulting available debt remains and hard-blocks future payouts.

### Failed payout after chargeback

**Threat:** release of reservation could create inconsistent balances.

**Controls:** failure posts `reserved -> available`; if available was already in debt, the returned funds naturally offset that debt. Chargeback history remains immutable.

### Payout velocity / cash-out abuse

**Threat:** rapid withdrawals reduce the fraud-recovery window.

**Controls:** persisted risk assessment; 24-hour velocity review; one open payout per agent; referral hold window; recent reversal exposure review; configurable auto-approval ceiling.

### Very large payout

**Threat:** abnormal-value payout bypasses manual controls.

**Controls:** configurable auto-approval maximum; amounts above it receive `review`, not automatic submission.

### Wallet debt ignored

**Threat:** owner withdraws while chargeback/refund debt exists.

**Controls:** risk hard-denies any positive ledger-derived debt; reservation transaction re-checks available/debt under lock.

### Incomplete/changed provider onboarding

**Threat:** payout proceeds to an unverified/restricted recipient.

**Controls:** current onboarding status must be `complete`; account is locked/re-read during reservation. Production provider remains authoritative for recipient eligibility.

### Cross-tenant payout read/write

**Threat:** IDOR on payout account, payout list, detail or creation routes.

**Controls:** agent ownership/organization authorization before all payout owner routes; payout detail additionally checks internal agent ID.

### Real-money sandbox misuse

**Threat:** sandbox implementation is accidentally enabled in production.

**Controls:** production configuration requires managed payout provider; current build fails closed because no managed adapter is installed; sandbox provider contains no real credentials or money-movement API.

## Required continuous tests

- two simultaneous payout reservations for one agent -> exactly one succeeds;
- retry with same idempotency key returns the original payout;
- same idempotency key with conflicting parameters is rejected;
- another open payout blocks a new payout;
- cross-owner payout account insertion is rejected by PostgreSQL trigger;
- payout success clears reserved and records paid state once;
- payout failure clears reserved and restores available once;
- duplicate provider events create no additional ledger effects;
- provider event amount/provider/payout-ID mismatch is rejected;
- chargeback while payout processing creates debt that survives payout settlement;
- debt blocks next payout;
- recent reversal/velocity/high-value request requires review;
- below-minimum/onboarding-incomplete/inactive-agent request is denied;
- sandbox payout provider cannot be selected in production.
