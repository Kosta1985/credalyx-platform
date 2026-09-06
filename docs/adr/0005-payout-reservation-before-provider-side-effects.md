# ADR-0005: Reserve payout funds before provider side effects

Status: Accepted

## Context

Referral rewards become withdrawable only after the hold window. A payout request creates a race between the internal ledger, provider money movement, refunds/chargebacks and repeated client requests. Sending a provider payout before locking the internal entitlement would permit two concurrent requests to withdraw the same available balance.

A payout can also fail after reservation or be completed after a new chargeback has created debt. Historical ledger entries must not be rewritten to hide either event.

## Decision

### Provider-managed beneficiary onboarding

CREDALYX stores only provider account identifiers and onboarding state. Production KYC/KYB/recipient verification is delegated to the selected payout provider. An individual owner or organization can own a payout account, never both on the same row.

A database trigger validates that the payout account beneficiary matches the agent owner/organization and that the payout provider matches the account provider.

### Reservation before provider submission

A payout has three accounting transitions:

1. **Reservation** — `agent_owner_available_balance -> agent_owner_reserved_balance`.
2. **Success** — `agent_owner_reserved_balance -> payment_provider_clearing`.
3. **Failure** — `agent_owner_reserved_balance -> agent_owner_available_balance`.

Every transition is a new balanced, sealed ledger transaction. No balance column is decremented in place.

PostgreSQL takes a per-agent advisory transaction lock and re-checks available balance, debt, onboarding and open-payout state immediately before inserting the payout/reservation. A partial unique index also permits only one `pending`/`processing` payout per agent.

### Provider side effects

The external provider is called only after the reservation commits. Provider submission uses an idempotency key derived from the authenticated agent and client key. If submission throws before a provider payout is accepted, the reservation is released with a compensating ledger transaction and the payout becomes `failed`.

The no-money sandbox provider always returns `processing`; signed provider webhook events transition it to `paid` or `failed`.

### Webhook reconciliation

Provider events are unique by `(provider, provider_event_id)`. The event must match the stored payout reference, provider payout ID, amount and currency. A final payout state is not re-applied.

Success consumes reserved funds. Failure releases reserved funds. Duplicate events are acknowledged without new financial effects.

### Chargeback while payout is in flight

A chargeback can debit the available wallet after funds have already been reserved. The reserved payout remains isolated. If the provider later pays it, settlement clears only the reserved balance; newly created wallet debt remains visible and blocks subsequent payouts.

If the provider fails the payout instead, releasing the reservation credits available balance and can naturally offset the debt. This is an accounting consequence, not a mutation of the chargeback history.

### Risk gate

Each new payout request receives a persisted risk assessment. Hard denials include:

- inactive/unverified agent;
- incomplete beneficiary onboarding;
- amount below minimum;
- debt;
- insufficient available funds;
- another open payout.

Manual-review signals include payout velocity, recent reversal exposure and amount above the auto-approval ceiling. A near-full-balance withdrawal is a low-grade score signal but does not by itself force review.

A future risk service/manual-review queue can replace or enrich the deterministic policy without changing reservation accounting.

## Consequences

### Positive

- concurrent requests cannot spend the same available reward;
- provider failure cannot strand a hidden internal deduction;
- chargeback debt remains visible even when a previously reserved payout settles;
- provider webhook replay is financially idempotent;
- payout state and ledger state can be reconciled independently;
- beneficiary substitution is blocked at the database boundary;
- provider onboarding remains outside CREDALYX custody.

### Costs / limitations

- production still needs a licensed/appropriate payout provider adapter and provider-native webhook verification;
- `review` decisions currently block automatic payout and require a future manual-review workflow;
- partial payouts/refunds, payout cancellation and provider reconciliation jobs need later policy/runbooks;
- the sandbox adapter moves no real money and is rejected by production configuration.
