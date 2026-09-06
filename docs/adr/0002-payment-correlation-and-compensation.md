# ADR-0002: Correlated checkout and compensating financial events

Status: Accepted

## Context

A signed `payment.succeeded` webhook proves that the payment provider emitted an event, but it does not by itself prove that CREDALYX intended to sell a passport for the referenced agent, amount and currency. Refunds and chargebacks also occur after an immutable sale has already been recorded.

## Decision

1. CREDALYX creates the checkout server-side and persists a purchase reference before accepting payment success.
2. Payment success must match the persisted checkout's provider, agent, amount and currency.
3. Provider event IDs and checkout idempotency keys are unique.
4. Passport issuance, purchase recording, sale ledger entries and referral commission creation are one PostgreSQL transaction.
5. The issued passport is explicitly linked to its purchase.
6. Refunds/chargebacks create new balanced compensating ledger transactions; old ledger rows are never changed.
7. The linked passport is revoked when the purchase is reversed.
8. Referral commission is pending during a configurable hold period, then released into available balance by an idempotent `FOR UPDATE SKIP LOCKED` worker.
9. A later reversal debits the current commission balance state. If the balance has already been paid in a future payout phase, the ledger may represent owner debt while withdrawable balance remains clamped to zero.
10. Real payout operations are not executed until a licensed-provider payout adapter and recipient onboarding flow exist.

## Consequences

Payment and accounting state stay explainable from immutable events. Provider retries are safe. Chargebacks cannot silently leave a valid passport or referral reward behind. The tradeoff is additional database state and explicit lifecycle jobs, which is preferable to a mutable wallet balance.
