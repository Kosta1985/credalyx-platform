# Payout Lifecycle

## Status

Phase 5 implements the internal payout lifecycle and a **no-money sandbox provider**. It does not enable production money movement.

Production remains blocked until CREDALYX has a concrete provider adapter for recipient onboarding, payout creation, provider-native signed webhooks and reconciliation.

## Beneficiary onboarding

Payout recipients are provider-managed. CREDALYX stores the provider account ID and onboarding status, not bank-account/card credentials.

A payout account belongs to exactly one of:

- an individual owner; or
- an organization.

PostgreSQL validates this XOR relationship and a trigger rejects any payout whose payout account belongs to a different owner/organization than the agent.

API:

```text
POST /v1/payouts/onboarding
GET  /v1/payouts/account?agent_id=...
```

## Accounting model

Payouts never subtract a mutable wallet balance. They post sealed double-entry ledger transactions.

### 1. Reservation

Before any provider side effect:

```text
Debit  agent_owner_available_balance   +amount
Credit agent_owner_reserved_balance    -amount
```

This removes the amount from spendable availability while preserving a distinct in-flight liability.

### 2. Provider success

```text
Debit  agent_owner_reserved_balance    +amount
Credit payment_provider_clearing       -amount
```

### 3. Provider failure / pre-submission error

```text
Debit  agent_owner_reserved_balance    +amount
Credit agent_owner_available_balance   -amount
```

Historical reservation, failure, refund and chargeback entries are never edited or deleted.

## Reservation transaction

For a new approved payout PostgreSQL:

1. takes a per-agent advisory transaction lock;
2. re-checks beneficiary onboarding;
3. rejects another open payout;
4. recomputes available/debt from sealed ledger entries;
5. inserts the payout row;
6. posts/seals `payout_reservation`;
7. links the risk assessment;
8. writes an audit event;
9. commits.

Only after commit does the service call the payout provider.

A partial unique index also enforces one `pending` or `processing` payout per agent.

## Idempotency

Client requests require `Idempotency-Key`.

The internal key is namespaced by agent and purpose. A deterministic `pay_<sha256>` payout reference is derived from agent ID + client key.

On retry the service resolves that payout **before** a new risk assessment. Therefore the payout created by the original request is returned even though it is itself now an open payout.

A different amount with the same successful payout reference is rejected as an idempotency conflict.

Provider payout creation also receives the namespaced idempotency key.

## Risk policy

The current deterministic policy is a first-line gate, not a replacement for a production fraud platform.

### Hard deny

- agent is not active;
- Level 1 control is not verified;
- provider beneficiary onboarding is incomplete/restricted;
- amount is invalid or below `MIN_PAYOUT_MINOR`;
- wallet has debt;
- amount exceeds ledger-derived available balance;
- another payout is pending/processing.

### Manual review

- payout velocity reaches `PAYOUT_MAX_PER_24H`;
- a recent refund/chargeback affected withdrawable balance;
- amount exceeds `PAYOUT_AUTO_APPROVE_MAX_MINOR`.

### Soft signal

Withdrawing at least 90% of available balance adds risk score but does not by itself block a small otherwise clean payout.

Every new payout evaluation is persisted in `payout_risk_assessments`.

`review` currently blocks automatic payout. A manual-review queue/approval workflow is a later phase.

## Provider reconciliation

Sandbox webhook:

```text
POST /v1/webhooks/payout-provider
```

Events:

```text
payout.paid
payout.failed
```

Controls:

- timestamped canonical HMAC with a payout-specific secret;
- unique `(provider, provider_event_id)`;
- exact payout reference match;
- exact provider payout ID match;
- exact amount/currency match;
- final-state duplicate handling;
- deterministic settlement/release ledger idempotency keys.

Production must replace sandbox HMAC with the chosen provider's native raw-body signature validation.

## Chargeback while payout is processing

Reservation and available balance are separate liabilities.

Example:

1. wallet has USD 3.00 available;
2. USD 3.00 is reserved for payout, so available becomes 0 and reserved becomes 3.00;
3. a USD 1.00 referral chargeback arrives and debits available, creating USD 1.00 debt;
4. provider completes the already in-flight USD 3.00 payout;
5. settlement clears reserved only;
6. USD 1.00 debt remains and future payout requests are denied.

If the provider instead fails, releasing the USD 3.00 reservation back to available naturally offsets debt according to the ledger. The chargeback entry itself remains untouched.

## Read models

```text
GET /v1/payouts/summary?agent_id=...
GET /v1/payouts?agent_id=...&limit=...
GET /v1/payouts/{payout_id}?agent_id=...
```

Summary returns:

- `reserved_minor`;
- `paid_minor`;
- `open_payout_count`.

The existing wallet endpoint remains the authoritative available/debt/referral read model; payout summary adds in-flight/paid payout lifecycle information.

## Configuration

```text
MIN_PAYOUT_MINOR=2500
PAYOUT_AUTO_APPROVE_MAX_MINOR=100000
PAYOUT_MAX_PER_24H=3
PAYOUT_PROVIDER_BACKEND=sandbox
SANDBOX_PAYOUT_WEBHOOK_SECRET=...
```

`sandbox` is development/test only. Production requires `PAYOUT_PROVIDER_BACKEND=managed`, and this build fails closed because a managed provider adapter is not yet installed.

## Required production work

- select provider/legal launch countries;
- provider account onboarding adapter;
- provider-native payout API + raw webhook verification;
- manual review UI/workflow;
- payout cancellation and timeout/reconciliation worker;
- provider balance/reconciliation reports;
- sanctions/eligibility/tax requirements by jurisdiction;
- stronger velocity/device/network/referral-graph fraud signals;
- operational incident/runbook for stuck/duplicate/disputed payouts;
- cursor pagination for payout history;
- alerting/metrics for payout state drift.
