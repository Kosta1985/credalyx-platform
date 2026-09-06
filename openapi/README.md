# OpenAPI contracts

- `openapi.yaml` — primary platform contract through the merged issuer-key lifecycle.
- `payouts-v0.6.yaml` — **canonical Phase 5 payout contract** while payout work remains isolated in PR #10.
- `payouts.yaml` — early Phase 5 draft retained only as review history; do not use it for code generation.

When Phase 5 is accepted, the canonical payout paths/components should be folded into `openapi.yaml` and the early draft removed in a cleanup commit.
