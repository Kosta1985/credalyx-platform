## Summary

Describe the change and the invariant/business requirement it implements.

## Security / privacy impact

- [ ] No real secrets, card data, identity documents, or customer personal data added.
- [ ] Authorization/tenant boundaries reviewed where applicable.
- [ ] Cryptographic or payment-provider behavior reviewed where applicable.

## Financial impact

- [ ] No ledger history is mutated.
- [ ] New financial flows are balanced, idempotent, and covered by tests.
- [ ] Refund/chargeback/payout behavior considered where applicable.

## Verification

- [ ] `pnpm typecheck`
- [ ] `pnpm test`
- [ ] `pnpm build`
- [ ] migration/rollback or forward-fix notes included when schema changes.
