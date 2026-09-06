# Contributing

1. Work on a feature branch; do not push unreviewed changes directly to `main`.
2. Add or update tests for every security/financial invariant changed.
3. Run `pnpm typecheck`, `pnpm test`, and `pnpm build`.
4. Database changes require an additive migration and rollback/forward-fix notes.
5. Never edit historical ledger records in migrations.
6. Never add real secrets or personal/customer data to fixtures, screenshots or logs.
7. Document meaningful architecture changes with an ADR.
