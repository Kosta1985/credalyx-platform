# Threat Model — Phase 1

## Primary assets

- Agent signing identity and key references.
- Passport issuer keys and signed passports.
- Organization membership and authorization state.
- Payment event integrity.
- Ledger correctness and payout liabilities.
- Referral attribution.
- Audit evidence.

## Priority threats and controls

| Threat | Impact | Initial controls |
| --- | --- | --- |
| Replay of agent challenge/request | Agent impersonation | Random challenges, expiry, one-time consumption, timestamp/nonce design |
| Stolen static API key treated as identity | Agent impersonation | Challenge-response with asymmetric signatures; API keys never prove agent identity |
| Forged payment success | Free passport / fraudulent commission | Server-side provider webhook verification, event idempotency, no frontend authority |
| Duplicate webhook | Double issuance / accounting duplication | Provider event dedupe + ledger idempotency keys |
| Ledger imbalance | Financial misstatement | Per-currency zero-sum invariant, immutable entries, compensating corrections |
| Referral self-dealing / rings | Fraudulent payouts | Self-referral prohibition, immutable attribution, graph/risk signals, velocity/device/IP controls |
| Passport replay after revocation | Unauthorized trust | Online status/revocation reference and verifier status checks |
| Tenant breakout | Confidentiality breach | Membership-derived organization scope, authorization matrix tests, RLS where useful |
| Admin account takeover | High-impact fraud | Phishing-resistant MFA, least privilege, privileged-action audit log |
| Issuer-key compromise | Ecosystem compromise | KMS/HSM-backed keys, rotation, versioned key IDs, incident revocation process |
| SSRF through agent endpoints | Infrastructure compromise | HTTPS-only endpoint policy, egress filtering, DNS/IP validation, no unrestricted fetch |
| Secret leakage in logs/CI | Credential compromise | Structured redaction, secret scanning, no production secrets in repo/tests |

## Abuse cases requiring dedicated tests

- Same payment event delivered concurrently multiple times.
- Two payout requests racing against one available balance.
- Refund racing with commission release.
- Cyclic referral graph attempts.
- Owner attempting to access another organization's agent.
- Revoked key continuing to authenticate requests.
- Modified passport claims with original signature.
- Payment webhook with valid JSON but invalid signature.

## Regulatory/operational boundary

CREDALYX must not present the Agent Passport as state-issued identity, accreditation or regulatory approval. Real payment processing, recipient onboarding and payouts must remain with an appropriately licensed provider. Legal conclusions on stored value, referral rewards, sanctions, tax and country restrictions require jurisdiction-specific professional review before production launch.
