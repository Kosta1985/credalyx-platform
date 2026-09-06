# Security Policy

Do not commit secrets, production credentials, cardholder data, identity documents or real customer records.

Security-sensitive design requirements:

- use sandbox/test provider credentials only in development;
- production issuer signing must use a managed secret/KMS/HSM boundary;
- verify payment-provider signatures before parsing business meaning;
- treat agent endpoints as untrusted SSRF inputs;
- never mutate ledger history; use compensating transactions;
- require reason codes and audit events for privileged manual changes;
- rotate compromised credentials and revoke affected passports immediately.

If you discover a vulnerability, do not open an issue containing exploit secrets or customer data. Use the repository owner's private security-reporting channel when configured.
