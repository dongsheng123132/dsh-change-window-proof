# Security Policy

Security fixes target the latest release on `main`.

This verifier is offline and non-destructive. It does not schedule, approve, waive, or execute a change; authenticate receipts; observe live systems; or prove that the supplied ledger contains every real action. Treat each manifest field as an untrusted claim until independently authenticated.

Inputs are capped at 4 MiB. Paths must be workspace-relative. Manifest and artifact paths reject symlinks. Report writes are exclusive, content-addressed, and verified by read-back. Secret-shaped fields and values, raw logs, prompts, bodies, content and chat text are rejected.

Report vulnerabilities privately through GitHub Security Advisories. Never attach production manifests, credentials, logs, or private business data.
