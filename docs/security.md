# Security

Security License Lens is **read-only**. It never calls a write Graph or Azure
API, and it ships no telemetry by default.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes (current) |
| 0.2.x   | No |
| 0.1.x   | No |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Use GitHub **Security Advisories** on this repository.

Include:

- Description of the issue
- Steps to reproduce
- Impact assessment
- Any suggested fix

## Design expectations

- Read-only against customer tenants (no write Graph/Azure APIs)
- No telemetry by default; reports are written only to paths you choose
- Do not commit customer tokens, `.env` files, live reports, or unredacted exports
- Default dormant-account evidence redacts UPN local-parts only; treat full JSON as sensitive
- Production MSP use should prefer a dedicated app registration with the client secret in a secret manager (or Azure CLI); certificate credentials are **not implemented**
- Collectors must not call write APIs

## Data handling

| Data | Handling |
|------|----------|
| Access tokens | In-memory only via azure-identity; never logged |
| Client secrets | Preferred via environment variables (`AZURE_CLIENT_SECRET`). Also accepted via `--client-secret` (visible in process lists) and `tenants.yaml` `client_secret` (do not commit) |
| HTML/JSON/MD reports | Local files under your control; may contain tenant configuration metadata |
| Dry-run demo data | Synthetic Contoso-style fixtures only |

## Scope

Findings are **advisory**. This tool does not certify compliance, replace
Microsoft Secure Score, or provide incident response.
