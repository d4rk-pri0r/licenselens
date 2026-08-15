# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes (current) |
| 0.2.x   | No |
| 0.1.x   | No |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Use GitHub **Security Advisories** on this repository, or contact the maintainer privately.

Include:

- Description of the issue
- Steps to reproduce
- Impact assessment
- Any suggested fix

## Design expectations

- Security License Lens is **read-only** against customer tenants (no write Graph/Azure APIs)
- No telemetry is sent by default; reports are written only to paths you choose
- Do not commit customer tokens, `.env` files, live reports, or unredacted exports
- Default dormant-account evidence redacts UPN local-parts; treat full JSON as sensitive
- Prefer certificate credentials over long-lived client secrets in production MSP use
- Collectors must not call write APIs

## Data handling

| Data | Handling |
|------|----------|
| Access tokens | In-memory only via azure-identity; never logged |
| Client secrets | Environment variables only; never printed |
| HTML/JSON/MD reports | Local files under your control; may contain tenant configuration metadata |
| Dry-run demo data | Synthetic Contoso-style fixtures only |

## Scope

Findings are **advisory**. This tool does not certify compliance, replace Microsoft Secure Score, or provide incident response.
