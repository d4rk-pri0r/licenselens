# Security policy

## Supported versions

| Version   | Supported |
|-----------|-----------|
| 0.1.x-a   | Yes (active development) |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Use GitHub **Security Advisories** on this repository, or contact the maintainer privately.

Include:

- Description of the issue
- Steps to reproduce
- Impact assessment
- Any suggested fix

## Design expectations

- Security License Lens aims to be **read-only** against customer tenants
- No customer tokens or report artifacts should be committed to the repo
- Collectors must not call write APIs
