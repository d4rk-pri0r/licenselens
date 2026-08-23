---
name: False positive
about: A check reported a gap that is not a real gap in your tenant.
title: "false-positive: "
labels: ["validation", "false-positive"]
---

## Check

Which check_id produced the false positive? (Look in the report JSON or the
finding ID; e.g. `id-ca-mfa-all-users`.)

## What the report said

Paste the finding summary and status.

## What is actually true

What the tenant actually has that the check missed (with sanitized evidence —
no customer tenant IDs, UPNs, or client secrets).

## Evidence you can share

- Redacted report JSON/HTML snippet
- Admin-console screenshots (no PII)

## Why you believe this is a false positive

Which Microsoft object/API result contradicts the finding?

## References

Learn.microsoft.com or product-doc links supporting your interpretation.

## Environment

- Package version (from `licenselens --version` or `pip show licenselens`)
- Auth mode (device code / client secret / Azure CLI)
- Approximate tenant size and cloud (commercial / GCC / GCC High / DoD)
