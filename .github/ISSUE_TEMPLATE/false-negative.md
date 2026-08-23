---
name: False negative
about: A real security gap exists that LicenseLens did not flag.
title: "false-negative: "
labels: ["validation", "false-negative"]
---

## Check

Which check_id should have flagged the gap but did not? (Report JSON finding ID.)

## The gap you observed

What the security gap actually is in the tenant (sanitized — no customer tenant
IDs, UPNs, or client secrets).

## What the report said instead

Paste the finding status/summary the report produced.

## Evidence you can share

- Redacted report JSON/HTML snippet
- Admin-console screenshots

## Why you believe this is a gap LicenseLens should detect

What should the evidence have shown for a correct verdict?

## References

Learn.microsoft.com or product-doc links supporting your interpretation.

## Environment

- Package version (from `licenselens --version` or `pip show licenselens`)
- Auth mode (device code / client secret / Azure CLI)
- Approximate tenant size and cloud (commercial / GCC / GCC High / DoD)
