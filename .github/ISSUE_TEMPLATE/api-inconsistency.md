---
name: Microsoft API inconsistency
about: LicenseLens read a Microsoft API result that conflicts with the portal or other Microsoft data.
title: "api-inconsistency: "
labels: ["validation", "api"]
---

## Check

Which check_id depends on the inconsistent API result?

## API / endpoint

Which Microsoft API/endpoint returned the value (Graph, MDE, ARM, Exchange
Online PowerShell)?

## What LicenseLens read

The raw/normalized value from the API (sanitized).

## What you expected

What the portal or another authoritative source shows instead.

## Scope

- Does it reproduce across tenants, or is it specific?
- Does pagination/truncation play a role?

## Evidence you can share

- Redacted JSON from `licenselens` output
- Portal screenshots or CLI output showing the discrepancy

## References

Microsoft Learn or Microsoft Q&A documenting the API/behavior.

## Environment

- Package version
- Auth mode (delegated / application)
- Cloud (commercial / GCC / GCC High / DoD)
