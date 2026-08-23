---
name: New edge case
about: A tenant configuration that a check does not handle correctly.
title: "edge-case: "
labels: ["edge-case", "validation"]
---

## Check

Which check_id fails to handle your configuration correctly?

## The configuration

Describe the tenant setup that is not covered (sanitized — no customer tenant
IDs, UPNs, or client secrets).

Examples: unusual grant operator (`OR` in Conditional Access), service
principal / workload identity, empty `clientAppTypes`, partial/paginated
inventory, government cloud plan, grandfathered SKU.

## What LicenseLens currently does

Paste the finding status/summary it produced for this configuration.

## What it should do

The correct behavior for this edge case (status, wording, or explicit
limitation).

## Can you share a sanitized fixture?

If possible, provide a minimal tenant-safe JSON fixture that reproduces the edge
case (no real identifiers).

## References

Learn.microsoft.com or product-docs for the configuration.
