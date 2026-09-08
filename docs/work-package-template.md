# Implementation work package (practitioner-authored)

Use this when three related LicenseLens findings should become one change
the customer can authorize. It is a delivery note, not a generated plan
engine. Fill it by hand from the report; do not invent hours, owners, or
risk ratings the evidence does not support.

This project remains **read-only**. Customer authorization and execution
through their existing admin process are external gates. A synthetic worked
example cannot close those gates.

## Identity

| Field | Value |
|---|---|
| Customer / engagement | |
| Assessment build / version | |
| Scan time and scope (packs, tiers) | |
| Author | |
| Date | |
| Related finding IDs | |

## Observed condition

What is actually true in this tenant, in one paragraph. Not a list of data
sources. Cite the evidence fields (policy names, counts, assignment
fractions) that a second practitioner could re-check.

What remains unknown, and what collection would resolve it:

## Affected population

Who or what is in scope (users, devices, apps, workloads). Distinguish
tenant-owned SKU from assigned entitlement. Do not write “E5 so every user.”

## Intended outcome

The change in assessed state a later comparable scan should show. Name the
check IDs and the expected status after the work, plus residual gaps that
will remain.

## Prerequisites and dependencies

Order matters. Example: a legacy-auth block should exist before Security
Defaults is turned off. List blockers (break-glass accounts, exception
users, change windows, user communication).

## Accountable owner

Name a person or role in the customer organization. “IT” is not an owner.

## Rollout sequence

1.
2.
3.

Include a pilot / ring if the change can disrupt sign-in or device access.

## Exceptions and alternate controls

Deliberate non-adoption is allowed. Record the accepted exception, expiry,
and the alternate control if one exists. Activation is not the objective
when it would not improve this customer’s outcome.

## Operational risk and rollback

What can go wrong, who notices, and how to reverse the change. Disabling an
authentication method is not automatically a quick safe change.

## Acceptance evidence for reassessment

Comparable scope, same catalog/evaluator version called out if it changed.
Separate actual configuration change from catalog, entitlement, evidence
window, or collection changes.

| Check ID | Before | Expected after | Residual uncertainty |
|---|---|---|---|

## Decision

- [ ] Implement
- [ ] Collect more evidence first
- [ ] Defer (reason / date)
- [ ] Accept exception
- [ ] Rely on verified alternate control

Customer authorization: _pending / granted (date)_
Reassessment scheduled:
Operator found this valuable: _yes / no / unknown_
