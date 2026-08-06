# Adding a check

## 1. Ensure the capability exists

If the check depends on a licensed feature, add or reuse an entry in `catalog/capabilities.yaml`.

## 2. Create YAML

Path: `checks/<workload>/<id>.yaml`

```yaml
id: id-example
title: Short technical title
# Required: plain language for SMB owners / novice admins
customer_title: Everyday wording without product jargon
customer_summary: >
  What this means for the business, in one or two sentences.
customer_next_step: >
  A concrete action they can ask IT to take.
description: >
  What paid capability should be realized, and what gap looks like.
workload: identity   # identity | defender | sentinel | purview | endpoint
required_capabilities:
  - entra_id_p2
severity: high       # critical | high | medium | low | info
value_impact: high   # high | medium | low
collector: graph_example
remediation: >
  Concrete next steps for an admin or consultant.
references:
  - https://learn.microsoft.com/...
enabled: true
```

Customer-facing fields appear first in the HTML/Markdown report. Technical
titles and product names stay available in the collapsible technical section.

## 3. Collector (optional in early PRs)

If logic is more than metadata, implement a collector and wire it in the engine. Until then, licensed checks may return `skipped`.

## 4. Test

- `licenselens checks` shows your check
- `pytest` passes
- Prefer fixtures over live tenants in CI

## 5. PR

Describe:

- Which SKU/plan unlocks the capability
- What “gap” means operationally
- Why MSPs/consultants care (security and/or value)
