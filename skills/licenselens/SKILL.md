---
name: licenselens
description: License-aware Microsoft 365 security posture checks via the LicenseLens posture.assess MCP tool — use when the user asks to assess tenant posture, license utilization, or security configuration gaps (e.g. "assess this tenant", "posture", "license gaps").
---

# LicenseLens posture assessment

## When to use

Use this skill when the user asks to:

- Assess their Microsoft 365 security posture ("assess this tenant")
- Check what their licenses cover and which controls should be on
- Find security configuration gaps, ranked by priority
- Understand license utilization from a security angle

## Procedure

1. Call the `posture.assess` tool. Default = offline demo (curated sample data,
   no tenant contact). **Ask the user before setting `live=true`** — a live
   scan reads their real tenant with environment-based read-only credentials.
   Live also requires the operator to set `LICENSELENS_MCP_ALLOW_LIVE=1` in the
   MCP server's environment — without it the tool returns `live_disabled`.
2. Read the result — it is the LicenseLens report schema. Ground every
   statement in these fields, by name:
   - `findings[]`: `check_id`, `status` (one of `gap | partial | ok |
     not_licensed | skipped | error | manual`), `severity`, `exposure_class`,
     `summary`, `evidence`, `deep_link`
   - `owned_capabilities`, `subscribed_skus`: what the tenant pays for
   - `moves` / `recommended_next_steps`: ranked fixes (respect this order)
   - `capability_rollup`: headline numbers for the summary view
3. Never invent findings or scores. When citing a finding, quote its
   `check_id` and its evidence verbatim. If a field is absent from the
   response, do not speculate about its value.

## License-constraint rules (hard)

- Never recommend a control the tenant does not own. Check
  `owned_capabilities` before suggesting any control.
- Findings with status `not_licensed` are SKU problems, not configuration
  gaps — phrase them as "requires <SKU/capability>", never as "misconfigured".
- Frame every fix by license reality: separate what is fixable on current
  SKUs from what needs a license upgrade, and say which is which.

## Output rules

- Lead with the top 3 items from `moves` / `recommended_next_steps`, in the
  given order — do not re-rank by your own judgment.
- Include `deep_link` URLs verbatim so the user can jump to the admin page.
- Findings are advisory, not a compliance certification. Say so when
  presenting results.
- Do not mutate anything: the tool is read-only; never suggest applying
  changes through it. Remediation happens in the admin portals the
  `deep_link` URLs point to.
- Do not echo tenant identifiers (tenant IDs, domains, UPNs) in your response
  unless the user asks for them.

## Error handling

If the tool returns `{"error": {...}}`, relay the `code` and `hint` fields to
the user. `auth_unavailable` means live credentials are missing — the fix is
setting `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`, or
running `licenselens scan --live` in a terminal for interactive sign-in.
`invalid_argument` means a parameter was rejected; correct it and retry.
