# Manual test checklist (v0.2.0)

Use a Microsoft 365 Developer tenant or a non-production customer lab.

## Prerequisites

- [ ] App registration created per [app-registration.md](app-registration.md)
- [ ] Admin consent granted for identity pack permissions in [permissions.md](permissions.md)
- [ ] `pip install -e ".[dev]"` from a clean clone
- [ ] `pytest` and `ruff check src tests` pass offline

## Dry-run

- [ ] `licenselens version` prints `0.2.0`
- [ ] `licenselens checks` lists 10 checks
- [ ] `licenselens doctor` (default) succeeds
- [ ] `licenselens scan -o reports` writes HTML/JSON/MD
- [ ] HTML opens and shows “What you already pay for” + plain-language findings
- [ ] Exit code is `1` when demo data contains gaps (expected)

## Live — app-only

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
licenselens doctor --live --auth client_secret
licenselens scan --live --auth client_secret -o reports-live
```

- [ ] Doctor: token, organization, subscribedSkus, conditionalAccess, roleAssignments OK
- [ ] Scan completes without exit code `2`
- [ ] Report `scan_mode` is `live`
- [ ] Capability cards match tenant SKUs (spot-check E5/P2)
- [ ] Identity findings are not all `skipped` (unless permissions missing → `error` with clear text)
- [ ] No secrets appear in HTML/JSON/console
- [ ] Dormant privileged evidence uses redacted UPNs

## Live — device code

```bash
licenselens doctor --live --auth device \
  --tenant-id "$AZURE_TENANT_ID" \
  --client-id "$AZURE_CLIENT_ID"
```

- [ ] Browser/device login completes
- [ ] Doctor succeeds with the same checks

## Live — Sentinel

```bash
licenselens doctor --live --auth client_secret \
  --workspace-resource-id "/subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/..."
licenselens scan --live --auth client_secret \
  --workspace-resource-id "..." -o reports-sentinel
```

- [ ] Doctor `sentinelWorkspace` row OK with rule counts
- [ ] `sen-analytics-rule-coverage` and `sen-ueba-not-enabled` are not `skipped`
- [ ] Missing workspace on live scan → Sentinel checks `error` with plain-language guidance

## Negative tests

- [ ] Wrong client secret → exit `2`, clear auth error
- [ ] Missing `Policy.Read.All` → CA checks `error` or doctor CA row fails (not a crash)
- [ ] `--workload identity` limits findings to identity checks
- [ ] Dry-run: **zero** `skipped` findings for the original 10 checks when demo SKUs unlock them

## Sign-off

| Role | Name | Date |
|------|------|------|
| Author | | |
| Reviewer | | |
