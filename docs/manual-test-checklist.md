# Manual test checklist (v0.3.0)

Use a Microsoft 365 Developer tenant or a non-production customer lab.

## Prerequisites

- [ ] App registration created per [app-registration.md](app-registration.md)
- [ ] Admin consent granted for identity pack permissions in [permissions.md](permissions.md)
- [ ] `pip install -e ".[dev]"` from a clean clone
- [ ] `pytest` and `ruff check` report no new issues on changed files

## Dry-run

- [ ] `licenselens version` prints a valid version
- [ ] `licenselens checks` lists 12 checks
- [ ] `licenselens doctor` (default) succeeds
- [ ] `licenselens doctor --profile deep` exits `2` with a clear profile error
- [ ] `licenselens scan -o reports` writes HTML/JSON/MD
- [ ] HTML opens and shows “What you already pay for” + plain-language findings
- [ ] Exit code is `1` when demo data contains gaps (expected)

## Diff

- [ ] Run `scan` twice, then `licenselens diff old.json new.json -o diff.md`
- [ ] Diff summary lists new gaps / resolved / improved / worsened / unchanged
- [ ] `-o diff.json` emits machine-readable output
- [ ] Missing input file → exit `2` with a clear message

## Workspace discovery (live)

```bash
licenselens discover-workspace --auth client_secret
```

- [ ] Prints only Sentinel-capable workspace ARM resource IDs
- [ ] `--subscription-id` restricts the search
- [ ] No accessible workspaces → exit `1` with a friendly message

## Batch

```bash
cat > tenants.yaml <<'EOF'
tenants:
  - slug: contoso
    tenant_id: 11111111-1111-1111-1111-111111111111
  - slug: fabrikam
    tenant_id: 22222222-2222-2222-2222-222222222222
EOF
licenselens batch tenants.yaml -o reports
```

- [ ] Dry-run batch writes `reports/<slug>/<timestamp>/` per tenant
- [ ] `reports/index.md` summarizes each tenant with gap counts
- [ ] A tenant with a bad `auth_mode` fails into the index (`error`) and the batch continues
- [ ] `--live` runs live scans per tenant config

## Live — app-only

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
licenselens doctor --live --auth client_secret
licenselens scan --live --auth client_secret -o reports-live
```

- [ ] Doctor: token, organization, subscribedSkus, conditionalAccess, roleAssignments OK
- [ ] `--profile full` adds `defenderEndpoint` (and `sentinelWorkspace` with a workspace ID)
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
