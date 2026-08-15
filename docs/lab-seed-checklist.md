# Product validation tenant seed checklist

Seed these **intentionally weak** settings so dry-run fixtures and live product
validation exercise customer-facing findings. Prefer under-fire to over-fire on
EXPOSED. Pair every weak (fail) seed below with at least one **clean control**
so a compliant tenant does not report everything red.

This checklist is the human-readable companion to
`catalog/lab/live-lab-matrix.yaml`, the machine-readable live-lab matrix that
`scripts/lab_runner.py` validates. Every direct check family below has a
proven pass (compliant → `ok`) and fail (noncompliant → `gap`/`partial`) case.

## Identity (default pack) — Graph, app-only + delegated

- [ ] **PIM unused / standing admin** — at least one Global Admin or Privileged Role Admin with permanent (not eligible) assignment → `id-pim-unused`, `id-pim-no-permanent-privileged` gap
- [ ] **Identity Protection off** — no risk-based CA requiring MFA / password change on medium+ user/sign-in risk → `id-idprotect-off` gap
- [ ] **CA gaps** — privileged roles without MFA grant; or MFA policy that excludes break-glass only (document the exclusion group) → `id-ca-priv-gaps` gap
- [ ] **Legacy auth open** — CA does not block legacy authentication for all users (or only a pilot) → `id-ca-legacy-auth-block` gap (EXPOSED class)
- [ ] **MFA-less GA path** — a tier-0 / GA principal that can sign in without MFA (not the named break-glass exclusion) → `id-ca-mfa-all-users` gap
- [ ] **Dormant privileged** — one privileged account with no successful sign-in in 90+ days → `id-dormant-privileged` gap
- [ ] **Weak app posture** — an app registration with an expiring credential or a risky delegated permission grant → `id-app-expiring-credentials` / `id-app-risky-delegated-consent` gap
- [ ] **Pass control** — one enforced all-user MFA + legacy-auth-block CA policy (so not everything is red) → `id-ca-legacy-auth-block`, `id-ca-mfa-all-users` `ok`

## Endpoint (default pack) — Graph (Intune/XDR) + MDE API

- [ ] **MDE onboard gap** — licensed MDE P2 seats >> onboarded machines (leave a visible gap) → `mde-onboard-gap` gap
- [ ] **Unassigned compliance policy** — compliance/endpoint-security policy not assigned to all in-scope devices → `endpoint-compliance-policy-assigned` / `endpoint-security-policy-coverage` gap
- [ ] **Unhealthy sensor** — at least one stale/inactive MDE sensor → `mde-sensor-health` partial
- [ ] **Pass control** — a compliance policy assigned platform-wide and the Intune-MDE connector enabled → `endpoint-compliance-policy-assigned`, `endpoint-mde-connector` `ok`

## Email / Security Suite (off default packs) — PowerShell bridge (EXO/SCC)

- [ ] **Weak MDO** — preset Standard/Strict off or pilot-only; Safe Links/Attachments not org-wide → `mdo-safe-links-click-tracking`, `mdo-safe-attachments-block` gap
- [ ] **SMTP AUTH on** → `exo-smtp-auth-disabled` gap
- [ ] **External forwarding allowed** → `exo-forwarding-external-disabled` gap
- [ ] **Missing DMARC** — no DMARC record on a verified domain → `exo-dmarc-published` / `exo-dmarc-reject` gap
- [ ] **Pass control** — SPF/DKIM/DMARC published and mailbox audit on → `exo-spf-published`, `exo-dkim-enabled`, `exo-mailbox-audit-enabled` `ok`
  (Not verified by Graph; PowerShell bridge only. The default dry-run does not depend on this firing.)

## Collaboration — PowerShell bridge (SPO/Teams)

- [ ] **Anyone links with no expiration** → `spo-anyone-link-expiration`, `spo-anyone-link-view` gap
- [ ] **Default link = anyone** → `spo-default-link-specific` / `spo-default-link-view` gap
- [ ] **Anonymous meetings / recording on** → `teams-anonymous-start-disabled`, `teams-recording-disabled` gap
- [ ] **Weak custom policy not masked** — one assigned custom Teams policy weaker than the compliant global default → corresponding `teams-*` gap
- [ ] **Pass control** — specific-people default links, anyone-link expiration enforced → `spo-default-link-specific`, `spo-anyone-link-expiration` `ok`

## Power Platform + Power BI — PowerShell bridge

- [ ] **Anyone can create environments** → `pp-env-creation-admin-only` gap
- [ ] **Tenant isolation off** → `pp-tenant-isolation-enabled` gap
- [ ] **Share-with-everyone allowed** → `pp-share-with-everyone-disabled` gap
- [ ] **Publish-to-web on / guest access on** → `pbi-publish-to-web-disabled`, `pbi-guest-access-disabled` gap
- [ ] **Pass control** — admin-only environment creation, tenant isolation on → `pp-env-creation-admin-only`, `pp-tenant-isolation-enabled` `ok`

## Purview — PowerShell bridge (SCC DLP/labels)

- [ ] **DLP missing or simulation-only** → `pur-dlp-policy-present`, `pur-dlp-enforcement-block` gap
- [ ] **Labels defined but unpublished** → `pur-sensitivity-labels-published` gap
- [ ] **No retention coverage** → `pur-retention-policy-coverage` gap
- [ ] **Pass control** — an enforced DLP policy and a published label → `pur-dlp-policy-present`, `pur-sensitivity-labels-published` `ok`

## Sentinel + selective Azure — ARM (Azure RBAC)

- [ ] **Thin rules / UEBA off** (if workspace present) → `sen-analytics-rule-coverage`, `sen-ueba-not-enabled` gap
- [ ] **No automation rules / no data connectors** → `sen-automation-rules`, `sen-data-connectors` gap
- [ ] **Pass control** — healthy analytics coverage across tactics and UEBA on → `sen-analytics-rule-coverage`, `sen-ueba-not-enabled` `ok`

## Negative cases (must NOT pass)

- [ ] **Permission denied** — remove one read permission → that family reports `error`/`skipped`, never `ok`
- [ ] **Unsupported cloud** — point at a GCC/GCC High/DoD/China surface → `skipped`/`not_applicable`, never `ok`
- [ ] **Empty tenant** — no users/devices/policies → bounded empty states, never a false pass
- [ ] **Large tenant** — paginated/truncated inventory → `partial`, confidence lowered

## Clean controls (false-positive pass)

- [ ] Named break-glass accounts excluded from MFA-less EXPOSED
- [ ] One healthy CA policy that correctly protects admins with MFA (so not everything is red)
- [ ] Friend-tenant pass: no EXPOSED on a cleanly configured control tenant

## Product validation

- [ ] `licenselens demo` → identity + endpoint moves, no email top-card move
- [ ] `licenselens quickstart` device-code path works end-to-end
- [ ] `uv run python scripts/lab_runner.py validate` exits 0
- [ ] `uv run python scripts/lab_runner.py receipt` emits redacted receipts with no secrets/identifiers
- [ ] HTML report remains readable at desktop and mobile widths; finding filters update visible counts
