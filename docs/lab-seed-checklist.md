# Product validation tenant seed checklist

Seed these **intentionally weak** settings so dry-run fixtures and live product validation exercise customer-facing findings. Prefer under-fire to over-fire on EXPOSED.

## Identity (default pack)

- [ ] **PIM unused / standing admin** — at least one Global Admin or Privileged Role Admin with permanent (not eligible) assignment
- [ ] **Identity Protection off** — no risk-based CA requiring MFA / password change on medium+ user/sign-in risk
- [ ] **CA gaps** — privileged roles without MFA grant; or MFA policy that excludes break-glass only (document the exclusion group)
- [ ] **Legacy auth open** — CA does not block legacy authentication for all users (or only a pilot) → EXPOSED class
- [ ] **MFA-less GA path** — a tier-0 / GA principal that can sign in without MFA (not the named break-glass exclusion) → EXPOSED class
- [ ] **Dormant privileged** — one privileged account with no successful sign-in in 90+ days

## Endpoint (default pack)

- [ ] **MDE onboard gap** — licensed MDE P2 seats >> onboarded machines (leave a visible gap)

## Email (off default packs)

- [ ] **Weak MDO** — preset Standard/Strict off or pilot-only; Safe Links/Attachments not org-wide  
  (Not verified by Graph; portal/PowerShell only. The default dry-run does not depend on this firing.)

## Starter packs (optional contrast)

- [ ] Thin Sentinel rules / UEBA off (if workspace present)
- [ ] Purview DLP missing or simulation-only
- [ ] MDI sensors missing (if on-prem AD)

## Clean controls (false-positive pass)

- [ ] Named break-glass accounts excluded from MFA-less EXPOSED
- [ ] One healthy CA policy that correctly protects admins with MFA (so not everything is red)
- [ ] Friend-tenant pass: no EXPOSED on a cleanly configured control tenant

## Product validation

- [ ] `licenselens demo` → identity + endpoint moves, no email top-card move
- [ ] `licenselens quickstart` device-code path works end-to-end
- [ ] HTML report remains readable at desktop and mobile widths; finding filters update visible counts
