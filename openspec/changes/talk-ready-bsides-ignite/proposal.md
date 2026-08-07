## Why

Security License Lens (v0.2) already has a sharp thesis — entitlement-gated configuration debt — and solid engine bones, but it is not yet something a B-Sides audience can install Monday morning and screenshot with pride. Delaware B-Sides is Nov 13–14 2026 and Microsoft Ignite follows Nov 17–20; the product must be **talk-ready by Nov 10** whether or not the CFP accepts. The goal is public credibility for d4rk-pri0r (and honest Huntress affiliation), adoption by moderately skilled IT owners, and organic MSP/Huntress traction via the same artifact.

## What Changes

- **Iconic HTML top card** as the unit of share: YOU OWN / FULLY WORKING, % realized + plain sentence, ≤3 ranked moves with approximate effort, rare EXPOSED alarm, trust seal (`by d4rk-pri0r`, read-only, advisory)
- **Capability rollup + move ranking** driven by check metadata (`impact`, `effort`, `blast_radius`, `pack`, `exposure_class`, portal deep links)
- **EXPOSED v1 (two classes only):** legacy auth broadly allowed; MFA-less path for Global Admin / tier-0 privileged set
- **Email pack off the default talk path** (spike Sep 2026: no Graph API reads MDO email policy config; Exchange Online PowerShell is the only read path and needs an interactive session). Identity + endpoint carry the demo; the email check keeps its stable id but is excluded from default packs, with evidence only via explicit operator opt-in (labeled Secure Score proxy or research-only EXO PowerShell collector), never rolled up as fully working
- **Talk packs** default: identity + endpoint; email/Sentinel/Purview/MDI not in default packs (email is opt-in) or labeled starter and ranked down
- **Monday path:** `demo` (dry-run card first), `quickstart` (device-code wizard), English `doctor` with ready-enough partial cards, terminal CTA for screenshot loop
- **Distribution:** PyPI + `pipx install licenselens`, Docker escape hatch, tagged talk-ready release
- **MSP Friday ritual:** enriched estate `index.md` (sort by EXPOSED then lowest % realized), MSP docs chapter; batch/diff already largely present
- **Brand surfaces:** naming freeze (Security License Lens / License Lens / `licenselens`), hallway line on README + card, Huntress disclosed not embedded in-product
- **Non-goals (freeze):** SaaS, auto-remediation, dollarization, AI-authored findings, Huntress upsell in-app, large check-volume land grab, PSA plugins

## Capabilities

### New Capabilities

- `top-card`: Scan report top-card contract — capability rollup, % realized, ranked moves, EXPOSED chip, trust seal, share-safe mode labeling
- `check-ranking`: Declarative check metadata and deterministic ranking used to build top moves and pack scope
- `exposure-rules`: Rules and finding behavior for EXPOSED (worse-than-default / purposeful open) vs ordinary gap/partial
- `mdo-direct`: Direct Defender for Office evidence path for preset/Safe Links/Safe Attachments style enforcement (entitlement-gated)
- `monday-path`: First-run UX — demo, quickstart auth, doctor ready-enough, scan output ending in HTML path + CTA
- `distribution`: Install and release surfaces (PyPI/pipx, container image, versioned GitHub release)
- `estate-index`: Multi-tenant batch index summarizing realized %, EXPOSED, worst move per tenant for MSP triage

### Modified Capabilities

- (none — no main specs exist yet; this change introduces the first capability specs)

## Impact

- **Code:** `models.py`, `engine/runner.py`, `engine/evaluate.py`, `engine/quality.py`, collectors (esp. MDO/CA), `report/*` + `templates/report.html.j2`, `cli.py`, `doctor.py`, `batch.py`, check YAML under `checks/`, catalog if needed
- **Docs:** README hero, MSP chapter, limitations, permissions (human-first), sample report aligned to slides
- **Release:** package version bump toward talk-ready (v0.9 or v1.0), CI may gain publish workflow later
- **Ops/calendar:** Phase gates Sep 1 / Oct 1 / Oct 15 / Nov 1 / **Nov 10 hard ready**; B-Sides megaphone optional; Ignite is pocket-demo only
- **Brand:** manager/legal heads-up before public abstract amplification; no product behavior depends on Huntress
