## 1. Foundation (P0 → Sep 1)

- [x] 1.1 Draft manager/brand one-pager (independent MIT, disclosure, no in-product Huntress, CTA personal, endpoint rails)
- [x] 1.2 Tag or finalize 0.2.1 release notes for batch/diff/discover already in tree
- [x] 1.3 Extend `CheckDefinition` / loader for `impact`, `effort`, `blast_radius`, `pack`, `exposure_class`, optional `deep_link`
- [x] 1.4 Backfill all enabled check YAML with required metadata; add loader/CI test that fails on missing keys
- [x] 1.5 Extend `Finding` + `ScanResult` models for exposure_class, structured `moves`, capability rollup fields, pack scope (additive; keep `recommended_next_steps` filled from moves)
- [x] 1.6 Write unit tests for rollup rules (gap/partial/ok/proxy-cap → YOU OWN / FULLY WORKING / % realized)
- [x] 1.7 Document lab seed checklist for d4rkpr10r tenant (PIM standing, IdP off, legacy open, MFA-less GA, MDE gap, weak MDO, optional EXPOSED contrast)
- [x] 1.8 README hero draft: hallway line, sample card placeholder, demo-first command order

## 2. Ranking and top-card data (P0–P1)

- [x] 2.1 Implement deterministic move ranking (impact, exposure, confidence, pack preference, effort penalty, check_id tie-break)
- [x] 2.2 Build structured moves list on `ScanResult` after findings (title, why, effort label, check_ids, deep_link)
- [x] 2.3 Implement capability rollup over owned in-scope capabilities
- [x] 2.4 Demote starter-pack findings in ranking relative to identity/email/endpoint
- [x] 2.5 Tests for ranking: exposed > ordinary gap; direct > proxy; stable ties

## 3. Exposure rules (P1 → Oct 1)

- [x] 3.1 Implement EXPOSED legacy-auth rubric in CA evaluation path + tests
- [x] 3.2 Implement EXPOSED MFA-less GA/tier-0 rubric + break-glass exclusion notes/tests
- [x] 3.3 Ensure exposure_class propagates to findings, top-card chip inputs, and JSON
- [x] 3.4 Confirm PIM-unused and similar remain non-exposed ordinary gaps
- [ ] 3.5 Lab verify both EXPOSED classes fire on seeded sins and not on clean controls

## 4. Identity harden + MDO email decision (P1 → Oct 1)

- [ ] 4.1 FP pass identity checks on lab + one friendly tenant; fix false gap/partial thresholds
- [x] 4.2 Spike MDO direct Graph/API evidence (presets and/or Safe Links + Safe Attachments); record permissions — RESULT: no Graph v1.0/beta read API for MDO policy config; Exchange Online PowerShell-only; `exchangeProtectionPolicy` is M365 Backup, unrelated
- [x] 4.3 Drop email from default talk packs; doctor probe reports whether email policy signals are readable + one-line human fix (EXO admin center/PowerShell pointer)
- [x] 4.4 Owner-voice copy on `mdo-p2-policies-default`; keep id stable; excluded from default packs; evaluate only via opt-in proxy/EXO
- [x] 4.5 Remove Secure Score as default MDO path; optional explicit degraded proxy only if kept
- [x] 4.6 Update dry-run fixtures and sample report: email evidence shape = opt-in proxy or absent from talk
- [x] 4.7 Label Sentinel/Purview/MDI as starter in metadata; verify they do not dominate top moves

## 5. HTML top card (P1 end / P2)

- [x] 5.1 Redesign `templates/report.html.j2` top card per sealed wireframe (own/working, % + sentence, chips, ≤3 moves, ≈effort disclaimer, conditional EXPOSED, trust seal, hallway line, mode)
- [x] 5.2 Ensure markdown report leads with equivalent executive summary (not only HTML)
- [x] 5.3 Print/CSS or layout pass so card is screenshot-stable (~share crop)
- [x] 5.4 Update `examples/sample-report/` to match slide-ready Contoso card
- [x] 5.5 Tests or snapshot checks for required top-card strings/fields in HTML output

## 6. Monday path UX (P2 → Oct 15)

- [x] 6.1 Add `licenselens demo` (dry-run scan, print HTML path, optional open)
- [x] 6.2 Add `licenselens quickstart` (read-only blurb, device code, org confirm, offer doctor/scan)
- [x] 6.3 Doctor English rewrite: ✓/⚠/✗, one-line fixes, ready-enough when identity works despite MDE/email 403
- [x] 6.4 Scan interactive completion: org summary, HTML path, screenshot CTA line
- [x] 6.5 Device-code-blocked error rail → plain English + MSP app path pointer
- [x] 6.6 Partial permissions scan still writes HTML with limitations (no stack-trace-only death)
- [x] 6.7 CLI/help text aligns with talk verbs; avoid new unnecessary commands

## 7. Estate index + MSP docs (P2)

- [x] 7.1 Enrich batch `index.md` with realized %, exposed count, worst move, failure rows
- [x] 7.2 Sort or document EXPOSED-first then lowest realized triage order
- [x] 7.3 Verify per-tenant HTML uses same top-card contract as single scan
- [x] 7.4 Write MSP docs chapter: app-only auth screenshots, tenants.yaml, Friday batch, monthly diff, vendor-neutral note
- [x] 7.5 Example `tenants.yaml` with defaults for packs/auth

## 8. Distribution (P2 → P4)

- [x] 8.1 Verify package metadata/versioning for public install; bump version plan (0.3.x prerelease → talk-ready tag)
- [ ] 8.2 Publish to PyPI (trusted/manual release process); document `pipx install licenselens`
- [x] 8.3 Dockerfile + GHCR (or chosen registry) image; document output mount dry-run
- [ ] 8.4 Test hero install + Docker escape on clean Mac and clean Windows VM
- [x] 8.5 Confirm default builds have no product telemetry

## 9. Freeze and talk assets (P3 → Nov 1)

- [ ] 9.1 Scope freeze sticky: no new checks/classes after Oct 15 except talk-blocking fixes
- [x] 9.2 Known limitations page: proud honesty (proxies remaining, sampling, advisory)
- [ ] 9.3 Align sample report bytes with slide screenshots exactly
- [ ] 9.4 Record 60s silent demo fallback (demo → card)
- [ ] 9.5 Manual test checklist green on lab + one external tenant
- [ ] 9.6 Abstract/bio/disclosure final; QR targets README hero + sample report
- [ ] 9.7 Tag rc (v0.9.0-rc or v1.0.0-rc)

## 10. Ship corridor (P4 → Nov 10; Nov 13–20)

- [ ] 10.1 Talk-blocking bugfix only; tag talk-ready release + GitHub Release notes
- [ ] 10.2 Pin/docs for pipx + Docker digests/tags used on slides
- [ ] 10.3 Deck freeze; terminal font/size rehearsal; CTA channel live
- [ ] 10.4 Nov 10 hard gate checklist (install → demo → quickstart → card ≤30 min cold test)
- [ ] 10.5 B-Sides execution (if accepted) or public drop + community presence
- [ ] 10.6 Ignite pocket demo kit (QR one-pager, pre-authed lab, 90s script)
- [ ] 10.7 Afterglow container: triage CTA screenshots, issues, only then post-talk backlog
