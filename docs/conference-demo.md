# BSides / conference demo workflow

A rehearsable, reproducible live demonstration of LicenseLens built for
conference reliability (product-maturity goal §20 / §26). The demo is **not** a
live-tenant gamble: it runs entirely offline on deterministic demo fixtures,
then optionally reuses the same flows against a live tenant when an attendee
asks for it.

## Reliability contract

- **No dependence on unpredictable live tenant state** unless explicitly chosen
  — the canonical `licenselens demo` path is fully offline and deterministic.
- **Deterministic results** — identical normalized evidence always yields the
  same findings (verified: two demo runs are byte-identical modulo the run
  timestamp).
- **Fast execution** — a demo scan completes in seconds.
- **No secret exposure** — demo fixtures carry no tenant id, UPN, token, or
  client secret; reports are redacted by default.
- **No dependency on unstable APIs** for the core demonstration — the offline
  fixtures stand in for Graph/MDE/ARM.
- **Graceful offline/failure fallback** — if a collector is unavailable the
  finding degrades to a labeled `partial`/`error` with a limitation, never a
  silent drop.
- **The presenter can show raw Microsoft evidence, the normalized evidence, the
  deterministic evaluator, and the resulting finding** — nothing is hidden
  behind undocumented reasoning.

## The canonical ten-step demonstration

Runs entirely offline:

```bash
licenselens demo -o reports --open
```

1. **Show what the customer owns** — the report's entitlement/capability summary
   lists owned SKUs → capabilities (`licenselens scan` on a real tenant shows
   this from `subscribedSkus`; the demo shows the same shape from fixtures).
2. **Show which security capability that entitlement provides** — the capability
   field maps each owned SKU/plan to a high-value security control.
3. **Show the Microsoft evidence LicenseLens collected** — open a finding and
   inspect its `data_sources` / raw `evidence` (what was queried, what was found,
   whether it was direct or proxy).
4. **Show deterministic evaluator logic** — the evaluator's predicate and the
   `evaluation_mode`/`confidence` are inspectable per finding.
5. **Show the finding** — status, customer copy, severity, and the direct admin
   `deep_link`.
6. **Show why the evidence produced that finding** — the finding exposes its
   summary, limitations, and the traceable evidence path.
7. **Show Microsoft/security guidance supporting the desired state** — each
   flagship check carries an authoritative Microsoft reference link.
8. **Apply or simulate the remediation** — demonstrate the G1 activation
   backlog (`--export action-plan`) that turns a GAP into an actionable work
   item.
9. **Re-run the assessment** — run `licenselens demo` again and/or `diff` two
   artifacts.
10. **Show the finding change** — `licenselens diff before.json after.json`
    reports closed / new / regressed gaps, so the presenter shows
    remediation-driven improvement.

## Rehearsal checklist (do before the talk)

- [ ] `licenselens demo -o demo --report-archive --export json` completes offline.
- [ ] Run it twice; confirm the finding set is identical (only the run timestamp
      changes) — determinism proof.
- [ ] Practice showing 3 flagship findings end-to-end: entitlement → capability →
      evidence → evaluator → finding → why → reference → action.
- [ ] Practice `diff` of two artifacts to show a closed gap and a change.
- [ ] Confirm no live credentials are on the laptop; confirm `--no-redact` is
      never used in the talk.
- [ ] Confirm the demo runs with **no network** (airplane mode on) to prove
      offline reliability.

## Optional live-tenant segment (only if you choose)

Only attempt a live scan when you control the tenant and have verified
credentials. Use `licenselens scan --live --auth oidc` (secret-free, federated
workload identity) or a dedicated demo app registration. Never use a
customer-touching production credential on a conference network.

## Answering a skeptical practitioner

The strongest line of defense is the public methodology (`docs/methodology/`,
including the [limitations methodology](./methodology/limitations.md) and the
evidence model) and the repository's own skeptical audit
(`audit/skeptical-repository-audit.md`, not published on the site). When asked
"how do I know this isn't AI guesswork?", the answer is:

> The assessment logic is deterministic and the evidence is inspectable. Here
> is the raw Graph object, here is the normalized evidence, here is the
> evaluator predicate that produced the finding, and here is the Microsoft
> reference for the desired state.
