# BSides / conference demo workflow

A rehearsable, reproducible live demonstration of LicenseLens built for
conference reliability (product-maturity goal §20 / §26). The talk runs as a
12-minute, six-beat arc — entirely offline on deterministic demo fixtures,
airplane mode announced out loud and left on — with an optional controlled
live-tenant segment held in reserve. The demo is **not** a live-tenant gamble:
the canonical `licenselens demo` path never touches the network unless you
choose the live segment.

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

## The 12-minute talk arc (BSides, airplane mode on)

Announce airplane mode **before** the first command and leave it on for the
whole demo. Every beat below runs offline.

### Beat 1 — Cold open, hands up (0:00–1:00)

"Raise your hand if your org pays for Microsoft 365 E5." (Most hands stay up.)
"Keep it up if you know what percentage of the security features in it you
actually use." (Hands drop.)

*You're paying for a security product and leaving it in the box. Let's find
out how much of it is in the box.*

### Beat 2 — Four words of install (1:00–3:00)

```bash
pipx install licenselens
licenselens demo --open
```

While the report renders (seconds): "No telemetry. No network. Nothing leaves
this machine — and after this talk, nothing leaves yours either."

### Beat 3 — One finding, end to end (3:00–6:00)

Open the flagship finding, `id-ca-priv-gaps`, and walk its evidence path on
screen:

- **You pay for** Microsoft 365 E5 → Conditional Access is licensed for every
  user.
- **We observed** zero Conditional Access policies → the tenant is marked
  `EXPOSED`.
- Click through the full chain: raw Graph object → normalized evidence →
  deterministic evaluator predicate → Microsoft reference → deep link into the
  admin portal.

Say the line: *"No LLM in the verdict path. Identical evidence always yields
identical findings."*

### Beat 4 — The money slide (6:00–8:00)

Show the report's licensed-but-unenforced percentage: of the 31 security
capabilities the tenant pays for, N sit at default. Follow with two
rapid-fire findings — one endpoint, one email-pack (via the bundled PowerShell
bridge, on a Windows laptop).

### Beat 5 — The remediation payoff (8:00–11:00)

Export the baseline demo, run the after-remediation scenario, and diff:

```bash
licenselens demo -o before --export json
licenselens demo -o after --after --export json
licenselens diff before/security-license-lens-report.json after/security-license-lens-report.json
```

Resolved gaps land on screen. *"Fix one thing, rescan, watch the debt shrink.
That loop is the whole product."* The `--after` overlay is new in 0.4.0 — see
[Version honesty on stage](#version-honesty-on-stage) before you present it.

### Beat 6 — Close and QR (11:00–12:00)

"Four commands. Your tenant, your laptop, your data. Hotel room tonight, four
minutes. No consent screen, no cloud, no AI." The closing QR points at the
hotel-room quick start: [Run it in your hotel room tonight](hotel-room.md)

## Version honesty on stage

`pipx install licenselens` currently serves **0.3.0** from PyPI (see the
[releases](releases.md) page). Two things this page mentions are **new in
0.4.0** and require 0.4.0+:

- the `--after` after-remediation overlay (Beat 5);
- `licenselens ui --demo` — a private local wizard page that walks demo vs.
  live tenant, sign-in, and scan progress, then shows the same report. A good
  closing beat once it ships.

Until 0.4.0 is published to PyPI, present those two only from a laptop running
the 0.4.0 tree — or say "shipping in 0.4.0" and move on. Every other beat in
the arc works from tonight's pipx install.

## The 90-second booth variant (Ignite / partners)

**Presenter machine only.** The booth demo never asks an attendee to consent
to anything on your hardware.

"What's your biggest Microsoft 365 license tier?" → run the demo tenant on the
presenter's machine → land on the licensed-but-unenforced percentage → "Scan
your own tenant tonight from this QR; your credentials never leave your
device."

Partner hook, one accurate paragraph: `licenselens batch tenants.yaml` reads a
multi-tenant manifest and produces a per-tenant report plus an index page in a
single run — one command, every tenant you manage.

## Presenter script (one line per beat)

Rehearse from these one-liners. The 10-minute rehearsal recording itself is a
**human task** — it is never agent-produced.

1. "Raise your hand if your org pays for M365 E5. Keep it up if you know what
   percentage of its security features you actually use."
2. "Four words: `pipx install licenselens`. Airplane mode is on — nothing
   leaves this machine, and tonight nothing leaves yours."
3. "`id-ca-priv-gaps`: you pay for E5, Conditional Access is licensed for every
   user, and we observed zero policies. Raw Graph object, normalized evidence,
   evaluator predicate — no LLM in the verdict path."
4. "Thirty-one capabilities you already pay for. Here's the share sitting at
   default."
5. "Fix one thing, rescan, watch the debt shrink."
6. "Four commands. Your tenant, your laptop, your data. Hotel room tonight."

## Rehearsal checklist (do before the talk)

- [ ] `licenselens demo -o demo --report-archive --export json` completes offline.
- [ ] Run it twice; confirm the finding set is identical (only the run timestamp
      changes) — determinism proof.
- [ ] Walk `id-ca-priv-gaps` end to end on screen: entitlement → capability →
      evidence → evaluator → finding → why → reference → action.
- [ ] Practice the Beat 5 payoff: baseline export → `--after` overlay → `diff`
      showing one closed gap.
- [ ] Confirm no live credentials are on the laptop; confirm `--no-redact` is
      never used in the talk.
- [ ] Confirm the demo runs with **no network** (airplane mode on) to prove
      offline reliability.

## Optional live-tenant segment (only if you choose)

Only attempt a live scan when you control the tenant and have verified
credentials. Use `licenselens scan --live --auth oidc` (secret-free, federated
workload identity) or a dedicated demo app registration. Never use a
customer-touching production credential on a conference network. The offline
arc above is the rehearsed default; the live segment is presenter's discretion.

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
