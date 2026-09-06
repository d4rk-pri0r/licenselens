# Limitations

This is the standing methodology for how LicenseLens states its own limits. It
complements the operational [Known limitations](../limitations.md) page with
the *principle*: the product describes what it measured, never more.

## The honesty principle

LicenseLens optimizes for this outcome, above all else:

> The authors know exactly what the evidence proves, what it does not prove, and
> have engineered the product accordingly.

Practical consequences of the principle:

- **No overclaiming language.** Words like *healthy*, *complete*, *protected*,
  *covered*, *secure*, *effective*, *comprehensive*, or *fully deployed* are only
  used when the evaluated evidence supports them. A Sentinel assessment built
  from enabled analytics rules and tactical representation reports *configured
  analytics-rule diversity* or *observed tactic representation*—not *healthy
  detection coverage*.
- **No fabricated precision.** Percentages, scores, and grades expose their
  denominator and their exclusions. The posture figure says "of the controls
  associated with owned entitlements that could be evaluated," not "you are X%
  secure."
- **No hidden methodology.** Every material finding exposes its evidence source,
  its evaluator's observation, its confidence, its limitations, and its
  reference. "Show me why" is a product feature, not an afterthought.
- **Empty/unverbose states are stated.** A check that could not verify something
  says so. A capability outside scope is not counted as failing.

## Specifically not claimed

LicenseLens is **not**:

- a compliance certification (CIS, CISA, SCuBA, SOC2);
- a vulnerability scanner or a generic Microsoft 365 posture scanner;
- a replacement for Microsoft Secure Score, Maester, CIPP, or Microsoft
  Lighthouse;
- a license-cost-optimization tool;
- a guarantee that "secure" is an achievable, claimable end state.

Overlaps with those tools are disclosed honestly, and LicenseLens positions
itself as complementary: an entitlement-aware activation-gap assessment with
inspectable evidence, not a scoring competitor.

## Known structural limits (summary)

The operational limitations page details these; the short, honest version:

- Email (MDO) policy config has **no Graph read API**; it is PowerShell-only, so
  the email pack is off by default and only runs as a labeled proxy when opted
  in.
- Some surfaces are **manual** (operator-confirmed) or **proxy** (Secure Score);
  each check declares its mode, and proxy findings are capped/low-confidence.
- Sentinel / Log Analytics / Defender for Cloud need a workspace ARM ID and
  Azure RBAC; without an Azure scope (or on a denied/failed Azure read) those
  checks report `error` (entitlement undetermined) rather than not-licensed,
  and 404 means genuinely not onboarded.
- Sign-in, MDE, and Intune inventories may **truncate** on very large tenants;
  samples are labeled and never presented as the population.
- License seats are a licensing-leverage signal, never a coverage denominator.
- Findings are advisory, not a guarantee.

## Conditional Access effective scope

- Joint coverage across several narrower Conditional Access policies is not
  computed; each scoped policy is listed in evidence instead.
- `includeLocations` scoping (applying only in some locations) is not modelled
  as a gap in this version.

## Decision rule when evidence cannot support a claim

When the evidence cannot support a desired conclusion:

> change the claim (or the code) rather than forcing the data to support it.

If the data shows something weaker or narrower, LicenseLens reports the weaker
truth, downgrades the assessment, or marks the result unknown/partial—it never
inflates.

## Public disclosure

Limitations are documented in the public methodology so a skeptical practitioner
reviewing the repository sees them stated plainly. Visible intellectual honesty
is a product feature: the project expects its limits to be inspected, and it
documents them instead of hiding them.
