# Assessment model

This document defines exactly what Security License Lens can and cannot conclude
about a tenant. It is the formal methodology behind every finding. The software
is engineered so that no displayed conclusion exceeds what this model permits.

## The thesis

LicenseLens answers a specific question:

> Given the Microsoft security capabilities an organization is entitled to use,
> which capabilities are actually deployed, correctly configured, operational,
> partially implemented, unverifiable, or unused—and what evidence supports each
> conclusion?

The product is **not** a generic posture scanner, a vulnerability scanner, a
replacement for Microsoft Secure Score, Maester, CIPP, or Lighthouse, or a
compliance certification. Its differentiation is the relationship:

```text
WHAT THE CUSTOMER OWNS
        +
WHAT SECURITY CAPABILITY THAT ENTITLEMENT ENABLES
        +
WHAT THE TENANT ACTUALLY SHOWS
        =
ACTIVATION GAP
```

Findings describe whether a capability an organization already owns is being
put to use, backed by inspectable evidence. They do **not** assert that the
absence of a symptom means the environment is "secure."

## Concept inventory

The methodology distinguishes the following concepts. Each is defined below
with its evidence requirements, the Microsoft APIs that can support it, what it
means, what is insufficient, and what LicenseLens is prohibited from claiming.

| Concept | Meaning | Sufficient evidence | Insufficient evidence | Primary Microsoft sources |
|---|---|---|---|---|
| Entitlement | The tenant owns a license/service plan that unlocks a capability | An active `subscribedSkus` service plan whose `servicePlanId` GUID matches the catalog (GUID-first match) | A free-text plan name match alone; a `prepaidUnits` count without a plan/scope | Microsoft Graph `organization/subscribedSkus` |
| Capability availability | The owned entitlement makes the security feature available to license | A cataloged capability mapped to the owned service plan GUID | A claim that every user/device is automatically covered | Microsoft licensing docs (per-SKU capability matrix) |
| Configuration evidence | The specific control is set the way the desired state requires | A direct read of the governing object (policy, setting, rule) from the documented API | An inference from a neighboring signal | Graph / MDE / ARM / Exchange Online PowerShell as documented per check |
| Deployment evidence | The control is applied to the intended population | Direct evidence of assignment/scope/coverage over the eligible population | License seat counts used as the population denominator | Graph (assignment, group membership), MDE machine inventory, Intune managed devices |
| Operational evidence | The control is actively functioning, not merely configured | Activity that demonstrates use (alerts, incidents, successful enforcements) | "The policy exists" | MDE alerts/incidents, Security alerts API, SIEM signals |
| Coverage | The share of an eligible population that a control reaches | An authoritative eligible-population inventory compared against observed enrollment | Licensed seats used as the device/eligible population | Intune managed devices, Entra device inventory, Defender machine inventory, explicit customer inventory |
| Effectiveness | The control actually reduces the target risk | Outcome evidence validated over time (rare; requires operational telemetry) | A configured baseline or a single snapshot | Not claimed by LicenseLens except where a study/standard explicitly states it |
| Proxy evidence | A neighboring signal used only when the direct read is unavailable, always labeled | A documented, labeled proxy (e.g., Secure Score control score) admitted as approximate | Using a proxy as if it were direct evidence | Documented per check; always labeled proxy/low-confidence |
| Incomplete evidence | Only part of the evidence was collected (sampling, truncation, page caps) | An explicit partial/truncated marker in the finding | Treating the sample as the complete population | Documented per collector |
| Unavailable evidence | The data could not be collected (permissions, API failure, unsupported) | A surfaced `error`/`partial` status explaining why | Dropping the check silently | Documented per collector |
| Manual verification | A conclusion that requires operator confirmation | An operator-confirmed result recorded through the validation process | Auto-passing a manual-only check | Documented per check |
| Unsupported conclusion | LicenseLens states it cannot conclude something | An explicit limitation or a rejected capability/claim | Fabricating a verdict | The rejection/limitation itself |

## Distinctions that must never be conflated

The following are different and LicenseLens treats them as such:

```text
ENTITLED  ≠  DEPLOYED
DEPLOYED  ≠  CORRECTLY CONFIGURED
CONFIGURED ≠ OPERATIONAL
OPERATIONAL ≠ EFFECTIVE
LICENSE COUNT ≠ DEVICE INVENTORY
POLICY EXISTS ≠ POLICY COVERS THE INTENDED POPULATION
ANALYTICS RULE EXISTS ≠ DETECTION COVERAGE IS HEALTHY
```

Concretely, the engine uses **licensed seats as a licensing-leverage signal,
never as a coverage denominator**. A `mde-onboard-gap` finding that compares
onboarded machines to purchased seats is worded as a licensing-leverage
indicator and capped at `partial`; it is only reported as coverage when an
authoritative eligible-device inventory is supplied. When Entra, Intune, and
MDE inventories join, the MDE denominator is the Intune-managed active
population (`intune_managed_active_30d`) and the Intune enrollment denominator
is Entra devices active in 30 days (`entra_devices_active_30d`). See
[deployment and coverage](./entitlement-model.md#denominators-licensing-versus-population)
for how denominators are validated.

## Effective scope

A Conditional Access policy that exists is not the same as a Conditional
Access policy that covers the intended population. Every coverage check
therefore classifies each enforced matching policy's *effective scope* before
claiming it covers anything: a policy is **universal** only when no scope gap
applies, and scoped-only matches yield `partial`, never `ok`.

The nine scope-gap tokens and their plain-English meanings:

| Token | Plain English |
|---|---|
| `not_all_users` | The policy does not target all users. |
| `not_all_cloud_apps` | The policy does not apply to all cloud apps. |
| `user_actions_only` | The policy governs only specific user actions (for example registering security info), not sign-in to apps generally. |
| `risk_conditioned` | The policy applies only to sign-ins or users already marked with a risk level, so ordinary sign-ins bypass it. |
| `client_app_subset` | The policy applies only to some client types (for example browser only). |
| `platform_subset` | The policy applies only to some device platforms. |
| `trusted_location_bypass` | Sign-ins from trusted locations are excluded from the policy. |
| `named_location_bypass` | Sign-ins from named excluded locations are excluded from the policy. |
| `device_filter` | The policy applies a device filter, so access depends on device attributes. |

Two boundaries of the model:

- **Joint coverage is not computed.** Several narrower policies whose union
  covers everyone are still reported as `partial`; each scoped policy is
  listed in the finding's evidence so a reviewer can judge the union.
- **`includeLocations` is not modelled.** A policy that *includes only some
  locations* (rather than excluding some) is not a scope gap in this version.

**Security Defaults interaction.** When Security Defaults is on, the two
checks it actually covers — all-user MFA and legacy-authentication blocking —
report `partial` (baseline present, the licensed Conditional Access capability
unused) instead of `gap`. Every other Conditional Access coverage check stays
`gap` and records a limitation that Conditional Access policies cannot be
created until Security Defaults is disabled.

## How a finding is built

Each enabled check flows through a fixed pipeline:

```text
ENTITLEMENT
    ↓
CAPABILITY AVAILABILITY
    ↓
EVIDENCE COLLECTION (collector)
    ↓
NORMALIZATION
    ↓
DETERMINISTIC EVALUATION
    ↓
FINDING STATUS + CONFIDENCE + LIMITATIONS
```

1. The tenant's active service plans are matched to catalog capabilities by
   plan GUID (with a free-text name fallback).
2. Every enabled check requires one or more capabilities it maps to.
3. A check whose required capability is not owned reports `not_licensed`
   (informational), never a false gap.
4. Collectors gather raw evidence from the documented Microsoft APIs.
5. A deterministic evaluator maps normalized evidence to a status.
6. The quality policy attaches confidence, demotes proxy findings, and records
   truncation limitations.

Evaluation logic is deterministic: the same normalized evidence always yields
the same finding. No LLM determines entitlement, PASS/GAP status, coverage, or
score.

## What LicenseLens will not do

- It will not claim a tenant is "X% secure." The posture figure is scoped to
  *the controls associated with the entitlements and assessment scope that were
  evaluated*. See [scoring](./scoring.md).
- It will not treat an API failure, a missing permission, or an unsupported
  API as a security gap. See [uncertainty](./uncertainty.md).
- It will not treat absence of evidence as evidence of absence.
- It will not certify compliance with CIS, CISA, SOC2, or any framework.
- It will not remediate, write back, or modify a tenant (read-only).
- It will not use AI to make a security verdict.
