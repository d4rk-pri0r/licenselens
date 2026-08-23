# Entitlement model

This document defines how LicenseLens determines what a tenant is entitled to
use, how that maps to security capabilities, and how denominators are kept
honest. It also defines the source-of-truth model that forbids unsourced facts
from becoming product logic.

## From SKU to capability

LicenseLens reads the tenant's active Microsoft 365 subscriptions from Microsoft
Graph `organization/subscribedSkus`. Each subscription exposes its `skuPartNumber`
and its constituent service plans (each with a `servicePlanName` and a stable
`servicePlanId` GUID).

The catalog (`catalog/capabilities.yaml`) maps service plans and SKUs to
security capabilities. Matching is **GUID-first**:

1. An active service plan whose `servicePlanId` GUID is in the capability's
   `service_plan_ids` unlocks that capability (stable across plan renames).
2. As a documented fallback, the legacy free-text plan-name / `skuPartNumber`
   intersection applies—so capabilities without a cataloged GUID keep working.

Unknown service plans and disabled/deleted/suspended plans or SKUs never unlock
a capability. A capability is only "owned" when an active plan/SKU that the
catalog maps to it is actually present in `subscribedSkus`.

Every capability mapping captures:

- the included workload and plan level;
- the entitlement kind (`included`, `base`, `add_on`, `consumption`);
- the supported clouds;
- the backends that can read evidence;
- the source version and a `docs_url` reference;
- known limitations recorded inline where licensing is ambiguous.

### Licensing nuances validated per mapping

Each curated capability mapping is reviewed for:

- workload inclusion and plan level;
- add-on vs. included relationships;
- user vs. device vs. tenant licensing;
- server licensing differences where relevant;
- prerequisites;
- Microsoft 365 vs. Office 365 differences;
- E3/E5 differences;
- Defender-suite and Entra licensing relationships;
- trial/developer license caveats;
- government (GCC / GCC High / DoD) plan variations.

Where Microsoft's licensing is commercially variable or ambiguous, LicenseLens
adopts a conservative interpretation, records the assumption, and never encodes
certainty that does not exist. The mapping audit is maintained in the repository
and tested (`scripts/validate_sku_catalog.py`, catalog loader tests).

## Denominators: licensing versus population

A license count is **not** a device count, and a licensed seat is **not** an
endpoint. LicenseLens refuses to present licensed seats as the population a
security control must cover unless Microsoft licensing semantics explicitly
justify that reading.

The required, defensible pattern for coverage is:

```text
authoritative eligible device inventory
        ↓
filter stale / unsupported / excluded devices
        ↓
compare against actively onboarded/enrolled devices
```

Potential authoritative sources that are considered, and used where the tenant
provides them:

- Intune managed devices;
- Entra registered/joined devices;
- Defender machine inventory;
- server inventory where applicable;
- an explicitly supplied customer inventory.

When an authoritative denominator is available it is used and genuine coverage
is reported. When it is not:

- the assessment is downgraded;
- the terminology changes from "coverage" to a licensing-leverage signal;
- the product reports observed enrollment rather than "coverage";
- the metric is marked proxy evidence, capped at `partial`, and given an
  explicit limitation naming that license counts do not equal the device
  population.

Concretely, `mde-onboard-gap` and `endpoint-enrollment-coverage` follow exactly
this rule: they never reach `ok` on licensed-seat math alone and never report
"coverage looks healthy" from it.

## Entitled, not auto-protected

An entitlement makes a capability *available*; it does not mean every user or
device is automatically covered. Each check distinguishes:

```text
ENTITLED
≠
DEPLOYED
≠
CORRECTLY CONFIGURED
≠
OPERATIONAL
```

A capability being owned only establishes the denominator background for
whether activating it is worthwhile; it never implies the control is active.

## Source-of-truth model

Security assertions and entitlement mappings are traceable to authoritative
sources. LicenseLens prefers, in order:

1. Microsoft Learn;
2. Microsoft licensing documentation;
3. Microsoft product documentation;
4. CISA / SCuBA;
5. recognized standards/frameworks where relevant;
6. documented product behavior observed through supported Microsoft APIs.

**Prohibited** as authoritative product logic: LLM-generated facts, blog posts,
SEO articles, and community assumptions. They never silently become a mapping
or a recommendation.

### Machine-readable metadata

Where practical the source-of-truth model is machine-readable, carrying the
fields the product-maturity goal requires:

```text
source_url
source_type
source_title
last_verified
claim_supported
version_or_date
```

These are attached to capability mappings and, for flagship checks, to the
check's documented reference and the security claim it makes.

## Assertion validation

Security and licensing assertions are validated against primary Microsoft
documentation before they are released. Passing unit tests are necessary but not
sufficient: each behavior is cross-checked against the authoritative reference
for the specific claim, and any discrepancy results in the claim or the code
being corrected (never the evidence forced to fit the claim). The assertion
audit records each claim, the reference that supports it, and its verification
status; see the claim-audit artifact in the repository's `audit/` directory.
