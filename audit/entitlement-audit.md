# Microsoft licensing / entitlement accuracy audit

Authoritative source of the audit: Microsoft Learn, *Product names and service
plan identifiers for licensing* (updated 2026-08-19) and its official CSV, plus
the Microsoft Learn product/licensing pages cited inline. This document records
what was verified, what was corrected, and the known limitations of the
entitlement model (product-maturity goal §11 / §12).

Scope: every curated `servicePlanId` GUID mapping in
`catalog/sku_service_plans.yaml` and the capability attachments in
`catalog/capabilities.yaml` are asserted against the authoritative Microsoft
table. Nothing here is guessed or inferred.

## Method

1. Download the official Microsoft licensing reference CSV (the canonical
   machine form of the Learn "Product names and service plan identifiers"
   table).
2. Grep each cataloged GUID and plan name and cross-reference the owning
   product rows (SKU inclusion: E3/E5, EMS E5, alone).
3. Verify entitlement-claim semantics against the relevant Microsoft Learn
   licensing/product pages (Entra licensing, Defender service description,
   Workload ID FAQs, Sentinel billing, etc.).

## Verification result (all items CONFIRMED unless marked corrected)

| GUID | Plan | Catalog mapping | Result |
|------|------|-----------------|--------|
| `eec0eb4f-6444-4f95-aba0-50c24d67f998` | AAD_PREMIUM_P2 | Entra ID P2 → entra_id_p2, conditional_access, identity_protection | ✅ Confirmed |
| `41781fb2-bc02-4b7c-bd55-b576c07bb09d` | AAD_PREMIUM | Entra ID P1 → conditional_access | ✅ Confirmed |
| `7dc0e92d-bf15-401d-907e-0884efe7c760` | AAD_WRKLDID_P2 | Workload ID Premium | ✅ Confirmed |
| `84c289f0-efcb-486f-8581-07f44fc9efad` | AAD_WRKLDID_P1 | Workload ID P1 alias | ✅ Confirmed (caveat below) |
| `f20fedf3-f3c3-43c3-8267-2bfdd51c0939` | ATP_ENTERPRISE | Defender for Office 365 P1 | ✅ Confirmed (this is MDO Plan 1) |
| `871d91ec-ec1a-452b-a83f-bd76c7d770ef` | WINDEFATP | Defender for Endpoint P2 | ✅ Confirmed |
| `8e0c0a52-6a6c-4d40-8370-dd62790dcd70` | THREAT_INTELLIGENCE | Defender for Office 365 P2 | ✅ Confirmed — **label corrected** (see below) |
| `c1ec4a95-1f05-45b3-a911-aa3fa01094f5` | INTUNE_A | Microsoft Intune | ✅ Confirmed |
| `14ab5db5-e6c4-4b20-b4bc-13e36fd2227f` | ATA | Microsoft Defender for Identity | ✅ Confirmed (`ATA` is the string id; friendly name is Defender for Identity) |
| `efb87545-963c-4e0d-99df-69c6916d9eb0` | EXCHANGE_S_ENTERPRISE | Exchange Online Plan 2 | ✅ Confirmed |
| `3e170737-c728-4eae-bbb9-3f3360f7184c` | INTUNE_A_VL | Microsoft Intune | ✅ Confirmed |
| `70d33638-9c74-4d01-bfd3-562de28bd4ba` | BI_AZURE_P2 | Power BI Pro | ✅ Confirmed |
| `292cc034-7b7c-4950-aaf5-943befd3f1d4` | MDE_LITE | Defender for Endpoint Plan 1 | ✅ **Added to catalog** (was absent) |

## Corrections applied (2026-08)

1. **`THREAT_INTELLIGENCE` label corrected.** The plan `THREAT_INTELLIGENCE`
   (`8e0c0a52-...`) is **Microsoft Defender for Office 365 (Plan 2)**, not
   "Microsoft Defender for Office 365 (Threat Intelligence)." The previous
   friendly label could be conflated with *Microsoft Defender Threat
   Intelligence* (whose plan is `THREAT_INTELLIGENCE_APP`,
   `fbdb91e6-7bfd-4a1f-8f7a-d27f4ef39702`). `friendly_plan_names` now reads
   "Microsoft Defender for Office 365 (Plan 2)".
2. **`MDE_LITE` GUID added to the catalog.** The plan identifier for Defender
   for Endpoint Plan 1 is `MDE_LITE = 292cc034-7b7c-4950-aaf5-943befd3f1d4`.
   The `defender_endpoint_p1` capability previously carried an empty
   `service_plan_ids` list (with a stale "no sourced GUID" note). It now lists
   the `MDE_LITE` GUID and the note documents the provenance.

## Entitlement-claim semantics (verified)

- **Microsoft 365 E5** includes Entra ID P2, Defender for Endpoint P2, Defender
  for Office 365 P2, and the Purview/Information-Protection P2 plans — confirmed
  against the SPE_E5 row of the licensing table and the Microsoft Entra /
  Defender service-description pages.
- **Microsoft 365 E3** includes Entra ID P1 (Conditional Access) + MFA Premium,
  and Defender for Endpoint Plan 1 + Defender for Office 365 P1, but **not** Entra
  P2 / PIM / Identity Protection — confirmed against the SPE_E3 row and the
  Zero Trust identity/device-access licensing note.
- **Microsoft Entra Workload ID Premium** is a standalone add-on enabling
  Conditional Access for service principals and risky workload-identity
  detection; it is a separate purchase on top of Entra P1/P2 — confirmed against
  the Workload Identities FAQ and the Conditional Access for workload identities
  doc.
- **Microsoft Sentinel** is an Azure consumption service billed per GB via Azure
  meters; it has **no** `servicePlanId` in `subscribedSkus`. The catalog leaving
  `service_plan_ids` empty for `microsoft_sentinel` is correct. The M365 E5
  benefit is a data-ingestion grant, not a license. Confirmed against the
  Azure Sentinel billing doc and the E5 benefit-offer page.

## Known limitations

- **Identity caveats:**
  - `AAD_WRKLDID_P1` (`84c289f0-...`) currently appears only under the
    Workload-Identities-Premium (China) product row in the Aug-2026 table; the
    commercial "Microsoft Entra Workload ID" product exposes only
    `AAD_WRKLDID_P2`. A `AAD_WRKLDID_P1` GUID match should be treated with that
    caveat.
  - There is no `DEFENDER_ENDPOINT_P2` product identifier in the licensing
    table; the service-plan string is `WINDEFATP`. The catalog keeps
    `WINDEFATP` as the canonical plan name/alias.
- **Churn:** Microsoft states the licensing table is accurate only as of the
  article's last-update date (2026-08-19). GUIDs can change with SKU churn; the
  offline validator and the pinned catalog must be re-validated against the
  upstream table before each conference release.
- **Commercial variability:** Where Microsoft licensing is commercially
  variable (e.g., Workload ID licensing granularity), the catalog adopts a
  conservative interpretation and records the assumption rather than encoding
  certainty that does not exist.

## Last validated

2026-08 — all GUIDs above verified against the official Microsoft licensing
reference; corrections applied and the offline SKU catalog validator
(`scripts/validate_sku_catalog.py`) passes with the updated catalog.
