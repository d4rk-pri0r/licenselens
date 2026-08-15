# Third-party notices

Security License Lens is MIT-licensed. This file lists the **direct runtime
dependencies** declared in `pyproject.toml` and their licenses. The exact
resolved versions and license metadata are recorded at build time by
`scripts/release/license_inventory.py` and shipped with every release as
`license-inventory.json` / `license-inventory.md`.

| Package | Declared specifier | License |
|---------|--------------------|---------|
| azure-identity | `>=1.19.0` | MIT |
| dnspython | `>=2.6,<3` | ISC |
| httpx | `>=0.27.0` | BSD-3-Clause |
| jinja2 | `>=3.1.4` | BSD-3-Clause |
| pydantic | `>=2.9.0` | MIT |
| pyyaml | `>=6.0.2` | MIT |
| rich | `>=13.9.0` | MIT |
| typer | `>=0.12.5` | MIT |

Transitive dependencies and their licenses are resolved from the lock file
(`uv.lock`) and the build environment; the per-release SBOM (SPDX + CycloneDX)
and `license-inventory.json` are the authoritative sources for a specific
artifact.

MIT: Copyright (c) contributors — see the LICENSE file for the full text.
BSD-3-Clause / ISC licenses are reproduced in the respective packages' own
`LICENSE` files.

---

## Microsoft workload identification icons (vendored)

### What is vendored

Twelve product-identification icons live under
`assets/vendor/microsoft-cloud/` and are described by
`assets/vendor/microsoft-cloud/manifest.yaml`. Each entry pins:

- upstream repository: `loryanstrant/MicrosoftCloudLogos`
- upstream commit: `fc3a6c9506dc9a6ebdfb4f5891ee486f2717257c`
- exact raw GitHub URL used at vendor time
- SHA-256 of the vendored bytes

Runtime code must load only these local files. **Do not hotlink** remote logo
URLs at runtime.

### Upstream provenance facts (recorded)

The upstream repository `loryanstrant/MicrosoftCloudLogos` at the pinned
commit:

1. **Has no license file** in the repository root (no `LICENSE`, `LICENSE.md`,
   or equivalent SPDX declaration observed at pin time).
2. **Mixes sources**: official Microsoft icon packages alongside assets that
   appear scraped or re-hosted from other Microsoft surfaces.
3. **Retains legacy / unofficial variants** in the broader tree (for example
   paths or names containing `unofficial`, former-product marks, corporate
   lockups, or legacy folders). Those variants are **not** vendored here.

Only the twelve allowlisted paths in `manifest.yaml` are present on disk.
Anything unofficial, former-product, corporate-logo, flagship-lockup,
legacy-folder, or otherwise unlisted is rejected by
`licenselens.vendor_assets.validate_manifest`.

### Owner risk acceptance

The repository owner explicitly accepted the trademark and provenance risk of
vendoring these twelve product-identification icons for report UX, with the
understanding that:

- Microsoft trademarks remain Microsoft’s property.
- The icons identify Microsoft workloads in Security License Lens reports only.
- **None of these assets is LicenseLens product branding**, a wordmark, or a
  substitute for the Security License Lens mark.
- Assets may need rapid withdrawal if Microsoft guidelines or upstream
  availability change.

### Trademark attribution

Microsoft, Azure, Microsoft Entra, Microsoft Defender, Microsoft Intune,
Microsoft Purview, Microsoft Sentinel, Exchange, SharePoint, OneDrive,
Microsoft Teams, Microsoft Power Platform, and Microsoft Power BI are
trademarks of Microsoft Corporation. Security License Lens is an independent
open-source project and is **not** affiliated with, endorsed by, or sponsored
by Microsoft Corporation.

### Microsoft trademark / brand guideline references

- Microsoft Trademark and Brand Guidelines:
  https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks
- Microsoft brand / logo use overview:
  https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general
- Azure icon / architecture icon terms (context for product icons):
  https://learn.microsoft.com/en-us/azure/architecture/icons/

Consult the current Microsoft pages before redistributing marks outside this
repository’s documented report-identification use.

### Replace / remove procedure (rapid withdrawal)

To withdraw or replace the vendored icons quickly:

1. Delete the tree `assets/vendor/microsoft-cloud/` (or replace individual
   files listed in `manifest.yaml`).
2. Update or remove `assets/vendor/microsoft-cloud/manifest.yaml` so the
   allowlist and SHA-256 pins match remaining files (or delete the manifest if
   no icons remain).
3. Remove or update any report/UI references that resolve paths under
   `assets/vendor/microsoft-cloud/`.
4. Update this section of `THIRD_PARTY_NOTICES.md`.
5. Run `uv run pytest tests/test_red_contracts_logo_manifest.py -q` and the
   project test suite; fix any callers that assumed the icons exist.
6. Commit the removal as a focused change (do not leave broken pins).

To replace an icon: vendor the new bytes under the same relative path (or a
new allowlisted path), recompute SHA-256, update `manifest.yaml`, and re-run
`licenselens.vendor_assets.verify_assets()`.
