# Support & compatibility

Security License Lens is an independent open-source project (MIT). Support is
best-effort. The canonical policies live in the repository root files
`SUPPORT.md` and `SECURITY.md` (see the [repository](https://github.com/d4rk-pri0r/licenselens)).

## Supported versions

| Version | Status | Python |
|---------|--------|--------|
| 0.3.x | Supported | 3.12, 3.13 |
| 0.2.x | End-of-life | 3.12 |
| 0.1.x | End-of-life | 3.12 |

Only the latest release line receives fixes.

## Compatibility

- **Python 3.12+**; tested against the two most recent lines (3.12 and 3.13).
- **Windows x64** standalone distribution (PyInstaller one-folder), built on a
  Windows host only.
- **Read-only** Microsoft Graph / Azure calls; API changes are announced in
  `CHANGELOG.md`.
- **Report JSON** check IDs and top-level shapes stay stable across minor
  releases; changes are additive.

## Deprecation

- Deprecated features are listed under **Deprecated** in `CHANGELOG.md` and
  remain functional for one full minor release.
- Removal happens only in a major release.

## Third-party licenses

Direct-dependency licenses are listed in the repository root file
`THIRD_PARTY_NOTICES.md`;
each release ships an SPDX/CycloneDX SBOM and a `license-inventory.json`.
