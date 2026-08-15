# Support

Security License Lens is an independent open-source project (MIT). Support is
provided on a best-effort basis by the maintainer and community.

## Supported versions

Only the latest release line is supported. Security and bug fixes are published
for the current minor series; older series receive no fixes.

| Version | Status | Python | Notes |
|---------|--------|--------|-------|
| 0.3.x | **Supported** | 3.12, 3.13 | Current release line |
| 0.2.x | End-of-life | 3.12 | Superseded by 0.3 |
| 0.1.x | End-of-life | 3.12 | Superseded by 0.2/0.3 |

## Compatibility policy

- **Python:** LicenseLens requires Python 3.12+. Each release is tested against
  the two most recent supported Python lines (currently 3.12 and 3.13).
- **Windows:** the standalone distribution targets **Windows x64** only; it is
  built with PyInstaller on a Windows host (PyInstaller is not a cross-compiler).
- **Microsoft Graph / Azure:** read-only API calls only. New Microsoft API
  versions are adopted in minor releases; removed/renamed endpoints are recorded
  in `CHANGELOG.md` and `docs/limitations.md`.
- **Report JSON schema:** check IDs and top-level JSON shapes stay stable across
  minor releases; changes are additive and announced in `CHANGELOG.md`.
  Consumers should tolerate unknown keys.

## Deprecation policy

- Deprecated features (flags, fields, commands) keep working for **one full
  minor release** and are listed under **Deprecated** in `CHANGELOG.md`.
- Removal happens in the next **major** release, never in a patch.
- Breaking changes require a major-version bump (Semantic Versioning).

## Getting help

1. Read the [documentation](https://d4rk-pri0r.github.io/licenselens/) and
   [known limitations](docs/limitations.md).
2. Search [open and closed issues](https://github.com/d4rk-pri0r/licenselens/issues).
3. Open a new issue with your command, exit code, and redacted output. Never
   paste tokens, client secrets, or tenant identifiers.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do **not** open a public issue for
vulnerabilities; use GitHub Security Advisories.

## Third-party licenses

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the direct-dependency
license inventory; each release also ships a machine-readable
`license-inventory.json`.
