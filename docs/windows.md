# Windows

Security License Lens runs anywhere Python 3.12+ runs. The Windows-specific
surface is the read-only PowerShell collector bridge.

## The PowerShell bridge

Email (MDO), SharePoint, Teams, Power Platform, and Purview policy data has no
Microsoft Graph read API, so the tool shells out to an allowlisted PowerShell
module: `powershell/LicenseLens.Collectors`.

### Prerequisites

- Windows PowerShell 5.1 (or PowerShell 7) with the required Exchange Online
  module for the adapters you enable.
- The module exports a single function, `Invoke-LicenseLensCollectorAdapter`,
  which runs allowlisted, read-only adapters and returns structured JSON.

### Enable it

```powershell
Import-Module ./powershell/LicenseLens.Collectors/LicenseLens.Collectors.psd1
```

Then opt into the email pack explicitly in the CLI (it is off by default):

```bash
licenselens scan --allow-email-proxy -o reports
```

The bridge never calls write cmdlets; every adapter is read-only.

## Running the CLI on Windows

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
licenselens demo -o reports
```

Use PowerShell or Windows Terminal for the interactive prompts; in CI or a
non-interactive session the tool falls back to dry-run and never hangs.

## Standalone distribution

A Windows x64 **one-folder** distribution (no Python required) is built from
`packaging/windows/licenselens.spec` on a Windows host:

```powershell
pip install -e ".[build-windows]"
pyinstaller --clean --noconfirm packaging/windows/licenselens.spec
```

This bundles the catalog, checks, report templates, and the PowerShell collector
module into `dist/licenselens/` and writes a deterministic `test-only` ZIP.
One-file mode is deliberately unsupported (no temp-extraction executable).

- **Support matrix:** Windows x64, Python 3.12/3.13. PyInstaller is not a
  cross-compiler, so the exe must be built on Windows (CI), never on macOS/Linux.
- **Trust:** the build-time executable is **unsigned** and its artifact is
  labeled `test-only`; only the release job (with Artifact Signing configured)
  may produce a signed, promotable package. SmartScreen can still warn on a
  newly signed publisher — signing establishes identity, not instant reputation.

## Installing, updating, and removing the CLI

Per-user lifecycle scripts live in `packaging/windows/` and install under
`%LOCALAPPDATA%\LicenseLens\versions\<version>` (no administrator rights needed).
**Never run `irm https://… | iex`.** Download the script and its
`release-manifest.json` over HTTPS, review them, then run them.

```powershell
# Install from a locally downloaded, verified archive + manifest
.\Install-LicenseLens.ps1 -ArchivePath .\licenselens-windows-x64-0.3.0.zip `
    -ManifestPath .\release-manifest.json -AddToPath

# Update to a newer verified version (previous version is kept for rollback)
.\Update-LicenseLens.ps1 -ArchivePath .\licenselens-windows-x64-<version>.zip `
    -ManifestPath .\release-manifest.json

# Roll back to the previously installed version after a failed update
.\Update-LicenseLens.ps1 -Rollback

# Remove the CLI (idempotent; deletes only files it recorded as owned)
.\Uninstall-LicenseLens.ps1
```

The trust guarantees:

- **Checksum first.** Every archive is SHA-256-verified against the manifest
  before extraction; a mismatch aborts with nothing installed.
- **Signature only when promised.** Authenticode is checked on `licenselens.exe`
  only when the manifest says `signed: true`. An unsigned artifact is treated as
  `test-only`, and a promised-but-missing signature is a hard failure.
- **Atomic shim.** The `current` shim is switched with an atomic replace, so an
  interrupted update leaves the old or the new version — never a half-written
  marker — and the previous version stays available for `-Rollback`.
- **PATH consent.** The user PATH is changed only when you pass `-AddToPath`;
  uninstall removes only the exact entry it added.
- **Owned files only.** Uninstall deletes only paths recorded in `state.json`;
  foreign files in the directory are left untouched.

See [Collectors and backends](collectors.md) for how the bridge fits the data
plane, and [Limitations](limitations.md) for what email collection can and
cannot read.
