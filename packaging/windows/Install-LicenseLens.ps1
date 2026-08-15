<#
.SYNOPSIS
    Install the Security License Lens CLI for the current user.

.DESCRIPTION
    Installs a verified per-user copy of LicenseLens under
    %LOCALAPPDATA%\LicenseLens\versions\<version>. The archive is SHA-256 verified
    against a release manifest before extraction; Authenticode is enforced only
    when the manifest promises a signature. The `current` shim is switched
    atomically and the previous version is preserved for rollback. The user PATH
    is modified only when -AddToPath is passed.

    This script NEVER pipes a remote payload into Invoke-Expression. Do not run
    `irm https://... | iex`; instead download this script and its manifest over
    HTTPS, review them, and run the script.

.PARAMETER ArchivePath
    Path to a local LicenseLens Windows x64 ZIP.

.PARAMETER ReleaseBaseUrl
    HTTPS base URL hosting release-manifest.json and the archive, e.g.
    https://github.com/d4rk-pri0r/licenselens/releases/download/v0.3.0

.PARAMETER ManifestPath
    Path to a local release-manifest.json (used with -ArchivePath or -ReleaseBaseUrl).

.PARAMETER Version
    Version to install, e.g. 0.3.0. Inferred from -ArchivePath when omitted.

.PARAMETER AddToPath
    With this explicit consent, append the `current` shim directory to the user PATH.

.PARAMETER Force
    Allow overwriting an existing install of the same version.

.EXAMPLE
    .\Install-LicenseLens.ps1 -ArchivePath .\licenselens-windows-x64-0.3.0-test-only.zip -ManifestPath .\release-manifest.json

.EXAMPLE
    .\Install-LicenseLens.ps1 -ReleaseBaseUrl https://example.org/dl -Version 0.3.0 -AddToPath
#>
[CmdletBinding()]
param(
    [string] $InstallRoot,
    [string] $ArchivePath,
    [string] $ReleaseBaseUrl,
    [string] $ManifestPath,
    [string] $Version,
    [switch] $AddToPath,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'LicenseLens.Installer.psm1') -Force

$params = @{}
foreach ($name in 'InstallRoot', 'ArchivePath', 'ReleaseBaseUrl', 'ManifestPath', 'Version') {
    if ($PSBoundParameters.ContainsKey($name)) { $params[$name] = $PSBoundParameters[$name] }
}
if ($AddToPath) { $params['AddToPath'] = $true }
if ($Force) { $params['Force'] = $true }

Install-LicenseLens @params
