<#
.SYNOPSIS
    Update the Security License Lens CLI to a newer verified version, or roll back.

.DESCRIPTION
    Verifies a new archive against its release manifest (SHA-256, and Authenticode
    when a signature is promised) and switches the `current` shim atomically. The
    previous version is preserved so -Rollback can restore it after an interrupted
    or unwanted update. The user PATH is left untouched by updates.

    This script NEVER pipes a remote payload into Invoke-Expression. Do not run
    `irm https://... | iex`.

.PARAMETER ArchivePath
    Path to a local LicenseLens Windows x64 ZIP for the target version.

.PARAMETER ReleaseBaseUrl
    HTTPS base URL hosting release-manifest.json and the archive.

.PARAMETER ManifestPath
    Path to a local release-manifest.json.

.PARAMETER Version
    Version to update to. Inferred from -ArchivePath when omitted.

.PARAMETER Rollback
    Restore the previously installed version instead of installing a new one.

.EXAMPLE
    .\Update-LicenseLens.ps1 -ArchivePath .\licenselens-windows-x64-0.4.0.zip -ManifestPath .\release-manifest.json

.EXAMPLE
    .\Update-LicenseLens.ps1 -Rollback
#>
[CmdletBinding()]
param(
    [string] $InstallRoot,
    [string] $ArchivePath,
    [string] $ReleaseBaseUrl,
    [string] $ManifestPath,
    [string] $Version,
    [switch] $Rollback
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'LicenseLens.Installer.psm1') -Force

$params = @{}
foreach ($name in 'InstallRoot', 'ArchivePath', 'ReleaseBaseUrl', 'ManifestPath', 'Version') {
    if ($PSBoundParameters.ContainsKey($name)) { $params[$name] = $PSBoundParameters[$name] }
}
if ($Rollback) { $params['Rollback'] = $true }

Update-LicenseLens @params
