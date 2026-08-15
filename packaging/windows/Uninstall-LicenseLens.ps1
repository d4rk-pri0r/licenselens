<#
.SYNOPSIS
    Uninstall the Security License Lens CLI for the current user.

.DESCRIPTION
    Removes only the files recorded as owned by this install in state.json, and
    removes only the exact user PATH entry the installer added. It never deletes a
    directory it did not create. Uninstall is idempotent: running it again is a
    no-op.

    This script NEVER pipes a remote payload into Invoke-Expression.

.PARAMETER InstallRoot
    Override the install root (defaults to %LOCALAPPDATA%\LicenseLens).

.EXAMPLE
    .\Uninstall-LicenseLens.ps1
#>
[CmdletBinding()]
param([string] $InstallRoot)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'LicenseLens.Installer.psm1') -Force

$params = @{}
if ($PSBoundParameters.ContainsKey('InstallRoot')) { $params['InstallRoot'] = $InstallRoot }

Uninstall-LicenseLens @params
