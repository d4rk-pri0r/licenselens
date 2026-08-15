<#
LicenseLens.Installer — shared, read-only install/update/uninstall engine.

Trust model (hard requirements, do not weaken):

  * Every archive is SHA-256-verified against a signed release manifest BEFORE
    extraction. Nothing is extracted or executed on the basis of an unverified
    download.
  * Authenticode is verified only when the manifest promises a signature
    (artifact.signed == true). An unsigned archive is never silently treated as
    signed, and a promised-but-missing/invalid signature is a hard failure.
  * The `current` shim is switched atomically (temp file + File.Replace with a
    backup) so an interrupted update leaves either the old or the new version,
    never a half-written marker. The previous version is preserved for rollback.
  * User PATH is changed only with explicit consent (-AddToPath); the exact
    entry added is recorded and is the only PATH entry uninstall will remove.
  * Uninstall removes only paths recorded in state.json as owned by this
    install; it never deletes a directory it did not create.

This module never pipes a remote payload into Invoke-Expression and never
recommends `irm | iex`.
#>

#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AppName = 'licenselens'
$script:ProductName = 'Security License Lens'
$script:StateSchemaVersion = 1
$script:ManifestSchemaVersion = 1
$script:VersionPattern = '^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$'
$script:Sha256Pattern = '^[0-9a-fA-F]{64}$'

# Older Windows PowerShell defaults to SSL3/TLS1.0 for Invoke-WebRequest; raise
# it so HTTPS release installs actually work on supported hosts.
if ([System.Net.ServicePointManager]::SecurityProtocol -band
    [System.Net.SecurityProtocolType]::Tls12 -eq 0) {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor
            [System.Net.SecurityProtocolType]::Tls12
    } catch { }
}

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

function Get-LicenseLensInstallRoot {
    param([string] $Base = $env:LOCALAPPDATA)
    if ([string]::IsNullOrWhiteSpace($Base)) {
        throw 'LOCALAPPDATA is not set; cannot determine the per-user install root.'
    }
    return (Join-Path -Path $Base -ChildPath 'LicenseLens')
}

function Get-LicenseLensVersionsRoot {
    param([string] $InstallRoot)
    return (Join-Path -Path $InstallRoot -ChildPath 'versions')
}

function Get-LicenseLensVersionDir {
    param([string] $InstallRoot, [string] $Version)
    return (Join-Path -Path (Get-LicenseLensVersionsRoot -InstallRoot $InstallRoot) -ChildPath $Version)
}

function Get-LicenseLensShimDir {
    param([string] $InstallRoot)
    return (Join-Path -Path $InstallRoot -ChildPath 'current')
}

function Get-LicenseLensPreviousDir {
    param([string] $InstallRoot)
    return (Join-Path -Path $InstallRoot -ChildPath 'previous')
}

function Get-LicenseLensExePath {
    param([string] $InstallRoot, [string] $Version)
    $versionDir = Get-LicenseLensVersionDir -InstallRoot $InstallRoot -Version $Version
    return [System.IO.Path]::Combine($versionDir, 'licenselens', 'licenselens.exe')
}

function Get-LicenseLensArchiveName {
    param([string] $Version, [bool] $Signed)
    $label = if ($Signed) { '' } else { '-test-only' }
    return "licenselens-windows-x64-$Version$label.zip"
}

# ---------------------------------------------------------------------------
# Small, testable primitives
# ---------------------------------------------------------------------------

function Test-LicenseLensVersion {
    param([string] $Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $false }
    return [bool]([regex]::IsMatch($Version, $script:VersionPattern))
}

function Write-LicenseLensAtomicFile {
    <#
    Write a file atomically: write to a unique temp name, then File.Replace into
    place with a .bak backup on the same volume. On interruption the original or
    the new content is intact; a leftover .bak/.tmp file is harmless and cleaned
    on the next run.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Content
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        [System.IO.Directory]::CreateDirectory($dir) | Out-Null
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $tmp = "$Path.tmp.$([guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllText($tmp, $Content, $utf8)
        if (Test-Path -LiteralPath $Path) {
            [System.IO.File]::Replace($tmp, $Path, "$Path.bak")
        } else {
            [System.IO.File]::Move($tmp, $Path)
        }
    } catch {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        throw
    }
}

function Clear-LicenseLensStaleTemp {
    param([string] $InstallRoot)
    if (-not (Test-Path -LiteralPath $InstallRoot)) { return }
    Get-ChildItem -LiteralPath $InstallRoot -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.(tmp\.[0-9a-f]{32}|bak)$' } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -LiteralPath $InstallRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\.staging-[0-9a-f]{32}$' } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-LicenseLensCurrentVersion {
    param([string] $InstallRoot)
    $path = Join-Path -Path (Get-LicenseLensShimDir -InstallRoot $InstallRoot) -ChildPath 'version.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $value = (Get-Content -LiteralPath $path -Raw).Trim()
    if (-not (Test-LicenseLensVersion -Version $value)) { return $null }
    return $value
}

function Set-LicenseLensCurrentVersion {
    param([string] $InstallRoot, [string] $Version)
    $path = Join-Path -Path (Get-LicenseLensShimDir -InstallRoot $InstallRoot) -ChildPath 'version.txt'
    Write-LicenseLensAtomicFile -Path $path -Content $Version
}

function Get-LicenseLensPreviousVersion {
    param([string] $InstallRoot)
    $path = Join-Path -Path (Get-LicenseLensPreviousDir -InstallRoot $InstallRoot) -ChildPath 'version.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $value = (Get-Content -LiteralPath $path -Raw).Trim()
    if (-not (Test-LicenseLensVersion -Version $value)) { return $null }
    return $value
}

function Set-LicenseLensPreviousVersion {
    param([string] $InstallRoot, [string] $Version)
    $path = Join-Path -Path (Get-LicenseLensPreviousDir -InstallRoot $InstallRoot) -ChildPath 'version.txt'
    Write-LicenseLensAtomicFile -Path $path -Content $Version
}

function Get-LicenseLensState {
    param([string] $InstallRoot)
    $path = Join-Path -Path $InstallRoot -ChildPath 'state.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
    } catch {
        throw "state.json at '$path' is unreadable or corrupt; run Uninstall-LicenseLens or remove it manually."
    }
}

function Set-LicenseLensState {
    param([string] $InstallRoot, [AllowNull()] $State)
    $path = Join-Path -Path $InstallRoot -ChildPath 'state.json'
    $json = $State | ConvertTo-Json -Depth 6
    Write-LicenseLensAtomicFile -Path $path -Content $json
}

function Test-LicenseLensOwnedPath {
    <#
    A path is owned only if it is a real descendant of the install root (never
    the root itself, never a sibling, never an ancestor).
    #>
    param([string] $InstallRoot, [string] $Candidate)
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }
    $rootFull = [System.IO.Path]::GetFullPath($InstallRoot).Replace('/', '\').TrimEnd('\') + '\'
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate).Replace('/', '\').TrimEnd('\')
    return $candidateFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-LicenseLensUserPathContains {
    param([string] $Entry)
    if ([string]::IsNullOrWhiteSpace($Entry)) { return $false }
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrEmpty($user)) { return $false }
    foreach ($seg in $user.Split(';')) {
        if ($seg.Trim().Trim('"') -ieq $Entry.Trim().Trim('"')) { return $true }
    }
    return $false
}

function Add-LicenseLensToUserPath {
    param([string] $Entry)
    if (Test-LicenseLensUserPathContains -Entry $Entry) { return $false }
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrEmpty($user)) {
        $new = $Entry
    } else {
        $new = $user.TrimEnd(';') + ';' + $Entry
    }
    [Environment]::SetEnvironmentVariable('Path', $new, 'User')
    return $true
}

function Remove-LicenseLensFromUserPath {
    param([string] $Entry)
    if ([string]::IsNullOrWhiteSpace($Entry)) { return $false }
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrEmpty($user)) { return $false }
    $parts = $user.Split(';') | Where-Object { $_ -and ($_.Trim().Trim('"') -ine $Entry.Trim().Trim('"')) }
    $new = $parts -join ';'
    if ($new -eq $user) { return $false }
    [Environment]::SetEnvironmentVariable('Path', $new, 'User')
    return $true
}

# ---------------------------------------------------------------------------
# Release manifest and checksum / signature verification
# ---------------------------------------------------------------------------

function Read-LicenseLensManifestRaw {
    param([string] $ManifestPath, [string] $ReleaseBaseUrl)
    if ($ManifestPath) {
        if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
            throw "release manifest not found: $ManifestPath"
        }
        return (Get-Content -LiteralPath $ManifestPath -Raw)
    }
    if ($ReleaseBaseUrl) {
        $url = "$($ReleaseBaseUrl.TrimEnd('/'))/release-manifest.json"
        try {
            return (Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop).Content
        } catch {
            throw "failed to fetch release manifest from '$url': $($_.Exception.Message)"
        }
    }
    throw 'a release manifest is required: pass -ManifestPath (local) or -ReleaseBaseUrl (HTTPS).'
}

function Resolve-LicenseLensArtifact {
    <#
    Return the manifest entry for one Windows x64 archive: { name, sha256, signed }.
    The archive name is matched explicitly when -ArchiveName is supplied, or by
    the `windows-x64-<version>` convention otherwise.
    #>
    param(
        [string] $ManifestPath,
        [string] $ReleaseBaseUrl,
        [Parameter(Mandatory = $true)][string] $Version,
        [string] $ArchiveName
    )
    if (-not (Test-LicenseLensVersion -Version $Version)) {
        throw "invalid version '$Version'"
    }
    $raw = Read-LicenseLensManifestRaw -ManifestPath $ManifestPath -ReleaseBaseUrl $ReleaseBaseUrl
    try {
        $manifest = $raw | ConvertFrom-Json
    } catch {
        throw "release manifest is not valid JSON: $($_.Exception.Message)"
    }
    if ($null -eq $manifest.schema_version -or [int]$manifest.schema_version -ne $script:ManifestSchemaVersion) {
        throw "unsupported release manifest schema_version '$($manifest.schema_version)' (expected $($script:ManifestSchemaVersion))"
    }
    if ($manifest.version -ne $Version) {
        throw "release manifest version '$($manifest.version)' does not match requested version '$Version'"
    }
    if ($null -eq $manifest.artifacts) {
        throw 'release manifest has no artifacts section'
    }
    $match = $null
    foreach ($prop in $manifest.artifacts.PSObject.Properties) {
        if ($null -eq $match) {
            if ($ArchiveName) {
                if ($prop.Name -eq $ArchiveName) { $match = [pscustomobject]@{ name = $prop.Name; entry = $prop.Value } }
            } elseif ($prop.Name -match "windows-x64-$([regex]::Escape($Version))(?:-test-only)?\.zip$") {
                $match = [pscustomobject]@{ name = $prop.Name; entry = $prop.Value }
            }
        }
    }
    if ($null -eq $match) {
        throw "release manifest has no Windows x64 artifact for version '$Version'"
    }
    if (-not $match.entry.sha256 -or $match.entry.sha256 -notmatch $script:Sha256Pattern) {
        throw "release manifest artifact '$($match.name)' has an invalid sha256"
    }
    return [pscustomobject]@{
        name   = $match.name
        sha256 = $match.entry.sha256.ToLower()
        signed = [bool]$match.entry.signed
    }
}

function Test-LicenseLensArchiveChecksum {
    param([string] $ArchivePath, [string] $ExpectedSha256)
    $actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
    if ($actual -ine $ExpectedSha256) {
        throw "checksum mismatch for '$(Split-Path -Leaf $ArchivePath)': expected $ExpectedSha256 but got $actual"
    }
    return $true
}

function Test-LicenseLensSignature {
    param([string] $ExePath, [bool] $SignaturePromised)
    if (-not $SignaturePromised) {
        Write-Warning "artifact is unsigned (test-only); skipping Authenticode verification"
        return $true
    }
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        throw "Authenticode verification is not available on this platform, but the manifest promises a signature; refusing to install."
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $ExePath
    } catch {
        throw "Authenticode verification could not be performed: $($_.Exception.Message)"
    }
    if ($sig.Status -ne 'Valid') {
        throw "Authenticode verification failed: signature is promised but status is '$($sig.Status)'"
    }
    return $true
}

# ---------------------------------------------------------------------------
# Safe extraction (zip-slip protection)
# ---------------------------------------------------------------------------

function Expand-LicenseLensArchive {
    param(
        [Parameter(Mandatory = $true)][string] $ArchivePath,
        [Parameter(Mandatory = $true)][string] $Destination
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destPath = [System.IO.Path]::GetFullPath($Destination)
    # $destFull is a backslash-normalized form used ONLY for zip-slip comparison.
    # On non-Windows the .NET runtime treats '\' as a literal character, so the
    # real directory must be created from the platform-native $destPath — never
    # from $destFull (which would create a literal-backslash directory in cwd).
    $destFull = $destPath.Replace('/', '\').TrimEnd('\') + '\'
    [System.IO.Directory]::CreateDirectory($destPath) | Out-Null
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($entry in $zip.Entries) {
            $relative = $entry.FullName
            if (-not [string]::IsNullOrEmpty($relative)) {
                if ([System.IO.Path]::IsPathRooted($relative)) {
                    throw "zip entry escapes destination (absolute path): $relative"
                }
                $normalized = $relative.Replace('/', '\')
                if ($normalized -eq '..' -or $normalized.StartsWith('..\') -or $normalized -match '\\\.\.(\\|$)') {
                    throw "zip entry escapes destination (path traversal): $relative"
                }
                $target = [System.IO.Path]::GetFullPath((Join-Path -Path $Destination -ChildPath $relative))
                $targetNorm = $target.Replace('/', '\')
                if (-not $targetNorm.StartsWith($destFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "zip entry escapes destination: $relative"
                }
                if ($entry.Name -ne '') {  # skip directory entries
                    $parent = [System.IO.Path]::GetDirectoryName($target)
                    if (-not (Test-Path -LiteralPath $parent)) {
                        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
                    }
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
                }
            }
        }
    } finally {
        $zip.Dispose()
    }
}

# ---------------------------------------------------------------------------
# State bookkeeping
# ---------------------------------------------------------------------------

function New-LicenseLensState {
    param([string] $InstallRoot, [string] $Version)
    return [pscustomobject]@{
        schema_version = $script:StateSchemaVersion
        product        = $script:AppName
        install_id     = [guid]::NewGuid().ToString('N')
        version        = $Version
        versions       = @($Version)
        path_entry     = ''
        owned_paths    = @(
            (Join-Path -Path $InstallRoot -ChildPath '.license'),
            (Get-LicenseLensShimDir -InstallRoot $InstallRoot),
            (Get-LicenseLensPreviousDir -InstallRoot $InstallRoot),
            (Get-LicenseLensVersionsRoot -InstallRoot $InstallRoot)
        )
    }
}

function Add-LicenseLensOwnedPath {
    param($State, [string] $Path)
    $current = @($State.owned_paths)
    if ($current -notcontains $Path) { $current += $Path }
    $State.owned_paths = $current
}

function Add-LicenseLensVersion {
    param($State, [string] $Version)
    $current = @($State.versions)
    if ($current -notcontains $Version) { $current += $Version }
    $State.versions = $current
}

function Write-LicenseLensLauncher {
    param([string] $InstallRoot)
    $shim = Get-LicenseLensShimDir -InstallRoot $InstallRoot
    [System.IO.Directory]::CreateDirectory($shim) | Out-Null
    $cmd = Join-Path -Path $shim -ChildPath 'licenselens.cmd'
    $content = @'
@echo off
setlocal EnableExtensions
set "LL_SHIM=%~dp0"
if not exist "%LL_SHIM%version.txt" (
  >&2 echo licenselens: current version marker is missing; reinstall or run Update-LicenseLens -Rollback.
  exit /b 1
)
set "LL_VERSION="
for /f "usebackq delims=" %%v in ("%LL_SHIM%version.txt") do set "LL_VERSION=%%v"
if not defined LL_VERSION (
  >&2 echo licenselens: current version marker is empty; reinstall or run Update-LicenseLens -Rollback.
  exit /b 1
)
set "LL_EXE=%LL_SHIM%..\versions\%LL_VERSION%\licenselens\licenselens.exe"
if not exist "%LL_EXE%" (
  >&2 echo licenselens: version %LL_VERSION% is not installed at "%LL_EXE%".
  exit /b 1
)
"%LL_EXE%" %*
exit /b %errorlevel%
'@
    [System.IO.File]::WriteAllText($cmd, $content, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

function Install-LicenseLens {
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
    if (-not $InstallRoot) { $InstallRoot = Get-LicenseLensInstallRoot }
    $root = [System.IO.Path]::GetFullPath($InstallRoot)

    if (-not $Version) {
        if ($ArchivePath) {
            $leaf = Split-Path -Leaf $ArchivePath
            if ($leaf -match '^licenselens-windows-x64-(.+?)(?:-test-only)?\.zip$') {
                $Version = $Matches[1]
            } else {
                throw '-Version is required unless -ArchivePath follows the licenselens-windows-x64-<version>[-test-only].zip naming convention.'
            }
        } else {
            throw '-Version is required for HTTPS release installs.'
        }
    }
    if (-not (Test-LicenseLensVersion -Version $Version)) { throw "invalid version '$Version'" }

    $artifact = Resolve-LicenseLensArtifact -ManifestPath $ManifestPath -ReleaseBaseUrl $ReleaseBaseUrl `
        -Version $Version -ArchiveName $(if ($ArchivePath) { Split-Path -Leaf $ArchivePath } else { $null })

    # Obtain the archive bytes and verify the checksum BEFORE extraction.
    $archiveFile = $null
    if ($ArchivePath) {
        if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
            throw "archive not found: $ArchivePath"
        }
        $archiveFile = $ArchivePath
    } else {
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("licenselens-install-" + [guid]::NewGuid().ToString('N'))
        [System.IO.Directory]::CreateDirectory($tempDir) | Out-Null
        $archiveFile = Join-Path $tempDir $artifact.name
        $url = "$($ReleaseBaseUrl.TrimEnd('/'))/$($artifact.name)"
        try {
            Invoke-WebRequest -Uri $url -OutFile $archiveFile -UseBasicParsing -ErrorAction Stop
        } catch {
            throw "failed to download '$url': $($_.Exception.Message)"
        }
    }

    Test-LicenseLensArchiveChecksum -ArchivePath $archiveFile -ExpectedSha256 $artifact.sha256 | Out-Null

    $versionsRoot = Get-LicenseLensVersionsRoot -InstallRoot $root
    [System.IO.Directory]::CreateDirectory($versionsRoot) | Out-Null

    # Fresh state or resume from an existing record (idempotent re-install).
    $state = Get-LicenseLensState -InstallRoot $root
    $isReinstall = $false
    if ($null -ne $state) {
        if ($state.version -eq $Version -and -not $Force) {
            throw "version '$Version' is already the current version; use -Force to reinstall."
        }
        if ($state.version -eq $Version) { $isReinstall = $true }
    }

    $versionDir = Get-LicenseLensVersionDir -InstallRoot $root -Version $Version
    if (Test-Path -LiteralPath $versionDir) {
        if ($isReinstall -or $Force) {
            Remove-Item -LiteralPath $versionDir -Recurse -Force
        } else {
            throw "version '$Version' already has an install directory at '$versionDir'; use -Force to overwrite."
        }
    }

    # Extract to a staging dir on the same volume, verify the exe and any
    # promised Authenticode signature, then atomically rename into versions/.
    # A failed verification therefore leaves nothing in the versions tree.
    $staging = Join-Path -Path $root -ChildPath ('.staging-' + [guid]::NewGuid().ToString('N'))
    try {
        Expand-LicenseLensArchive -ArchivePath $archiveFile -Destination $staging
        $stagedExe = [System.IO.Path]::Combine($staging, 'licenselens', 'licenselens.exe')
        if (-not (Test-Path -LiteralPath $stagedExe -PathType Leaf)) {
            throw "archive for version '$Version' does not contain 'licenselens\licenselens.exe'"
        }
        Test-LicenseLensSignature -ExePath $stagedExe -SignaturePromised $artifact.signed | Out-Null
        Move-Item -LiteralPath $staging -Destination $versionDir
    } finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Preserve the current version as the rollback target before switching.
    $previous = Get-LicenseLensCurrentVersion -InstallRoot $root
    if ($previous -and $previous -ne $Version) {
        Set-LicenseLensPreviousVersion -InstallRoot $root -Version $previous
    }

    Set-LicenseLensCurrentVersion -InstallRoot $root -Version $Version
    Write-LicenseLensLauncher -InstallRoot $root

    $pathEntry = (Get-LicenseLensShimDir -InstallRoot $root)
    if ($null -eq $state) {
        $state = New-LicenseLensState -InstallRoot $root -Version $Version
        $marker = Join-Path -Path $root -ChildPath '.license'
        Write-LicenseLensAtomicFile -Path $marker -Content ($state | ConvertTo-Json -Depth 4)
    } else {
        $state.version = $Version
        Add-LicenseLensVersion -State $state -Version $Version
        Add-LicenseLensOwnedPath -State $state -Path $versionDir
        Add-LicenseLensOwnedPath -State $state -Path (Get-LicenseLensShimDir -InstallRoot $root)
        Add-LicenseLensOwnedPath -State $state -Path (Get-LicenseLensPreviousDir -InstallRoot $root)
    }

    if ($AddToPath) {
        $added = Add-LicenseLensToUserPath -Entry $pathEntry
        if ($added) {
            Write-Host "Added '$pathEntry' to your user PATH."
        } else {
            Write-Host "'$pathEntry' is already on your user PATH."
        }
        $state.path_entry = $pathEntry
    }

    Set-LicenseLensState -InstallRoot $root -State $state
    Clear-LicenseLensStaleTemp -InstallRoot $root

    Write-Host "LicenseLens $Version installed at $root"
    Write-Host "Run '$pathEntry\licenselens.cmd' (or open a new shell and run 'licenselens')."
    if (-not $AddToPath) {
        Write-Host "Tip: re-run with -AddToPath to put 'licenselens' on your user PATH."
    }
}

function Update-LicenseLens {
    [CmdletBinding()]
    param(
        [string] $InstallRoot,
        [string] $ArchivePath,
        [string] $ReleaseBaseUrl,
        [string] $ManifestPath,
        [string] $Version,
        [switch] $Rollback
    )
    if (-not $InstallRoot) { $InstallRoot = Get-LicenseLensInstallRoot }
    $root = [System.IO.Path]::GetFullPath($InstallRoot)

    if ($Rollback) {
        $previous = Get-LicenseLensPreviousVersion -InstallRoot $root
        if (-not $previous) { throw 'no previous version is recorded; nothing to roll back to.' }
        $exe = Get-LicenseLensExePath -InstallRoot $root -Version $previous
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            throw "previous version '$previous' is not present at '$exe'; cannot roll back."
        }
        Set-LicenseLensCurrentVersion -InstallRoot $root -Version $previous
        $state = Get-LicenseLensState -InstallRoot $root
        if ($null -ne $state) {
            $state.version = $previous
            Set-LicenseLensState -InstallRoot $root -State $state
        }
        Write-Host "Rolled back to LicenseLens $previous."
        return
    }

    Install-LicenseLens -InstallRoot $root -ArchivePath $ArchivePath -ReleaseBaseUrl $ReleaseBaseUrl `
        -ManifestPath $ManifestPath -Version $Version
}

function Uninstall-LicenseLens {
    [CmdletBinding()]
    param([string] $InstallRoot)
    if (-not $InstallRoot) { $InstallRoot = Get-LicenseLensInstallRoot }
    $root = [System.IO.Path]::GetFullPath($InstallRoot)

    if (-not (Test-Path -LiteralPath $root)) {
        Write-Host "LicenseLens is not installed (nothing at '$root')."
        return
    }

    $state = Get-LicenseLensState -InstallRoot $root
    if ($null -eq $state) {
        throw "no ownership record (state.json) found at '$root'; refusing to delete unknown files. Remove the directory manually only after confirming it contains no other data."
    }

    $pathEntry = $state.path_entry
    if ($pathEntry -and (Test-LicenseLensOwnedPath -InstallRoot $root -Candidate $pathEntry)) {
        Remove-LicenseLensFromUserPath -Entry $pathEntry | Out-Null
    }

    # Remove only recorded, owned paths — deepest first so parents empty out.
    $owned = @($state.owned_paths) | Sort-Object { $_.Length } -Descending
    foreach ($candidate in $owned) {
        if (Test-LicenseLensOwnedPath -InstallRoot $root -Candidate $candidate) {
            if (Test-Path -LiteralPath $candidate) {
                Remove-Item -LiteralPath $candidate -Recurse -Force
            }
        } else {
            Write-Warning "skipping unowned path '$candidate' (outside install root)"
        }
    }
    $stateFile = Join-Path -Path $root -ChildPath 'state.json'
    if (Test-Path -LiteralPath $stateFile) { Remove-Item -LiteralPath $stateFile -Force }
    Clear-LicenseLensStaleTemp -InstallRoot $root
    # Remove the root only if it is now empty (idempotent; never removes others' files).
    if ((Test-Path -LiteralPath $root) -and -not (Get-ChildItem -LiteralPath $root -Force)) {
        Remove-Item -LiteralPath $root -Force
    }
    Write-Host 'LicenseLens was uninstalled.'
}

Export-ModuleMember -Function @(
    'Get-LicenseLensInstallRoot', 'Get-LicenseLensVersionsRoot', 'Get-LicenseLensVersionDir',
    'Get-LicenseLensShimDir', 'Get-LicenseLensPreviousDir', 'Get-LicenseLensExePath',
    'Get-LicenseLensArchiveName', 'Test-LicenseLensVersion',
    'Write-LicenseLensAtomicFile', 'Clear-LicenseLensStaleTemp',
    'Get-LicenseLensCurrentVersion', 'Set-LicenseLensCurrentVersion',
    'Get-LicenseLensPreviousVersion', 'Set-LicenseLensPreviousVersion',
    'Get-LicenseLensState', 'Set-LicenseLensState', 'Test-LicenseLensOwnedPath',
    'Test-LicenseLensUserPathContains', 'Add-LicenseLensToUserPath', 'Remove-LicenseLensFromUserPath',
    'Read-LicenseLensManifestRaw', 'Resolve-LicenseLensArtifact',
    'Test-LicenseLensArchiveChecksum', 'Test-LicenseLensSignature', 'Expand-LicenseLensArchive',
    'New-LicenseLensState', 'Write-LicenseLensLauncher',
    'Install-LicenseLens', 'Update-LicenseLens', 'Uninstall-LicenseLens'
)
