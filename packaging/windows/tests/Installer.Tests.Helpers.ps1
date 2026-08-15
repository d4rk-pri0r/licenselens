# Test helpers for Installer.Tests.ps1 (Todo 32). Dot-sourced inside BeforeAll
# so the functions land in the It runspace (Pester 6 does not share top-level
# file functions with It blocks).

function New-TestArchive {
    param([string] $OutDir, [string] $Version)
    $src = Join-Path $OutDir "src-$Version"
    $exeDir = Join-Path $src 'licenselens'
    $catalogDir = Join-Path $exeDir '_internal/data/catalog'
    [System.IO.Directory]::CreateDirectory($catalogDir) | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $exeDir 'licenselens.exe'), "MZ fake executable for $Version")
    [System.IO.File]::WriteAllText((Join-Path $catalogDir 'capabilities.yaml'), 'capabilities: []')
    [System.IO.File]::WriteAllText((Join-Path $exeDir 'README.txt'), 'Security License Lens test fixture')
    $zip = Join-Path $OutDir "licenselens-windows-x64-$Version-test-only.zip"
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path $exeDir -DestinationPath $zip -Force
    $sha = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
    return [pscustomobject]@{ path = $zip; sha256 = $sha; name = (Split-Path -Leaf $zip) }
}

function New-TestManifest {
    param([string] $Version, [string] $ArchiveName, [string] $Sha256, [bool] $Signed)
    $manifest = [ordered]@{
        schema_version = 1
        product        = 'licenselens'
        version        = $Version
        artifacts      = [ordered]@{ $ArchiveName = [ordered]@{ sha256 = $Sha256; signed = $Signed } }
    }
    return ($manifest | ConvertTo-Json -Depth 5)
}

function New-TestSlipArchive {
    param([string] $OutDir)
    $zip = Join-Path $OutDir 'slip.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $fs = [System.IO.File]::Open($zip, [System.IO.FileMode]::Create)
    $archive = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $archive.CreateEntry('../evil.txt')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write('evil'); $writer.Dispose()
    } finally {
        $archive.Dispose(); $fs.Dispose()
    }
    $sha = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
    return [pscustomobject]@{ path = $zip; sha256 = $sha; name = (Split-Path -Leaf $zip) }
}

function Write-TestManifestFile {
    param([string] $Path, [string] $Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}
