# Pester contract tests for the LicenseLens per-user installer (Todo 32).
#
# Runs on any host with PowerShell + Pester (v5/v6 compatible). Windows-only
# behaviors (real Authenticode validity, hard file locking) are gated with
# -Skip:(-not $IsWindows) so they run on Windows CI and are clearly skipped here.
#
# Note: module/helper paths are resolved inside each BeforeAll (never at the top
# level), because Pester 6 does not share top-level file variables with test
# blocks.

Describe 'LicenseLens installer — happy path lifecycle' {
    BeforeAll {
        $modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'LicenseLens.Installer.psm1'
        $helperPath = Join-Path $PSScriptRoot 'Installer.Tests.Helpers.ps1'
        . $helperPath
        Import-Module $modulePath -Force
        $script:happyRoot = Join-Path $TestDrive 'localappdata\LicenseLens'
    }

    It 'install → update → rollback → uninstall (idempotent), verifying checksums and switching the shim atomically' {
        # --- install 0.3.0 ---
        $a030 = New-TestArchive -OutDir $TestDrive -Version '0.3.0'
        $m030 = New-TestManifest -Version '0.3.0' -ArchiveName $a030.name -Sha256 $a030.sha256 -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'manifest-0.3.0.json') -Content $m030
        Install-LicenseLens -InstallRoot $script:happyRoot -ArchivePath $a030.path `
            -ManifestPath (Join-Path $TestDrive 'manifest-0.3.0.json')

        (Get-LicenseLensCurrentVersion -InstallRoot $script:happyRoot) | Should -Be '0.3.0'
        (Test-Path -LiteralPath (Get-LicenseLensExePath -InstallRoot $script:happyRoot -Version '0.3.0')) | Should -Be $true
        $launcher = Join-Path (Get-LicenseLensShimDir -InstallRoot $script:happyRoot) 'licenselens.cmd'
        (Test-Path -LiteralPath $launcher) | Should -Be $true
        (Get-Content -LiteralPath $launcher -Raw) | Should -Match 'versions'
        (Get-Content -LiteralPath $launcher -Raw) | Should -Match 'licenselens\.exe'
        (Test-Path -LiteralPath (Join-Path $script:happyRoot '.license')) | Should -Be $true
        $state = Get-LicenseLensState -InstallRoot $script:happyRoot
        $state.version | Should -Be '0.3.0'
        $state.path_entry | Should -Be ''
        ($state.owned_paths -contains (Join-Path $script:happyRoot 'current')) | Should -Be $true

        # --- update to 0.4.0 (preserves previous version for rollback) ---
        $a040 = New-TestArchive -OutDir $TestDrive -Version '0.4.0'
        $m040 = New-TestManifest -Version '0.4.0' -ArchiveName $a040.name -Sha256 $a040.sha256 -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'manifest-0.4.0.json') -Content $m040
        Update-LicenseLens -InstallRoot $script:happyRoot -ArchivePath $a040.path `
            -ManifestPath (Join-Path $TestDrive 'manifest-0.4.0.json')

        (Get-LicenseLensCurrentVersion -InstallRoot $script:happyRoot) | Should -Be '0.4.0'
        (Get-LicenseLensPreviousVersion -InstallRoot $script:happyRoot) | Should -Be '0.3.0'
        (Test-Path -LiteralPath (Get-LicenseLensExePath -InstallRoot $script:happyRoot -Version '0.3.0')) | Should -Be $true
        (Test-Path -LiteralPath (Get-LicenseLensExePath -InstallRoot $script:happyRoot -Version '0.4.0')) | Should -Be $true

        # --- rollback ---
        Update-LicenseLens -InstallRoot $script:happyRoot -Rollback
        (Get-LicenseLensCurrentVersion -InstallRoot $script:happyRoot) | Should -Be '0.3.0'

        # --- uninstall, then idempotent second run ---
        Uninstall-LicenseLens -InstallRoot $script:happyRoot
        (Test-Path -LiteralPath $script:happyRoot) | Should -Be $false
        Uninstall-LicenseLens -InstallRoot $script:happyRoot
    }
}

Describe 'LicenseLens installer — negative paths' {
    BeforeAll {
        $modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'LicenseLens.Installer.psm1'
        $helperPath = Join-Path $PSScriptRoot 'Installer.Tests.Helpers.ps1'
        . $helperPath
        Import-Module $modulePath -Force
        $script:negRoot = Join-Path $TestDrive 'neg\LicenseLens'
    }

    It 'rejects a checksum mismatch before extraction' {
        $a = New-TestArchive -OutDir $TestDrive -Version '0.5.0'
        $bad = New-TestManifest -Version '0.5.0' -ArchiveName $a.name -Sha256 ('0' * 64) -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'neg-bad-hash.json') -Content $bad
        { Install-LicenseLens -InstallRoot $script:negRoot -ArchivePath $a.path `
                -ManifestPath (Join-Path $TestDrive 'neg-bad-hash.json') } |
            Should -Throw '*checksum mismatch*'
        (Test-Path -LiteralPath (Get-LicenseLensVersionDir -InstallRoot $script:negRoot -Version '0.5.0')) |
            Should -Be $false
    }

    It 'refuses when a signature is promised but cannot be validated' {
        $a = New-TestArchive -OutDir $TestDrive -Version '0.6.0'
        $m = New-TestManifest -Version '0.6.0' -ArchiveName $a.name -Sha256 $a.sha256 -Signed $true
        Write-TestManifestFile -Path (Join-Path $TestDrive 'neg-signed.json') -Content $m
        { Install-LicenseLens -InstallRoot $script:negRoot -ArchivePath $a.path `
                -ManifestPath (Join-Path $TestDrive 'neg-signed.json') } |
            Should -Throw '*Authenticode*'
        (Test-Path -LiteralPath (Get-LicenseLensVersionDir -InstallRoot $script:negRoot -Version '0.6.0')) |
            Should -Be $false
    }

    It 'rejects a zip-slip archive (path traversal)' {
        $s = New-TestSlipArchive -OutDir $TestDrive
        $m = New-TestManifest -Version '0.6.1' -ArchiveName $s.name -Sha256 $s.sha256 -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'neg-slip.json') -Content $m
        { Install-LicenseLens -InstallRoot $script:negRoot -ArchivePath $s.path -Version '0.6.1' `
                -ManifestPath (Join-Path $TestDrive 'neg-slip.json') } |
            Should -Throw '*escapes destination*'
    }

    It 'fails cleanly when the release URL is unreachable (offline update)' {
        $root = Join-Path $TestDrive 'offline\LicenseLens'
        { Install-LicenseLens -InstallRoot $root `
                -ReleaseBaseUrl 'http://127.0.0.1:9' -Version '0.7.0' } |
            Should -Throw '*failed to fetch release manifest*'
        (Test-Path -LiteralPath $root) | Should -Be $false
    }

    It 'recovers from an interrupted switch via rollback' {
        $root = Join-Path $TestDrive 'interrupted\LicenseLens'
        $a = New-TestArchive -OutDir $TestDrive -Version '0.3.0'
        $m = New-TestManifest -Version '0.3.0' -ArchiveName $a.name -Sha256 $a.sha256 -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'int-manifest.json') -Content $m
        Install-LicenseLens -InstallRoot $root -ArchivePath $a.path -ManifestPath (Join-Path $TestDrive 'int-manifest.json')

        # Simulate a crash after the shim was switched to a version that never staged.
        Set-LicenseLensPreviousVersion -InstallRoot $root -Version '0.3.0'
        Set-LicenseLensCurrentVersion -InstallRoot $root -Version '0.4.0'

        Update-LicenseLens -InstallRoot $root -Rollback
        (Get-LicenseLensCurrentVersion -InstallRoot $root) | Should -Be '0.3.0'
    }

    It 'uninstall removes only owned paths and preserves foreign files' {
        $root = Join-Path $TestDrive 'foreign\LicenseLens'
        $a = New-TestArchive -OutDir $TestDrive -Version '0.3.0'
        $m = New-TestManifest -Version '0.3.0' -ArchiveName $a.name -Sha256 $a.sha256 -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'for-manifest.json') -Content $m
        Install-LicenseLens -InstallRoot $root -ArchivePath $a.path -ManifestPath (Join-Path $TestDrive 'for-manifest.json')

        $foreign = Join-Path $root 'foreign.txt'
        [System.IO.File]::WriteAllText($foreign, 'not owned by licenselens')
        Uninstall-LicenseLens -InstallRoot $root

        (Test-Path -LiteralPath $foreign) | Should -Be $true
        (Test-Path -LiteralPath (Get-LicenseLensVersionDir -InstallRoot $root -Version '0.3.0')) | Should -Be $false
    }

    It 'does not record a PATH entry without -AddToPath consent' {
        $root = Join-Path $TestDrive 'nopath\LicenseLens'
        $a = New-TestArchive -OutDir $TestDrive -Version '0.3.0'
        $m = New-TestManifest -Version '0.3.0' -ArchiveName $a.name -Sha256 $a.sha256 -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'nopath-manifest.json') -Content $m
        Install-LicenseLens -InstallRoot $root -ArchivePath $a.path -ManifestPath (Join-Path $TestDrive 'nopath-manifest.json')
        $state = Get-LicenseLensState -InstallRoot $root
        $state.path_entry | Should -Be ''
    }

    It 'refuses to delete unknown files when the ownership record is missing' {
        $root = Join-Path $TestDrive 'orphan\LicenseLens'
        [System.IO.Directory]::CreateDirectory($root) | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $root 'secret.txt'), 'keep me')
        { Uninstall-LicenseLens -InstallRoot $root } | Should -Throw '*ownership record*'
        (Test-Path -LiteralPath (Join-Path $root 'secret.txt')) | Should -Be $true
    }

    It 'rejects a hard-locked target file (Windows share lock)' -Skip:(-not $IsWindows) {
        $root = Join-Path $TestDrive 'locked\LicenseLens'
        $a = New-TestArchive -OutDir $TestDrive -Version '0.3.0'
        $m = New-TestManifest -Version '0.3.0' -ArchiveName $a.name -Sha256 $a.sha256 -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'lock-manifest.json') -Content $m
        Install-LicenseLens -InstallRoot $root -ArchivePath $a.path -ManifestPath (Join-Path $TestDrive 'lock-manifest.json')

        $exe = Get-LicenseLensExePath -InstallRoot $root -Version '0.3.0'
        $handle = [System.IO.File]::Open($exe, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            { Install-LicenseLens -InstallRoot $root -ArchivePath $a.path `
                    -ManifestPath (Join-Path $TestDrive 'lock-manifest.json') -Force } |
                Should -Throw
        } finally {
            $handle.Dispose()
        }
    }
}

Describe 'LicenseLens installer — pure helpers' {
    BeforeAll {
        $modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'LicenseLens.Installer.psm1'
        $helperPath = Join-Path $PSScriptRoot 'Installer.Tests.Helpers.ps1'
        . $helperPath
        Import-Module $modulePath -Force
    }

    It 'rejects invalid and traversal version strings' {
        Test-LicenseLensVersion -Version '0.3.0' | Should -Be $true
        Test-LicenseLensVersion -Version '1.2.3-beta.1' | Should -Be $true
        Test-LicenseLensVersion -Version '../0.3.0' | Should -Be $false
        Test-LicenseLensVersion -Version 'latest' | Should -Be $false
        Test-LicenseLensVersion -Version '' | Should -Be $false
    }

    It 'labels unsigned archives test-only and signed archives plainly' {
        (Get-LicenseLensArchiveName -Version '0.3.0' -Signed $false) | Should -Be 'licenselens-windows-x64-0.3.0-test-only.zip'
        (Get-LicenseLensArchiveName -Version '0.3.0' -Signed $true) | Should -Be 'licenselens-windows-x64-0.3.0.zip'
    }

    It 'Test-LicenseLensOwnedPath guards ancestors, siblings, and the root itself' {
        $root = Join-Path $TestDrive 'owned/LicenseLens'
        (Test-LicenseLensOwnedPath -InstallRoot $root -Candidate (Join-Path $root 'versions/0.3.0')) | Should -Be $true
        (Test-LicenseLensOwnedPath -InstallRoot $root -Candidate $root) | Should -Be $false
        (Test-LicenseLensOwnedPath -InstallRoot $root -Candidate (Join-Path $TestDrive 'owned/Other')) | Should -Be $false
        (Test-LicenseLensOwnedPath -InstallRoot $root -Candidate (Join-Path $TestDrive 'owned')) | Should -Be $false
        (Test-LicenseLensOwnedPath -InstallRoot $root -Candidate '') | Should -Be $false
    }

    It 'Test-LicenseLensSignature skips verification for unsigned (test-only) artifacts' {
        Test-LicenseLensSignature -ExePath 'nope.exe' -SignaturePromised $false | Should -Be $true
    }

    It 'Resolve-LicenseLensArtifact rejects a manifest with the wrong version' {
        $m = New-TestManifest -Version '0.3.0' -ArchiveName 'licenselens-windows-x64-0.3.0-test-only.zip' -Sha256 ('a' * 64) -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'mismatch.json') -Content $m
        { Resolve-LicenseLensArtifact -ManifestPath (Join-Path $TestDrive 'mismatch.json') -Version '9.9.9' } |
            Should -Throw '*does not match requested version*'
    }

    It 'Resolve-LicenseLensArtifact rejects an invalid sha256 in the manifest' {
        $m = New-TestManifest -Version '0.3.0' -ArchiveName 'licenselens-windows-x64-0.3.0-test-only.zip' -Sha256 'not-a-hex-hash' -Signed $false
        Write-TestManifestFile -Path (Join-Path $TestDrive 'badsha.json') -Content $m
        { Resolve-LicenseLensArtifact -ManifestPath (Join-Path $TestDrive 'badsha.json') -Version '0.3.0' } |
            Should -Throw '*invalid sha256*'
    }
}
