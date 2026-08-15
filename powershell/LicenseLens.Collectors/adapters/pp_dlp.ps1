# Read-only: Power Platform connector DLP policies + environment coverage.
# Official module: Microsoft.PowerApps.Administration.PowerShell (Get-DlpPolicy).

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $fixture = Get-LicenseLensFixtureData -Request $Request
    if ($null -ne $fixture) {
        return $fixture
    }

    Assert-LicenseLensPowerAppsSession

    if (-not (Test-LicenseLensCommandAvailable -Name 'Get-DlpPolicy')) {
        throw (New-LicenseLensAdapterError -Code 'unavailable' -Message 'Get-DlpPolicy not present (module-version drift)')
    }

    $items = @()
    $status = 'ok'
    $reason = ''
    try {
        $rows = @(Invoke-LicenseLensPagedGet -Name 'Get-DlpPolicy')
        foreach ($row in $rows) {
            $display = 'unknown'
            foreach ($candidate in @('DisplayName', 'displayName', 'Name', 'name')) {
                if ($row.PSObject.Properties.Name -contains $candidate -and $row.$candidate) {
                    $display = [string] $row.$candidate
                    break
                }
            }
            $identity = $null
            foreach ($candidate in @('PolicyName', 'name', 'Name', 'Id')) {
                if ($row.PSObject.Properties.Name -contains $candidate -and $row.$candidate) {
                    $identity = [string] $row.$candidate
                    break
                }
            }
            $envType = $null
            foreach ($candidate in @('EnvironmentType', 'environmentType', 'FilterType')) {
                if ($row.PSObject.Properties.Name -contains $candidate) {
                    $envType = [string] $row.$candidate
                    break
                }
            }
            $envNames = @()
            if ($row.PSObject.Properties.Name -contains 'Environments') {
                foreach ($env in @($row.Environments)) {
                    if ($null -eq $env) { continue }
                    if ($env -is [string]) {
                        $envNames += $env
                    }
                    elseif ($env.PSObject.Properties.Name -contains 'name') {
                        $envNames += [string] $env.name
                    }
                    elseif ($env.PSObject.Properties.Name -contains 'Name') {
                        $envNames += [string] $env.Name
                    }
                    elseif ($env.PSObject.Properties.Name -contains 'id') {
                        $envNames += [string] $env.id
                    }
                }
            }
            $items += [ordered]@{
                name        = $display
                identity    = $identity
                kind        = 'custom'
                enabled     = $true
                properties  = [pscustomobject]@{
                    EnvironmentType = $envType
                    EnvironmentCount = @($envNames).Count
                    Environments     = @($envNames)
                }
                assignments = @($envNames)
            }
        }
    }
    catch {
        $status = 'denied'
        $reason = $_.Exception.Message
        $items = @()
    }

    $surfaces = [ordered]@{
        dlp_policies = [ordered]@{
            surface   = 'dlp_policies'
            status    = $status
            reason    = $reason
            items     = @($items)
            raw_count = @($items).Count
        }
    }

    if ($status -eq 'ok' -and @($items).Count -eq 0) {
        $surfaces['dlp_policies'].reason = 'absent: no DLP policies configured'
    }

    return [pscustomobject][ordered]@{
        adapter      = 'pp_dlp'
        module       = 'Microsoft.PowerApps.Administration.PowerShell'
        collection   = 'power_platform_dlp'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
