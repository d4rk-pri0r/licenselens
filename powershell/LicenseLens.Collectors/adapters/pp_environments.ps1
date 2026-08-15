# Read-only: Power Platform environments (paginated).
# Official module: Microsoft.PowerApps.Administration.PowerShell (Get-AdminPowerAppEnvironment).

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

    if (-not (Test-LicenseLensCommandAvailable -Name 'Get-AdminPowerAppEnvironment')) {
        throw (New-LicenseLensAdapterError -Code 'unavailable' -Message 'Get-AdminPowerAppEnvironment not present (module-version drift)')
    }

    $items = @()
    $status = 'ok'
    $reason = ''
    try {
        $rows = @(Invoke-LicenseLensPagedGet -Name 'Get-AdminPowerAppEnvironment')
        foreach ($row in $rows) {
            $name = 'unknown'
            foreach ($candidate in @('DisplayName', 'EnvironmentName', 'EnvironmentDisplayName', 'Name')) {
                if ($row.PSObject.Properties.Name -contains $candidate -and $row.$candidate) {
                    $name = [string] $row.$candidate
                    break
                }
            }
            $identity = $null
            foreach ($candidate in @('EnvironmentName', 'Name', 'Id')) {
                if ($row.PSObject.Properties.Name -contains $candidate -and $row.$candidate) {
                    $identity = [string] $row.$candidate
                    break
                }
            }
            $isDefault = $false
            if ($row.PSObject.Properties.Name -contains 'IsDefault') {
                $isDefault = [bool] $row.IsDefault
            }
            elseif ($row.PSObject.Properties.Name -contains 'isDefault') {
                $isDefault = [bool] $row.isDefault
            }
            $sku = $null
            foreach ($candidate in @('EnvironmentType', 'environmentSku', 'Type')) {
                if ($row.PSObject.Properties.Name -contains $candidate) {
                    $sku = [string] $row.$candidate
                    break
                }
            }
            $hasDataverse = $null
            if ($row.PSObject.Properties.Name -contains 'CommonDataServiceDatabaseProvisioningState') {
                $hasDataverse = ([string]$row.CommonDataServiceDatabaseProvisioningState -eq 'Succeeded')
            }
            elseif ($row.PSObject.Properties.Name -contains 'HasDataverse') {
                $hasDataverse = [bool] $row.HasDataverse
            }
            $items += [ordered]@{
                name        = $name
                identity    = $identity
                kind        = $(if ($isDefault) { 'default' } else { 'custom' })
                enabled     = $true
                properties  = [pscustomobject]@{
                    IsDefault     = $isDefault
                    EnvironmentType = $sku
                    HasDataverse  = $hasDataverse
                    Location      = $(if ($row.PSObject.Properties.Name -contains 'Location') { [string]$row.Location } else { $null })
                }
                assignments = @()
            }
        }
    }
    catch {
        $status = 'denied'
        $reason = $_.Exception.Message
        $items = @()
    }

    $surfaces = [ordered]@{
        environments = [ordered]@{
            surface   = 'environments'
            status    = $status
            reason    = $reason
            items     = @($items)
            raw_count = @($items).Count
        }
    }

    # Explicit empty-list is absent configuration (ok + raw_count 0), not unreadable.
    if ($status -eq 'ok' -and @($items).Count -eq 0) {
        $surfaces['environments'].reason = 'absent: no environments returned'
    }

    return [pscustomobject][ordered]@{
        adapter      = 'pp_environments'
        module       = 'Microsoft.PowerApps.Administration.PowerShell'
        collection   = 'power_platform_environments'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
