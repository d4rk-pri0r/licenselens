# Read-only: Power Platform tenant isolation policy.
# Official module: Microsoft.PowerApps.Administration.PowerShell (Get-PowerAppTenantIsolationPolicy).

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

    if (-not (Test-LicenseLensCommandAvailable -Name 'Get-PowerAppTenantIsolationPolicy')) {
        throw (New-LicenseLensAdapterError -Code 'unavailable' -Message 'Get-PowerAppTenantIsolationPolicy not present (module-version drift)')
    }

    $tenantId = $null
    if ($null -ne $Request.auth -and $Request.auth.PSObject.Properties.Name -contains 'tenant_id') {
        $tenantId = [string] $Request.auth.tenant_id
    }
    if ([string]::IsNullOrWhiteSpace($tenantId) -and $null -ne $Request.params `
            -and $Request.params.PSObject.Properties.Name -contains 'tenant_id') {
        $tenantId = [string] $Request.params.tenant_id
    }

    $items = @()
    $status = 'ok'
    $reason = ''
    try {
        $args = @{}
        if (-not [string]::IsNullOrWhiteSpace($tenantId)) {
            $args['TenantId'] = $tenantId
        }
        $policy = Invoke-LicenseLensReadCommand -Name 'Get-PowerAppTenantIsolationPolicy' -Arguments $args
        $isDisabled = $null
        if ($null -ne $policy) {
            if ($policy.PSObject.Properties.Name -contains 'isDisabled') {
                $isDisabled = [bool] $policy.isDisabled
            }
            elseif ($policy.PSObject.Properties.Name -contains 'IsDisabled') {
                $isDisabled = [bool] $policy.IsDisabled
            }
            elseif ($policy.PSObject.Properties.Name -contains 'properties') {
                $props = $policy.properties
                if ($null -ne $props -and $props.PSObject.Properties.Name -contains 'isDisabled') {
                    $isDisabled = [bool] $props.isDisabled
                }
            }
        }
        $isolationEnabled = $null
        if ($null -ne $isDisabled) {
            $isolationEnabled = -not $isDisabled
        }
        $items += [ordered]@{
            name        = 'TenantIsolation'
            identity    = 'tenant'
            kind        = 'effective'
            enabled     = $isolationEnabled
            properties  = [pscustomobject]@{
                isDisabled        = $isDisabled
                isolationEnabled  = $isolationEnabled
            }
            assignments = @()
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403|denied|Forbidden|Authorization') {
            $status = 'denied'
        }
        else {
            $status = 'error'
        }
        $reason = $msg
        $items = @()
    }

    $surfaces = [ordered]@{
        tenant_isolation = [ordered]@{
            surface   = 'tenant_isolation'
            status    = $status
            reason    = $reason
            items     = @($items)
            raw_count = @($items).Count
        }
    }

    return [pscustomobject][ordered]@{
        adapter      = 'pp_isolation'
        module       = 'Microsoft.PowerApps.Administration.PowerShell'
        collection   = 'power_platform_isolation'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
