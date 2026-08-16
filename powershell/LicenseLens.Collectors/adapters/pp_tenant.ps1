# Read-only: Power Platform tenant settings (env creation, portals, share-with-everyone).
# Official module: Microsoft.PowerApps.Administration.PowerShell (Get-TenantSettings only).

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

    if (-not (Test-LicenseLensCommandAvailable -Name 'Get-TenantSettings')) {
        throw (New-LicenseLensAdapterError -Code 'unavailable' -Message 'Get-TenantSettings not present (module-version drift)')
    }

    try {
        $settings = Invoke-LicenseLensReadCommand -Name 'Get-TenantSettings'
    }
    catch {
        throw (New-LicenseLensAdapterError -Code 'denied' -Message $_.Exception.Message)
    }

    function Read-BoolProp {
        param($Obj, [string] $Name)
        if ($null -eq $Obj) { return $null }
        if ($Obj.PSObject.Properties.Name -contains $Name) {
            return [bool] $Obj.$Name
        }
        return $null
    }

    $disableProd = Read-BoolProp -Obj $settings -Name 'disableEnvironmentCreationByNonAdminUsers'
    $disableTrial = Read-BoolProp -Obj $settings -Name 'disableTrialEnvironmentCreationByNonAdminUsers'
    $disablePortals = Read-BoolProp -Obj $settings -Name 'disablePortalsCreationByNonAdminUsers'

    $disableShare = $null
    $pp = $null
    if ($settings.PSObject.Properties.Name -contains 'powerPlatform') {
        $pp = $settings.powerPlatform
    }
    if ($null -ne $pp -and $pp.PSObject.Properties.Name -contains 'powerApps') {
        $disableShare = Read-BoolProp -Obj $pp.powerApps -Name 'disableShareWithEveryone'
    }
    if ($null -eq $disableShare) {
        $disableShare = Read-BoolProp -Obj $settings -Name 'disableShareWithEveryone'
    }

    function New-SettingSurface {
        param(
            [string] $Surface,
            [string] $Name,
            [hashtable] $Properties
        )
        $item = [ordered]@{
            name        = $Name
            identity    = 'tenant'
            kind        = 'effective'
            enabled     = $true
            properties  = [pscustomobject]$Properties
            assignments = @()
        }
        return (New-LicenseLensSurfaceResult -Surface $Surface -Status 'ok' -Items @($item))
    }

    $surfaces = [ordered]@{
        environment_creation = New-SettingSurface -Surface 'environment_creation' -Name 'EnvironmentCreation' -Properties @{
            disableEnvironmentCreationByNonAdminUsers      = $disableProd
            disableTrialEnvironmentCreationByNonAdminUsers = $disableTrial
        }
        power_pages = New-SettingSurface -Surface 'power_pages' -Name 'PowerPagesCreation' -Properties @{
            disablePortalsCreationByNonAdminUsers = $disablePortals
        }
        share_with_everyone = New-SettingSurface -Surface 'share_with_everyone' -Name 'ShareWithEveryone' -Properties @{
            disableShareWithEveryone = $disableShare
        }
        # Portal-only / no Get-* surface for CSP (Dataverse environment setting).
        content_security_policy = (New-LicenseLensSurfaceResult `
                -Surface 'content_security_policy' `
                -Status 'unsupported' `
                -Reason 'portal-only: CSP is per-environment Privacy+Security (Dataverse); no tenant Get-* cmdlet')
    }

    return [pscustomobject][ordered]@{
        adapter      = 'pp_tenant'
        module       = 'Microsoft.PowerApps.Administration.PowerShell'
        collection   = 'power_platform_tenant'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
