# Read-only: Teams app permission policies (legacy) + v2 org-wide app settings.
# Official module: MicrosoftTeams. Get-M365UnifiedTenantSettings may be unsupported
# without interactive auth / newer tenants (explicit unsupported surface).

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $fixture = Get-LicenseLensFixtureData -Request $Request
    if ($null -ne $fixture) {
        return $fixture
    }

    Assert-LicenseLensTeamsSession

    $surfaces = [ordered]@{}
    $appProps = @(
        'DefaultCatalogAppsType'
        'GlobalCatalogAppsType'
        'PrivateCatalogAppsType'
        'DefaultCatalogApps'
        'GlobalCatalogApps'
        'PrivateCatalogApps'
    )

    try {
        if (-not (Test-LicenseLensCommandAvailable -Name 'Get-CsTeamsAppPermissionPolicy')) {
            $surfaces['app_permission_policies'] = New-LicenseLensSurfaceResult `
                -Surface 'app_permission_policies' `
                -Status 'unsupported' `
                -Reason 'cmdlet not present: Get-CsTeamsAppPermissionPolicy'
        }
        else {
            $assignMap = Get-LicenseLensGroupPolicyAssignments -PolicyType 'TeamsAppPermissionPolicy'
            $policies = @(Invoke-LicenseLensReadCommand -Name 'Get-CsTeamsAppPermissionPolicy')
            $items = @()
            foreach ($policy in $policies) {
                $items += ConvertTo-LicenseLensTeamsPolicyItem `
                    -InputObject $policy `
                    -PropertyNames $appProps `
                    -AssignmentsByPolicy $assignMap
            }
            $surfaces['app_permission_policies'] = New-LicenseLensSurfaceResult `
                -Surface 'app_permission_policies' `
                -Status 'ok' `
                -Items $items
        }
    }
    catch {
        $surfaces['app_permission_policies'] = New-LicenseLensSurfaceResult `
            -Surface 'app_permission_policies' `
            -Status 'denied' `
            -Reason $_.Exception.Message
    }

    # v2 org-wide app settings (Get-M365UnifiedTenantSettings) — often unavailable.
    try {
        if (-not (Test-LicenseLensCommandAvailable -Name 'Get-M365UnifiedTenantSettings')) {
            $surfaces['app_settings_v2'] = New-LicenseLensSurfaceResult `
                -Surface 'app_settings_v2' `
                -Status 'unsupported' `
                -Reason 'Get-M365UnifiedTenantSettings not present (v2 org-wide app settings)' `
                -NationalCloudLimited $true
        }
        else {
            $settings = @(Invoke-LicenseLensReadCommand -Name 'Get-M365UnifiedTenantSettings')
            $items = @()
            foreach ($row in $settings) {
                $items += ConvertTo-LicenseLensTeamsPolicyItem `
                    -InputObject $row `
                    -PropertyNames @(
                        'IsAppsEnabled'
                        'IsThirdPartyAppsEnabled'
                        'IsCustomAppsEnabled'
                        'IsMicrosoftAppsEnabled'
                        'AppInstallationOptions'
                    ) `
                    -AssignmentsByPolicy @{}
            }
            if ($items.Count -eq 0) {
                $surfaces['app_settings_v2'] = New-LicenseLensSurfaceResult `
                    -Surface 'app_settings_v2' `
                    -Status 'unsupported' `
                    -Reason 'Get-M365UnifiedTenantSettings returned no data' `
                    -NationalCloudLimited $true
            }
            else {
                $surfaces['app_settings_v2'] = New-LicenseLensSurfaceResult `
                    -Surface 'app_settings_v2' `
                    -Status 'ok' `
                    -Items $items `
                    -NationalCloudLimited $true
            }
        }
    }
    catch {
        $surfaces['app_settings_v2'] = New-LicenseLensSurfaceResult `
            -Surface 'app_settings_v2' `
            -Status 'denied' `
            -Reason $_.Exception.Message `
            -NationalCloudLimited $true
    }

    return [pscustomobject][ordered]@{
        adapter      = 'teams_apps'
        module       = 'MicrosoftTeams'
        collection   = 'teams_apps'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
