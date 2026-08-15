# Read-only: Power BI / Fabric tenant security settings via Get-* only.
# Official modules: MicrosoftPowerBIMgmt / MicrosoftPowerBIMgmt.Admin.
# When Get-PowerBITenantSetting (or Get-FabricTenantSetting) is absent, surfaces
# are marked unsupported (module-version drift / portal-only) — never mutated.

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $fixture = Get-LicenseLensFixtureData -Request $Request
    if ($null -ne $fixture) {
        return $fixture
    }

    Assert-LicenseLensPowerBISession

    $getCmdlet = $null
    foreach ($candidate in @('Get-PowerBITenantSetting', 'Get-FabricTenantSetting')) {
        if (Test-LicenseLensCommandAvailable -Name $candidate) {
            $getCmdlet = $candidate
            break
        }
    }

    if ($null -eq $getCmdlet) {
        $reason = 'unsupported: no Get-PowerBITenantSetting/Get-FabricTenantSetting in installed module (portal or admin REST; module-version drift)'
        $surfaces = [ordered]@{
            publish_to_web              = (New-LicenseLensSurfaceResult -Surface 'publish_to_web' -Status 'unsupported' -Reason $reason)
            guest_access                = (New-LicenseLensSurfaceResult -Surface 'guest_access' -Status 'unsupported' -Reason $reason)
            external_invite             = (New-LicenseLensSurfaceResult -Surface 'external_invite' -Status 'unsupported' -Reason $reason)
            service_principal_api       = (New-LicenseLensSurfaceResult -Surface 'service_principal_api' -Status 'unsupported' -Reason $reason)
            service_principal_profiles  = (New-LicenseLensSurfaceResult -Surface 'service_principal_profiles' -Status 'unsupported' -Reason $reason)
            resource_key_auth           = (New-LicenseLensSurfaceResult -Surface 'resource_key_auth' -Status 'unsupported' -Reason $reason)
            python_r_visuals            = (New-LicenseLensSurfaceResult -Surface 'python_r_visuals' -Status 'unsupported' -Reason $reason)
            sensitivity_labels          = (New-LicenseLensSurfaceResult -Surface 'sensitivity_labels' -Status 'unsupported' -Reason $reason)
        }
        return [pscustomobject][ordered]@{
            adapter      = 'pbi_tenant'
            module       = 'MicrosoftPowerBIMgmt'
            collection   = 'power_bi_tenant'
            surfaces     = [pscustomobject]$surfaces
            collected_at = (Get-Date).ToUniversalTime().ToString('o')
        }
    }

    try {
        $rows = @(Invoke-LicenseLensPagedGet -Name $getCmdlet)
    }
    catch {
        throw (New-LicenseLensAdapterError -Code 'denied' -Message $_.Exception.Message)
    }

    $byName = @{}
    foreach ($row in $rows) {
        $settingName = $null
        foreach ($candidate in @('settingName', 'SettingName', 'name', 'Name', 'tenantSettingName')) {
            if ($row.PSObject.Properties.Name -contains $candidate -and $row.$candidate) {
                $settingName = [string] $row.$candidate
                break
            }
        }
        if ([string]::IsNullOrWhiteSpace($settingName)) { continue }
        $byName[$settingName.ToLowerInvariant()] = $row
    }

    function Find-Setting {
        param([string[]] $Aliases)
        foreach ($alias in $Aliases) {
            $key = $alias.ToLowerInvariant()
            if ($byName.ContainsKey($key)) { return $byName[$key] }
        }
        return $null
    }

    function Surface-FromSetting {
        param(
            [string] $Surface,
            [string[]] $Aliases,
            [string[]] $PropNames = @('enabled', 'Enabled', 'switch', 'tenantSettingGroup')
        )
        $row = Find-Setting -Aliases $Aliases
        if ($null -eq $row) {
            return (New-LicenseLensSurfaceResult `
                    -Surface $Surface `
                    -Status 'unsupported' `
                    -Reason ("absent or unreadable setting aliases: " + ($Aliases -join ',')))
        }
        $enabled = $null
        foreach ($p in @('enabled', 'Enabled', 'switch')) {
            if ($row.PSObject.Properties.Name -contains $p) {
                $enabled = [bool] $row.$p
                break
            }
        }
        $props = [ordered]@{}
        foreach ($p in $PropNames) {
            if ($row.PSObject.Properties.Name -contains $p) {
                $props[$p] = $row.$p
            }
        }
        if ($row.PSObject.Properties.Name -contains 'securityGroups' ) {
            $props['securityGroups'] = $row.securityGroups
        }
        if ($row.PSObject.Properties.Name -contains 'delegateToWorkspace') {
            $props['delegateToWorkspace'] = $row.delegateToWorkspace
        }
        $item = [ordered]@{
            name        = ($Aliases | Select-Object -First 1)
            identity    = ($Aliases | Select-Object -First 1)
            kind        = 'effective'
            enabled     = $enabled
            properties  = [pscustomobject]$props
            assignments = @()
        }
        return (New-LicenseLensSurfaceResult -Surface $Surface -Status 'ok' -Items @($item))
    }

    $surfaces = [ordered]@{
        publish_to_web = Surface-FromSetting -Surface 'publish_to_web' -Aliases @(
            'PublishToWeb', 'publishToWeb'
        )
        guest_access = Surface-FromSetting -Surface 'guest_access' -Aliases @(
            'AllowAzureAdGuestUserAccess', 'allowAzureAdGuestsToAccessPowerBI',
            'GuestUsersCanAccessMicrosoftFabric', 'guestUsersCanAccessMicrosoftFabric'
        )
        external_invite = Surface-FromSetting -Surface 'external_invite' -Aliases @(
            'AllowExternalUsersToCollaborateThroughItemSharing',
            'usersCanInviteGuestUsersToCollaborateThroughItemSharingAndPermissions'
        )
        service_principal_api = Surface-FromSetting -Surface 'service_principal_api' -Aliases @(
            'ServicePrincipalsCanUseReadOnlyAdminAPIs',
            'servicePrincipalsCanCallFabricPublicAPIs',
            'AllowServicePrincipalsUseReadOnlyAdminAPIs'
        )
        service_principal_profiles = Surface-FromSetting -Surface 'service_principal_profiles' -Aliases @(
            'AllowServicePrincipalsCreateAndUseProfiles',
            'allowServicePrincipalsToCreateAndUseProfiles'
        )
        resource_key_auth = Surface-FromSetting -Surface 'resource_key_auth' -Aliases @(
            'BlockResourceKeyAuthentication', 'blockResourceKeyAuthentication'
        )
        python_r_visuals = Surface-FromSetting -Surface 'python_r_visuals' -Aliases @(
            'InteractWithRVisuals', 'interactWithRVisuals',
            'CreateAndUseRAndPythonVisuals', 'createAndUseRAndPythonVisuals'
        )
        sensitivity_labels = Surface-FromSetting -Surface 'sensitivity_labels' -Aliases @(
            'InformationProtectionSensitivityLabel',
            'allowUsersToApplySensitivityLabelsForContent',
            'CreateAndUseSensitivityLabels'
        )
    }

    return [pscustomobject][ordered]@{
        adapter      = 'pbi_tenant'
        module       = 'MicrosoftPowerBIMgmt'
        collection   = 'power_bi_tenant'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
