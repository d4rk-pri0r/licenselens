# Read-only: Teams federation / external access and unmanaged-user policies.
# Official module: MicrosoftTeams. National-cloud limited for unmanaged consumers.

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

    try {
        if (-not (Test-LicenseLensCommandAvailable -Name 'Get-CsTenantFederationConfiguration')) {
            $surfaces['federation'] = New-LicenseLensSurfaceResult `
                -Surface 'federation' `
                -Status 'unsupported' `
                -Reason 'cmdlet not present: Get-CsTenantFederationConfiguration'
        }
        else {
            $fed = Invoke-LicenseLensReadCommand -Name 'Get-CsTenantFederationConfiguration'
            $allowed = @()
            if ($fed.PSObject.Properties.Name -contains 'AllowedDomains') {
                $domainObj = $fed.AllowedDomains
                if ($null -ne $domainObj) {
                    if ($domainObj.PSObject.Properties.Name -contains 'AllowedDomain') {
                        foreach ($d in @($domainObj.AllowedDomain)) {
                            if ($null -ne $d) {
                                if ($d.PSObject.Properties.Name -contains 'Domain') {
                                    $allowed += [string] $d.Domain
                                }
                                else {
                                    $allowed += [string] $d
                                }
                            }
                        }
                    }
                    elseif ($domainObj -is [System.Array]) {
                        foreach ($d in $domainObj) { $allowed += [string] $d }
                    }
                    else {
                        $allowed += [string] $domainObj
                    }
                }
            }
            $blocked = @()
            if ($fed.PSObject.Properties.Name -contains 'BlockedDomains') {
                foreach ($d in @($fed.BlockedDomains)) {
                    if ($null -ne $d) { $blocked += [string] $d }
                }
            }
            $item = [ordered]@{
                name        = 'TenantFederation'
                identity    = 'Global'
                kind        = 'effective'
                enabled     = $true
                properties  = [pscustomobject]@{
                    AllowFederatedUsers   = if ($fed.PSObject.Properties.Name -contains 'AllowFederatedUsers') { [bool] $fed.AllowFederatedUsers } else { $null }
                    AllowPublicUsers      = if ($fed.PSObject.Properties.Name -contains 'AllowPublicUsers') { [bool] $fed.AllowPublicUsers } else { $null }
                    AllowTeamsConsumer    = if ($fed.PSObject.Properties.Name -contains 'AllowTeamsConsumer') { [bool] $fed.AllowTeamsConsumer } else { $null }
                    AllowTeamsConsumerInbound = if ($fed.PSObject.Properties.Name -contains 'AllowTeamsConsumerInbound') { [bool] $fed.AllowTeamsConsumerInbound } else { $null }
                    SharedSipAddressSpace = if ($fed.PSObject.Properties.Name -contains 'SharedSipAddressSpace') { [bool] $fed.SharedSipAddressSpace } else { $null }
                    AllowedDomains        = @($allowed)
                    BlockedDomains        = @($blocked)
                }
                assignments = @()
            }
            $surfaces['federation'] = New-LicenseLensSurfaceResult `
                -Surface 'federation' `
                -Status 'ok' `
                -Items @($item)
        }
    }
    catch {
        $surfaces['federation'] = New-LicenseLensSurfaceResult `
            -Surface 'federation' `
            -Status 'denied' `
            -Reason $_.Exception.Message
    }

    # Unmanaged / Teams consumer access — not applicable on GCC/GCCH/DoD.
    try {
        if (-not (Test-LicenseLensCommandAvailable -Name 'Get-CsExternalAccessPolicy')) {
            $surfaces['unmanaged_users'] = New-LicenseLensSurfaceResult `
                -Surface 'unmanaged_users' `
                -Status 'unsupported' `
                -Reason 'cmdlet not present: Get-CsExternalAccessPolicy' `
                -NationalCloudLimited $true
        }
        else {
            $assignMap = Get-LicenseLensGroupPolicyAssignments -PolicyType 'ExternalAccessPolicy'
            $policies = @(Invoke-LicenseLensReadCommand -Name 'Get-CsExternalAccessPolicy')
            $items = @()
            foreach ($policy in $policies) {
                $items += ConvertTo-LicenseLensTeamsPolicyItem `
                    -InputObject $policy `
                    -PropertyNames @(
                        'EnableTeamsConsumerAccess'
                        'EnableTeamsConsumerInbound'
                        'EnableFederationAccess'
                        'EnableOutsideAccess'
                        'EnablePublicCloudAccess'
                        'EnablePublicCloudAudioVideoAccess'
                    ) `
                    -AssignmentsByPolicy $assignMap
            }
            $surfaces['unmanaged_users'] = New-LicenseLensSurfaceResult `
                -Surface 'unmanaged_users' `
                -Status 'ok' `
                -Items $items `
                -NationalCloudLimited $true
        }
    }
    catch {
        $surfaces['unmanaged_users'] = New-LicenseLensSurfaceResult `
            -Surface 'unmanaged_users' `
            -Status 'denied' `
            -Reason $_.Exception.Message `
            -NationalCloudLimited $true
    }

    return [pscustomobject][ordered]@{
        adapter      = 'teams_federation'
        module       = 'MicrosoftTeams'
        collection   = 'teams_federation'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
