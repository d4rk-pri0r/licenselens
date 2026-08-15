# Read-only: Teams client configuration (email integration into channels).
# Official module: MicrosoftTeams. Not applicable on GCC/GCCH/DoD.

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

    try {
        if (-not (Test-LicenseLensCommandAvailable -Name 'Get-CsTeamsClientConfiguration')) {
            $surface = New-LicenseLensSurfaceResult `
                -Surface 'email_integration' `
                -Status 'unsupported' `
                -Reason 'cmdlet not present: Get-CsTeamsClientConfiguration' `
                -NationalCloudLimited $true
        }
        else {
            $cfg = Invoke-LicenseLensReadCommand -Name 'Get-CsTeamsClientConfiguration'
            $allowEmail = $null
            if ($cfg.PSObject.Properties.Name -contains 'AllowEmailIntoChannel') {
                $allowEmail = [bool] $cfg.AllowEmailIntoChannel
            }
            $restricted = $null
            if ($cfg.PSObject.Properties.Name -contains 'RestrictedSenderList') {
                $restricted = $cfg.RestrictedSenderList
            }
            $item = [ordered]@{
                name        = 'ClientConfiguration'
                identity    = 'Global'
                kind        = 'effective'
                enabled     = $allowEmail
                properties  = [pscustomobject]@{
                    AllowEmailIntoChannel = $allowEmail
                    RestrictedSenderList  = $restricted
                }
                assignments = @()
            }
            $surface = New-LicenseLensSurfaceResult `
                -Surface 'email_integration' `
                -Status 'ok' `
                -Items @($item) `
                -NationalCloudLimited $true
        }
    }
    catch {
        $surface = New-LicenseLensSurfaceResult `
            -Surface 'email_integration' `
            -Status 'denied' `
            -Reason $_.Exception.Message `
            -NationalCloudLimited $true
    }

    return [pscustomobject][ordered]@{
        adapter      = 'teams_client'
        module       = 'MicrosoftTeams'
        collection   = 'teams_client'
        surfaces     = [pscustomobject]@{
            email_integration = $surface
        }
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
