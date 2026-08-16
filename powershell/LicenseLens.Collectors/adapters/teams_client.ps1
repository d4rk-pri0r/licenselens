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

    # Guest access: tenant toggle plus guest calling/messaging restrictions.
    try {
        if (-not (Test-LicenseLensCommandAvailable -Name 'Get-CsTeamsClientConfiguration')) {
            $guestSurface = New-LicenseLensSurfaceResult `
                -Surface 'guest_access' `
                -Status 'unsupported' `
                -Reason 'cmdlet not present: Get-CsTeamsClientConfiguration' `
                -NationalCloudLimited $true
        }
        else {
            $cfg = Invoke-LicenseLensReadCommand -Name 'Get-CsTeamsClientConfiguration'
            $allowGuestUser = $null
            if ($cfg.PSObject.Properties.Name -contains 'AllowGuestUser') {
                $allowGuestUser = [bool] $cfg.AllowGuestUser
            }
            $allowGuestCalling = $null
            if (Test-LicenseLensCommandAvailable -Name 'Get-CsTeamsGuestCallingConfiguration') {
                $guestCalling = Invoke-LicenseLensReadCommand -Name 'Get-CsTeamsGuestCallingConfiguration'
                if ($guestCalling.PSObject.Properties.Name -contains 'AllowGuestCalling') {
                    $allowGuestCalling = [bool] $guestCalling.AllowGuestCalling
                }
            }
            $allowGuestChat = $null
            if (Test-LicenseLensCommandAvailable -Name 'Get-CsTeamsGuestMessagingConfiguration') {
                $guestMessaging = Invoke-LicenseLensReadCommand -Name 'Get-CsTeamsGuestMessagingConfiguration'
                if ($guestMessaging.PSObject.Properties.Name -contains 'AllowGuestChat') {
                    $allowGuestChat = [bool] $guestMessaging.AllowGuestChat
                }
            }
            $guestItem = [ordered]@{
                name        = 'GuestAccess'
                identity    = 'Global'
                kind        = 'effective'
                enabled     = $allowGuestUser
                properties  = [pscustomobject]@{
                    AllowGuestUser    = $allowGuestUser
                    AllowGuestCalling = $allowGuestCalling
                    AllowGuestChat    = $allowGuestChat
                }
                assignments = @()
            }
            $guestSurface = New-LicenseLensSurfaceResult `
                -Surface 'guest_access' `
                -Status 'ok' `
                -Items @($guestItem) `
                -NationalCloudLimited $true
        }
    }
    catch {
        $guestSurface = New-LicenseLensSurfaceResult `
            -Surface 'guest_access' `
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
            guest_access      = $guestSurface
        }
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
