# Read-only: organization SMTP AUTH (client submission) posture.

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $fixture = Get-LicenseLensFixtureData -Request $Request
    if ($null -ne $fixture) {
        return $fixture
    }

    Assert-LicenseLensExoSession

    try {
        $transport = Invoke-LicenseLensReadCommand -Name 'Get-TransportConfig'
    }
    catch {
        throw (New-LicenseLensAdapterError -Code 'denied' -Message $_.Exception.Message)
    }

    $smtpDisabled = $null
    if ($transport.PSObject.Properties.Name -contains 'SmtpClientAuthenticationDisabled') {
        $smtpDisabled = [bool] $transport.SmtpClientAuthenticationDisabled
    }

    return [pscustomobject][ordered]@{
        adapter    = 'exo_smtp_auth'
        module     = 'ExchangeOnlineManagement'
        collection = 'exchange_smtp_auth'
        surfaces   = [pscustomobject]@{
            smtp_auth = [ordered]@{
                surface   = 'smtp_auth'
                status    = 'ok'
                reason    = ''
                items     = @(
                    [ordered]@{
                        name       = 'TransportConfig'
                        identity   = 'TransportConfig'
                        kind       = 'effective'
                        enabled    = if ($null -eq $smtpDisabled) { $null } else { -not $smtpDisabled }
                        properties = [pscustomobject]@{
                            SmtpClientAuthenticationDisabled = $smtpDisabled
                        }
                        assignments = @()
                    }
                )
                raw_count = 1
            }
        }
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
