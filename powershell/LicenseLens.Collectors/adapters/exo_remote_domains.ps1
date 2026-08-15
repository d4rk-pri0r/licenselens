# Read-only: remote domains and auto-forwarding posture.

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
        $domains = @(Invoke-LicenseLensReadCommand -Name 'Get-RemoteDomain')
    }
    catch {
        throw (New-LicenseLensAdapterError -Code 'denied' -Message $_.Exception.Message)
    }

    $items = @()
    foreach ($domain in $domains) {
        $kind = Get-LicenseLensPolicyKind -InputObject $domain
        $items += ConvertTo-LicenseLensPolicyItem -InputObject $domain -Kind $kind -PropertyNames @(
            'DomainName'
            'AllowedOOFType'
            'AutoForwardEnabled'
            'AutoReplyEnabled'
            'DeliveryReportEnabled'
            'NDREnabled'
            'TNEFEnabled'
            'TrustedMailOutboundEnabled'
            'TrustedMailInboundEnabled'
        )
    }

    return [pscustomobject][ordered]@{
        adapter    = 'exo_remote_domains'
        module     = 'ExchangeOnlineManagement'
        collection = 'exchange_remote_domains'
        surfaces   = [pscustomobject]@{
            remote_domains = [ordered]@{
                surface   = 'remote_domains'
                status    = 'ok'
                reason    = ''
                items     = @($items)
                raw_count = $items.Count
            }
        }
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
