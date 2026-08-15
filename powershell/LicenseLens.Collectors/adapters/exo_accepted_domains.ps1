# Read-only: accepted domains inventory.

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
        $domains = @(Invoke-LicenseLensReadCommand -Name 'Get-AcceptedDomain')
    }
    catch {
        throw (New-LicenseLensAdapterError -Code 'denied' -Message $_.Exception.Message)
    }

    $items = @()
    foreach ($domain in $domains) {
        $kind = 'custom'
        if ($domain.PSObject.Properties.Name -contains 'Default' -and [bool]$domain.Default) {
            $kind = 'default'
        }
        $items += ConvertTo-LicenseLensPolicyItem -InputObject $domain -Kind $kind -PropertyNames @(
            'DomainName'
            'DomainType'
            'Default'
            'EmailOnly'
            'MatchSubDomains'
            'OutboundOnly'
        )
    }

    return [pscustomobject][ordered]@{
        adapter    = 'exo_accepted_domains'
        module     = 'ExchangeOnlineManagement'
        collection = 'exchange_accepted_domains'
        surfaces   = [pscustomobject]@{
            accepted_domains = [ordered]@{
                surface   = 'accepted_domains'
                status    = 'ok'
                reason    = ''
                items     = @($items)
                raw_count = $items.Count
            }
        }
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
