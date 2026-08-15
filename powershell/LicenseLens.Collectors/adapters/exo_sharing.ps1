# Read-only: sharing policies (calendar/contact federation posture).

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
        $policies = @(Invoke-LicenseLensReadCommand -Name 'Get-SharingPolicy')
    }
    catch {
        throw (New-LicenseLensAdapterError -Code 'denied' -Message $_.Exception.Message)
    }

    $items = @()
    foreach ($policy in $policies) {
        $kind = Get-LicenseLensPolicyKind -InputObject $policy
        $items += ConvertTo-LicenseLensPolicyItem -InputObject $policy -Kind $kind -PropertyNames @(
            'Domains'
            'Enabled'
            'Default'
        )
    }

    return [pscustomobject][ordered]@{
        adapter    = 'exo_sharing'
        module     = 'ExchangeOnlineManagement'
        collection = 'exchange_sharing'
        surfaces   = [pscustomobject]@{
            sharing_policies = [ordered]@{
                surface   = 'sharing_policies'
                status    = 'ok'
                reason    = ''
                items     = @($items)
                raw_count = $items.Count
            }
        }
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
