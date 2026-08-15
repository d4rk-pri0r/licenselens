# Read-only: DKIM signing configuration per accepted domain.

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
        $configs = @(Invoke-LicenseLensReadCommand -Name 'Get-DkimSigningConfig')
    }
    catch {
        throw (New-LicenseLensAdapterError -Code 'denied' -Message $_.Exception.Message)
    }

    $items = @()
    foreach ($cfg in $configs) {
        $kind = Get-LicenseLensPolicyKind -InputObject $cfg
        $items += ConvertTo-LicenseLensPolicyItem -InputObject $cfg -Kind $kind -PropertyNames @(
            'Domain'
            'Enabled'
            'Status'
            'Selector1CNAME'
            'Selector2CNAME'
            'IsDefault'
        )
    }

    return [pscustomobject][ordered]@{
        adapter    = 'exo_dkim'
        module     = 'ExchangeOnlineManagement'
        collection = 'exchange_dkim'
        surfaces   = [pscustomobject]@{
            dkim = [ordered]@{
                surface   = 'dkim'
                status    = 'ok'
                reason    = ''
                items     = @($items)
                raw_count = $items.Count
            }
        }
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
