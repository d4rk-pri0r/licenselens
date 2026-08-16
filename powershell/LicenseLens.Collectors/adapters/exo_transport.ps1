# Read-only: transport rules and external sender warning signals.

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

    $surfaces = [ordered]@{}

    try {
        $rules = @(Invoke-LicenseLensReadCommand -Name 'Get-TransportRule')
        $items = @()
        foreach ($rule in $rules) {
            $kind = Get-LicenseLensPolicyKind -InputObject $rule
            $item = ConvertTo-LicenseLensPolicyItem -InputObject $rule -Kind $kind -PropertyNames @(
                'State'
                'Mode'
                'Priority'
                'FromScope'
                'SentToScope'
                'SetHeaderName'
                'SetHeaderValue'
                'ApplyHtmlDisclaimerText'
                'PrependSubject'
                'RejectMessageReasonText'
                'BlindCopyTo'
                'RedirectMessageTo'
                'SenderAddressLocation'
                'RecipientDomainIs'
                'ExceptIfRecipientDomainIs'
                'MessageTypeMatches'
                'RecipientAddressMatchesPatterns'
                'RecipientAddressContainsWords'
                'ExceptIfRecipientAddressContainsWords'
            )
            $items += $item
        }
        $surfaces['transport_rules'] = [ordered]@{
            surface   = 'transport_rules'
            status    = 'ok'
            reason    = ''
            items     = @($items)
            raw_count = $items.Count
        }
    }
    catch {
        $surfaces['transport_rules'] = [ordered]@{
            surface   = 'transport_rules'
            status    = 'denied'
            reason    = $_.Exception.Message
            items     = @()
            raw_count = 0
        }
    }

    try {
        $org = Invoke-LicenseLensReadCommand -Name 'Get-OrganizationConfig'
        $surfaces['external_warning'] = [ordered]@{
            surface   = 'external_warning'
            status    = 'ok'
            reason    = ''
            items     = @(
                [ordered]@{
                    name       = 'OrganizationConfig'
                    identity   = [string] $org.Identity
                    kind       = 'effective'
                    enabled    = [bool] $org.MailTipsExternalRecipientsTipsEnabled
                    properties = [pscustomobject]@{
                        MailTipsExternalRecipientsTipsEnabled = [bool] $org.MailTipsExternalRecipientsTipsEnabled
                        MailTipsAllTipsEnabled                = [bool] $org.MailTipsAllTipsEnabled
                    }
                    assignments = @()
                }
            )
            raw_count = 1
        }
    }
    catch {
        $surfaces['external_warning'] = [ordered]@{
            surface   = 'external_warning'
            status    = 'denied'
            reason    = $_.Exception.Message
            items     = @()
            raw_count = 0
        }
    }

    return [pscustomobject][ordered]@{
        adapter      = 'exo_transport'
        module       = 'ExchangeOnlineManagement'
        collection   = 'exchange_transport'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
