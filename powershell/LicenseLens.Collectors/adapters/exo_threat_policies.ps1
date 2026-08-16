# Read-only: EOP/MDO threat policies (malware, phish, Safe Links/Attachments,
# preset security, impersonation fields, quarantine). No Set-/New-/Remove- cmdlets.

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

    function Read-PolicyPair {
        param(
            [string] $Surface,
            [string] $PolicyCmdlet,
            [string] $RuleCmdlet,
            [string[]] $PolicyProps,
            [string[]] $RuleProps
        )
        $items = @()
        $status = 'ok'
        $reason = ''
        try {
            if (-not (Test-LicenseLensCommandAvailable -Name $PolicyCmdlet)) {
                return [ordered]@{
                    surface   = $Surface
                    status    = 'unsupported'
                    reason    = "cmdlet not present: $PolicyCmdlet"
                    items     = @()
                    raw_count = 0
                }
            }
            $policies = @(Invoke-LicenseLensReadCommand -Name $PolicyCmdlet)
            foreach ($policy in $policies) {
                $kind = Get-LicenseLensPolicyKind -InputObject $policy
                $items += ConvertTo-LicenseLensPolicyItem -InputObject $policy -Kind $kind -PropertyNames $PolicyProps
            }
            if (Test-LicenseLensCommandAvailable -Name $RuleCmdlet) {
                $rules = @(Invoke-LicenseLensReadCommand -Name $RuleCmdlet)
                foreach ($rule in $rules) {
                    $kind = 'custom'
                    $items += ConvertTo-LicenseLensPolicyItem -InputObject $rule -Kind $kind -PropertyNames $RuleProps
                }
            }
        }
        catch {
            $status = 'denied'
            $reason = $_.Exception.Message
            $items = @()
        }
        return [ordered]@{
            surface   = $Surface
            status    = $status
            reason    = $reason
            items     = @($items)
            raw_count = @($items).Count
        }
    }

    $surfaces['anti_malware'] = Read-PolicyPair `
        -Surface 'anti_malware' `
        -PolicyCmdlet 'Get-MalwareFilterPolicy' `
        -RuleCmdlet 'Get-MalwareFilterRule' `
        -PolicyProps @('EnableFileFilter', 'ZapEnabled', 'Action', 'IsDefault') `
        -RuleProps @('MalwareFilterPolicy', 'Priority', 'State', 'SentTo', 'SentToMemberOf', 'RecipientDomainIs')

    $surfaces['anti_phish'] = Read-PolicyPair `
        -Surface 'anti_phish' `
        -PolicyCmdlet 'Get-AntiPhishPolicy' `
        -RuleCmdlet 'Get-AntiPhishRule' `
        -PolicyProps @(
            'Enabled'
            'EnableSpoofIntelligence'
            'EnableMailboxIntelligence'
            'EnableMailboxIntelligenceProtection'
            'EnableFirstContactSafetyTips'
            'EnableSimilarUsersSafetyTips'
            'EnableSimilarDomainsSafetyTips'
            'EnableUnusualCharactersSafetyTips'
            'EnableTargetedUserProtection'
            'EnableTargetedDomainsProtection'
            'EnableOrganizationDomainsProtection'
            'TargetedUserProtectionAction'
            'TargetedDomainProtectionAction'
            'ImpersonationProtectionState'
            'IsDefault'
        ) `
        -RuleProps @('AntiPhishPolicy', 'Priority', 'State', 'SentTo', 'SentToMemberOf', 'RecipientDomainIs')

    # Impersonation is modeled from anti-phish policy fields (no separate cmdlet).
    $impItems = @()
    $impStatus = 'ok'
    $impReason = ''
    try {
        if (Test-LicenseLensCommandAvailable -Name 'Get-AntiPhishPolicy') {
            $phish = @(Invoke-LicenseLensReadCommand -Name 'Get-AntiPhishPolicy')
            foreach ($policy in $phish) {
                $kind = Get-LicenseLensPolicyKind -InputObject $policy
                $impItems += ConvertTo-LicenseLensPolicyItem -InputObject $policy -Kind $kind -PropertyNames @(
                    'EnableTargetedUserProtection'
                    'EnableTargetedDomainsProtection'
                    'EnableOrganizationDomainsProtection'
                    'TargetedUserProtectionAction'
                    'TargetedDomainProtectionAction'
                    'ImpersonationProtectionState'
                    'EnableMailboxIntelligence'
                    'IsDefault'
                )
            }
        }
        else {
            $impStatus = 'unsupported'
            $impReason = 'Get-AntiPhishPolicy not present'
        }
    }
    catch {
        $impStatus = 'denied'
        $impReason = $_.Exception.Message
        $impItems = @()
    }
    $surfaces['impersonation'] = [ordered]@{
        surface   = 'impersonation'
        status    = $impStatus
        reason    = $impReason
        items     = @($impItems)
        raw_count = @($impItems).Count
    }

    $surfaces['safe_links'] = Read-PolicyPair `
        -Surface 'safe_links' `
        -PolicyCmdlet 'Get-SafeLinksPolicy' `
        -RuleCmdlet 'Get-SafeLinksRule' `
        -PolicyProps @(
            'EnableSafeLinksForEmail'
            'EnableSafeLinksForTeams'
            'EnableSafeLinksForOffice'
            'ScanUrls'
            'DeliverMessageAfterScan'
            'EnableForInternalSenders'
            'TrackClicks'
            'AllowClickThrough'
            'IsEnabled'
            'RecommendedPolicyType'
        ) `
        -RuleProps @('SafeLinksPolicy', 'Priority', 'State', 'SentTo', 'SentToMemberOf', 'RecipientDomainIs')

    $surfaces['safe_attachments'] = Read-PolicyPair `
        -Surface 'safe_attachments' `
        -PolicyCmdlet 'Get-SafeAttachmentPolicy' `
        -RuleCmdlet 'Get-SafeAttachmentRule' `
        -PolicyProps @(
            'Enable'
            'Action'
            'Redirect'
            'RedirectAddress'
            'ActionOnError'
            'RecommendedPolicyType'
            'IsEnabled'
        ) `
        -RuleProps @('SafeAttachmentPolicy', 'Priority', 'State', 'SentTo', 'SentToMemberOf', 'RecipientDomainIs')

    # Preset security policies (Standard/Strict) via ATP protection policy rules.
    $presetItems = @()
    $presetStatus = 'ok'
    $presetReason = ''
    try {
        if (Test-LicenseLensCommandAvailable -Name 'Get-ATPProtectionPolicyRule') {
            $rules = @(Invoke-LicenseLensReadCommand -Name 'Get-ATPProtectionPolicyRule')
            foreach ($rule in $rules) {
                $kind = Get-LicenseLensPolicyKind -InputObject $rule
                $presetItems += ConvertTo-LicenseLensPolicyItem -InputObject $rule -Kind $kind -PropertyNames @(
                    'State'
                    'Priority'
                    'SafeAttachmentPolicy'
                    'SafeLinksPolicy'
                    'HostedContentFilterPolicy'
                    'AntiPhishPolicy'
                    'ExceptIfSentTo'
                    'ExceptIfSentToMemberOf'
                    'ExceptIfRecipientDomainIs'
                    'Comments'
                )
            }
        }
        elseif (Test-LicenseLensCommandAvailable -Name 'Get-EOPProtectionPolicyRule') {
            $rules = @(Invoke-LicenseLensReadCommand -Name 'Get-EOPProtectionPolicyRule')
            foreach ($rule in $rules) {
                $kind = Get-LicenseLensPolicyKind -InputObject $rule
                $presetItems += ConvertTo-LicenseLensPolicyItem -InputObject $rule -Kind $kind -PropertyNames @(
                    'State'
                    'Priority'
                    'HostedContentFilterPolicy'
                    'MalwareFilterPolicy'
                    'AntiPhishPolicy'
                )
            }
        }
        else {
            $presetStatus = 'unsupported'
            $presetReason = 'preset policy rule cmdlets not present'
        }
    }
    catch {
        $presetStatus = 'denied'
        $presetReason = $_.Exception.Message
        $presetItems = @()
    }
    $surfaces['preset_security'] = [ordered]@{
        surface   = 'preset_security'
        status    = $presetStatus
        reason    = $presetReason
        items     = @($presetItems)
        raw_count = @($presetItems).Count
    }

    $qItems = @()
    $qStatus = 'ok'
    $qReason = ''
    try {
        if (Test-LicenseLensCommandAvailable -Name 'Get-QuarantinePolicy') {
            $policies = @(Invoke-LicenseLensReadCommand -Name 'Get-QuarantinePolicy')
            foreach ($policy in $policies) {
                $kind = Get-LicenseLensPolicyKind -InputObject $policy
                $qItems += ConvertTo-LicenseLensPolicyItem -InputObject $policy -Kind $kind -PropertyNames @(
                    'EndUserQuarantinePermissionsValue'
                    'EsnEnabled'
                    'QuarantinePolicyType'
                    'RetentionDurationInDays'
                )
            }
        }
        else {
            $qStatus = 'unsupported'
            $qReason = 'Get-QuarantinePolicy not present'
        }
    }
    catch {
        $qStatus = 'denied'
        $qReason = $_.Exception.Message
        $qItems = @()
    }
    $surfaces['quarantine'] = [ordered]@{
        surface   = 'quarantine'
        status    = $qStatus
        reason    = $qReason
        items     = @($qItems)
        raw_count = @($qItems).Count
    }

    $surfaces['anti_spam'] = Read-PolicyPair `
        -Surface 'anti_spam' `
        -PolicyCmdlet 'Get-HostedContentFilterPolicy' `
        -RuleCmdlet 'Get-HostedContentFilterRule' `
        -PolicyProps @(
            'SpamAction'
            'HighConfidenceSpamAction'
            'PhishSpamAction'
            'HighConfidencePhishAction'
            'BulkSpamAction'
            'AllowedSenders'
            'AllowedSenderDomains'
            'IsDefault'
            'RecommendedPolicyType'
        ) `
        -RuleProps @('HostedContentFilterPolicy', 'Priority', 'State', 'SentTo', 'SentToMemberOf', 'RecipientDomainIs')

    $surfaces['connection_filter'] = Read-PolicyPair `
        -Surface 'connection_filter' `
        -PolicyCmdlet 'Get-HostedConnectionFilterPolicy' `
        -RuleCmdlet 'Get-HostedConnectionFilterRule' `
        -PolicyProps @(
            'IPAllowList'
            'IPBlockList'
            'EnableSafeList'
            'IsDefault'
        ) `
        -RuleProps @('HostedConnectionFilterPolicy', 'Priority', 'State')

    $surfaces['outbound_spam'] = Read-PolicyPair `
        -Surface 'outbound_spam' `
        -PolicyCmdlet 'Get-HostedOutboundSpamFilterPolicy' `
        -RuleCmdlet 'Get-HostedOutboundSpamFilterRule' `
        -PolicyProps @(
            'AutoForwardingEnabled'
            'IsDefault'
        ) `
        -RuleProps @('HostedOutboundSpamFilterPolicy', 'Priority', 'State')

    $atpItems = @()
    $atpStatus = 'ok'
    $atpReason = ''
    try {
        if (Test-LicenseLensCommandAvailable -Name 'Get-AtpPolicyForO365') {
            $policies = @(Invoke-LicenseLensReadCommand -Name 'Get-AtpPolicyForO365')
            foreach ($policy in $policies) {
                $kind = Get-LicenseLensPolicyKind -InputObject $policy
                $atpItems += ConvertTo-LicenseLensPolicyItem -InputObject $policy -Kind $kind -PropertyNames @(
                    'EnableATPForSPOTeamsODB'
                    'EnableSafeDocs'
                    'AllowSafeDocsOpen'
                    'EnableSafeAttachmentsForSPOTeamsODB'
                )
            }
        }
        else {
            $atpStatus = 'unsupported'
            $atpReason = 'Get-AtpPolicyForO365 not present'
        }
    }
    catch {
        $atpStatus = 'denied'
        $atpReason = $_.Exception.Message
        $atpItems = @()
    }
    $surfaces['atp_global'] = [ordered]@{
        surface   = 'atp_global'
        status    = $atpStatus
        reason    = $atpReason
        items     = @($atpItems)
        raw_count = @($atpItems).Count
    }

    return [pscustomobject][ordered]@{
        adapter      = 'exo_threat_policies'
        module       = 'ExchangeOnlineManagement'
        collection   = 'exchange_threat_policies'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
