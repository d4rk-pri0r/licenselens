# Read-only: Purview DLP / labels / audit / retention via SCC Get-* cmdlets.
# Official module: ExchangeOnlineManagement (IPPS session). No remediation verbs.

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $fixture = Get-LicenseLensFixtureData -Request $Request
    if ($null -ne $fixture) {
        return $fixture
    }

    Assert-LicenseLensPurviewSession

    $surfaces = [ordered]@{}

    function Read-PurviewList {
        param(
            [string] $Surface,
            [string] $Cmdlet,
            [string[]] $Props
        )
        $items = @()
        $status = 'ok'
        $reason = ''
        try {
            if (-not (Test-LicenseLensCommandAvailable -Name $Cmdlet)) {
                return [ordered]@{
                    surface   = $Surface
                    status    = 'unsupported'
                    reason    = "cmdlet not present: $Cmdlet (module-version drift)"
                    items     = @()
                    raw_count = 0
                }
            }
            $rows = @(Invoke-LicenseLensPagedGet -Name $Cmdlet)
            foreach ($row in $rows) {
                $kind = Get-LicenseLensPolicyKind -InputObject $row
                $items += ConvertTo-LicenseLensPolicyItem -InputObject $row -Kind $kind -PropertyNames $Props
            }
            if (@($items).Count -eq 0) {
                $reason = "absent: no $Surface configured"
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

    $surfaces['dlp_policies'] = Read-PurviewList `
        -Surface 'dlp_policies' `
        -Cmdlet 'Get-DlpCompliancePolicy' `
        -Props @('Mode', 'Enabled', 'Priority', 'Comment', 'Workload', 'DistributionStatus')

    $surfaces['dlp_rules'] = Read-PurviewList `
        -Surface 'dlp_rules' `
        -Cmdlet 'Get-DlpComplianceRule' `
        -Props @('Disabled', 'Mode', 'Priority', 'Policy', 'BlockAccess', 'NotifyUser')

    $surfaces['sensitivity_labels'] = Read-PurviewList `
        -Surface 'sensitivity_labels' `
        -Cmdlet 'Get-Label' `
        -Props @('DisplayName', 'Priority', 'Disabled', 'Tooltip', 'ContentType', 'ParentId')

    $surfaces['label_policies'] = Read-PurviewList `
        -Surface 'label_policies' `
        -Cmdlet 'Get-LabelPolicy' `
        -Props @('Comment', 'Enabled', 'ExchangeLocation', 'ModernGroupLocation', 'Settings')

    $surfaces['retention_policies'] = Read-PurviewList `
        -Surface 'retention_policies' `
        -Cmdlet 'Get-RetentionCompliancePolicy' `
        -Props @('Enabled', 'Mode', 'Comment', 'Workload', 'DistributionStatus', 'RestrictiveRetention')

    $surfaces['retention_rules'] = Read-PurviewList `
        -Surface 'retention_rules' `
        -Cmdlet 'Get-RetentionComplianceRule' `
        -Props @('Disabled', 'RetentionDuration', 'RetentionComplianceAction', 'Policy')

    # Unified audit log ingestion.
    $auditItems = @()
    $auditStatus = 'ok'
    $auditReason = ''
    try {
        if (Test-LicenseLensCommandAvailable -Name 'Get-AdminAuditLogConfig') {
            $cfg = Invoke-LicenseLensReadCommand -Name 'Get-AdminAuditLogConfig'
            $auditItems += [ordered]@{
                name        = 'AdminAuditLogConfig'
                identity    = 'AdminAuditLogConfig'
                kind        = 'effective'
                enabled     = [bool] $cfg.UnifiedAuditLogIngestionEnabled
                properties  = [pscustomobject]@{
                    UnifiedAuditLogIngestionEnabled = [bool] $cfg.UnifiedAuditLogIngestionEnabled
                    AdminAuditLogEnabled            = [bool] $cfg.AdminAuditLogEnabled
                }
                assignments = @()
            }
        }
        else {
            $auditStatus = 'unsupported'
            $auditReason = 'Get-AdminAuditLogConfig not present (module-version drift)'
        }
    }
    catch {
        $auditStatus = 'denied'
        $auditReason = $_.Exception.Message
        $auditItems = @()
    }
    $surfaces['audit_config'] = [ordered]@{
        surface   = 'audit_config'
        status    = $auditStatus
        reason    = $auditReason
        items     = @($auditItems)
        raw_count = @($auditItems).Count
    }

    return [pscustomobject][ordered]@{
        adapter      = 'purview_governance'
        module       = 'ExchangeOnlineManagement'
        collection   = 'purview_governance'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
