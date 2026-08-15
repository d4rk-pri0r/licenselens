# Read-only: Security & Compliance DLP, sensitivity labels, and audit surfaces.
# Uses official module cmdlets only; no remediation/write verbs.

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $fixture = Get-LicenseLensFixtureData -Request $Request
    if ($null -ne $fixture) {
        return $fixture
    }

    Assert-LicenseLensSccSession

    $surfaces = [ordered]@{}

    function Read-SccList {
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
                    reason    = "cmdlet not present: $Cmdlet"
                    items     = @()
                    raw_count = 0
                }
            }
            $rows = @(Invoke-LicenseLensReadCommand -Name $Cmdlet)
            foreach ($row in $rows) {
                $kind = Get-LicenseLensPolicyKind -InputObject $row
                $items += ConvertTo-LicenseLensPolicyItem -InputObject $row -Kind $kind -PropertyNames $Props
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

    $surfaces['dlp_policies'] = Read-SccList `
        -Surface 'dlp_policies' `
        -Cmdlet 'Get-DlpCompliancePolicy' `
        -Props @('Mode', 'Enabled', 'Priority', 'Comment', 'Workload', 'DistributionStatus')

    $surfaces['dlp_rules'] = Read-SccList `
        -Surface 'dlp_rules' `
        -Cmdlet 'Get-DlpComplianceRule' `
        -Props @('Disabled', 'Mode', 'Priority', 'Policy', 'BlockAccess', 'NotifyUser')

    $surfaces['sensitivity_labels'] = Read-SccList `
        -Surface 'sensitivity_labels' `
        -Cmdlet 'Get-Label' `
        -Props @('DisplayName', 'Priority', 'Disabled', 'Tooltip', 'ContentType', 'ParentId')

    $surfaces['label_policies'] = Read-SccList `
        -Surface 'label_policies' `
        -Cmdlet 'Get-LabelPolicy' `
        -Props @('Comment', 'Enabled', 'ExchangeLocation', 'ModernGroupLocation', 'Settings')

    # Unified audit log ingestion (when exposed on SCC/EXO session).
    $auditItems = @()
    $auditStatus = 'ok'
    $auditReason = ''
    try {
        if (Test-LicenseLensCommandAvailable -Name 'Get-AdminAuditLogConfig') {
            $cfg = Invoke-LicenseLensReadCommand -Name 'Get-AdminAuditLogConfig'
            $auditItems += [ordered]@{
                name       = 'AdminAuditLogConfig'
                identity   = 'AdminAuditLogConfig'
                kind       = 'effective'
                enabled    = [bool] $cfg.UnifiedAuditLogIngestionEnabled
                properties = [pscustomobject]@{
                    UnifiedAuditLogIngestionEnabled = [bool] $cfg.UnifiedAuditLogIngestionEnabled
                    AdminAuditLogEnabled            = [bool] $cfg.AdminAuditLogEnabled
                }
                assignments = @()
            }
        }
        else {
            $auditStatus = 'unsupported'
            $auditReason = 'Get-AdminAuditLogConfig not present'
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
        adapter      = 'scc_compliance'
        module       = 'ExchangeOnlineManagement'
        collection   = 'scc_compliance'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
