# Read-only: organization + mailbox audit configuration (Exchange Online).

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
        $org = Invoke-LicenseLensReadCommand -Name 'Get-OrganizationConfig'
        $surfaces['organization_audit'] = [ordered]@{
            surface    = 'organization_audit'
            status     = 'ok'
            reason     = ''
            items      = @(
                [ordered]@{
                    name       = 'OrganizationConfig'
                    identity   = [string] $org.Identity
                    kind       = 'effective'
                    enabled    = -not [bool] $org.AuditDisabled
                    properties = [pscustomobject]@{
                        AuditDisabled              = [bool] $org.AuditDisabled
                        DefaultPublicFolderProhibitPostQuota = [string] $org.DefaultPublicFolderProhibitPostQuota
                        MailTipsAllTipsEnabled     = [bool] $org.MailTipsAllTipsEnabled
                        MailTipsExternalRecipientsTipsEnabled = [bool] $org.MailTipsExternalRecipientsTipsEnabled
                        MailTipsGroupMetricsEnabled = [bool] $org.MailTipsGroupMetricsEnabled
                        MailTipsMailboxSourcedTipsEnabled = [bool] $org.MailTipsMailboxSourcedTipsEnabled
                    }
                    assignments = @()
                }
            )
            raw_count  = 1
        }
    }
    catch {
        $surfaces['organization_audit'] = [ordered]@{
            surface   = 'organization_audit'
            status    = 'denied'
            reason    = $_.Exception.Message
            items     = @()
            raw_count = 0
        }
    }

    try {
        # Admin audit log config is the unified audit ingestion switch when available.
        $adminAudit = $null
        if (Test-LicenseLensCommandAvailable -Name 'Get-AdminAuditLogConfig') {
            $adminAudit = Invoke-LicenseLensReadCommand -Name 'Get-AdminAuditLogConfig'
        }
        $mailboxAuditItems = @()
        if ($null -ne $adminAudit) {
            $mailboxAuditItems += [ordered]@{
                name       = 'AdminAuditLogConfig'
                identity   = 'AdminAuditLogConfig'
                kind       = 'effective'
                enabled    = [bool] $adminAudit.UnifiedAuditLogIngestionEnabled
                properties = [pscustomobject]@{
                    UnifiedAuditLogIngestionEnabled = [bool] $adminAudit.UnifiedAuditLogIngestionEnabled
                    AdminAuditLogEnabled            = [bool] $adminAudit.AdminAuditLogEnabled
                }
                assignments = @()
            }
        }
        $surfaces['mailbox_audit'] = [ordered]@{
            surface   = 'mailbox_audit'
            status    = 'ok'
            reason    = ''
            items     = @($mailboxAuditItems)
            raw_count = @($mailboxAuditItems).Count
        }
    }
    catch {
        $surfaces['mailbox_audit'] = [ordered]@{
            surface   = 'mailbox_audit'
            status    = 'denied'
            reason    = $_.Exception.Message
            items     = @()
            raw_count = 0
        }
    }

    return [pscustomobject][ordered]@{
        adapter        = 'exo_audit'
        module         = 'ExchangeOnlineManagement'
        collection     = 'exchange_audit'
        surfaces       = [pscustomobject]$surfaces
        collected_at   = (Get-Date).ToUniversalTime().ToString('o')
    }
}
