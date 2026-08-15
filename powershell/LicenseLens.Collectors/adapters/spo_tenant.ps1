# Read-only: SharePoint/OneDrive tenant sharing, default links, expiration, domains.
# Official module: Microsoft.Online.SharePoint.PowerShell (Get-SPOTenant only).

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $fixture = Get-LicenseLensFixtureData -Request $Request
    if ($null -ne $fixture) {
        return $fixture
    }

    Assert-LicenseLensSpoSession

    try {
        $tenant = Invoke-LicenseLensReadCommand -Name 'Get-SPOTenant'
    }
    catch {
        throw (New-LicenseLensAdapterError -Code 'denied' -Message $_.Exception.Message)
    }

    function New-TenantSurface {
        param(
            [string] $Surface,
            [string] $Name,
            [hashtable] $Properties,
            [object[]] $Assignments = @()
        )
        $item = [ordered]@{
            name        = $Name
            identity    = 'tenant'
            kind        = 'effective'
            enabled     = $true
            properties  = [pscustomobject]$Properties
            assignments = @($Assignments)
        }
        return (New-LicenseLensSurfaceResult -Surface $Surface -Status 'ok' -Items @($item))
    }

    $sharingCapability = $null
    if ($tenant.PSObject.Properties.Name -contains 'SharingCapability') {
        $sharingCapability = [string] $tenant.SharingCapability
    }

    $odSharing = $null
    if ($tenant.PSObject.Properties.Name -contains 'OneDriveSharingCapability') {
        $odSharing = [string] $tenant.OneDriveSharingCapability
    }
    elseif ($tenant.PSObject.Properties.Name -contains 'ODBSharingCapability') {
        $odSharing = [string] $tenant.ODBSharingCapability
    }

    $allowedDomains = ''
    if ($tenant.PSObject.Properties.Name -contains 'SharingAllowedDomainList') {
        $allowedDomains = [string] $tenant.SharingAllowedDomainList
    }
    $blockedDomains = ''
    if ($tenant.PSObject.Properties.Name -contains 'SharingBlockedDomainList') {
        $blockedDomains = [string] $tenant.SharingBlockedDomainList
    }
    $domainMode = ''
    if ($tenant.PSObject.Properties.Name -contains 'SharingDomainRestrictionMode') {
        $domainMode = [string] $tenant.SharingDomainRestrictionMode
    }

    $defaultLinkType = $null
    if ($tenant.PSObject.Properties.Name -contains 'DefaultSharingLinkType') {
        $defaultLinkType = [string] $tenant.DefaultSharingLinkType
    }
    $defaultLinkPerm = $null
    if ($tenant.PSObject.Properties.Name -contains 'DefaultLinkPermission') {
        $defaultLinkPerm = [string] $tenant.DefaultLinkPermission
    }

    $anonExpire = $null
    if ($tenant.PSObject.Properties.Name -contains 'RequireAnonymousLinksExpireInDays') {
        $anonExpire = $tenant.RequireAnonymousLinksExpireInDays
    }
    $fileAnon = $null
    if ($tenant.PSObject.Properties.Name -contains 'FileAnonymousLinkType') {
        $fileAnon = [string] $tenant.FileAnonymousLinkType
    }
    $folderAnon = $null
    if ($tenant.PSObject.Properties.Name -contains 'FolderAnonymousLinkType') {
        $folderAnon = [string] $tenant.FolderAnonymousLinkType
    }

    $reauthDays = $null
    if ($tenant.PSObject.Properties.Name -contains 'EmailAttestationReAuthDays') {
        $reauthDays = $tenant.EmailAttestationReAuthDays
    }
    $reauthRequired = $null
    if ($tenant.PSObject.Properties.Name -contains 'EmailAttestationRequired') {
        $reauthRequired = [bool] $tenant.EmailAttestationRequired
    }

    $guestPicker = $null
    if ($tenant.PSObject.Properties.Name -contains 'ShowPeoplePickerSuggestionsForGuestUsers') {
        $guestPicker = [bool] $tenant.ShowPeoplePickerSuggestionsForGuestUsers
    }

    $surfaces = [ordered]@{
        sharing_capability = New-TenantSurface -Surface 'sharing_capability' -Name 'TenantSharing' -Properties @{
            SharingCapability                           = $sharingCapability
            ShowPeoplePickerSuggestionsForGuestUsers    = $guestPicker
        }
        onedrive_sharing = New-TenantSurface -Surface 'onedrive_sharing' -Name 'OneDriveSharing' -Properties @{
            OneDriveSharingCapability = $odSharing
        }
        domain_restrictions = New-TenantSurface -Surface 'domain_restrictions' -Name 'DomainRestrictions' -Properties @{
            SharingDomainRestrictionMode = $domainMode
            SharingAllowedDomainList     = $allowedDomains
            SharingBlockedDomainList     = $blockedDomains
        }
        default_link = New-TenantSurface -Surface 'default_link' -Name 'DefaultLink' -Properties @{
            DefaultSharingLinkType = $defaultLinkType
            DefaultLinkPermission  = $defaultLinkPerm
        }
        anyone_link_expiration = New-TenantSurface -Surface 'anyone_link_expiration' -Name 'AnyoneLinkExpiration' -Properties @{
            RequireAnonymousLinksExpireInDays = $anonExpire
            SharingCapability                 = $sharingCapability
        }
        anyone_link_permissions = New-TenantSurface -Surface 'anyone_link_permissions' -Name 'AnyoneLinkPermissions' -Properties @{
            FileAnonymousLinkType   = $fileAnon
            FolderAnonymousLinkType = $folderAnon
        }
        reauth_days = New-TenantSurface -Surface 'reauth_days' -Name 'EmailAttestationReAuth' -Properties @{
            EmailAttestationRequired  = $reauthRequired
            EmailAttestationReAuthDays = $reauthDays
        }
    }

    return [pscustomobject][ordered]@{
        adapter      = 'spo_tenant'
        module       = 'Microsoft.Online.SharePoint.PowerShell'
        collection   = 'sharepoint_tenant'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
