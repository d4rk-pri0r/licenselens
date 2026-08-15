# LicenseLens.Collectors — allowlisted adapter host (read-only).
# Never Invoke-Expression user input. Never export write/remediation cmdlets.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ModuleVersion = '0.1.0'
$script:AdapterNamePattern = '^[a-z][a-z0-9_]{0,63}$'
$script:WriteCmdletPattern = '^(Set|New|Remove|Add|Update|Enable|Disable|Start|Stop|Move|Clear)-'

function Test-LicenseLensAdapterName {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )
    return [bool]([regex]::IsMatch($Name, $script:AdapterNamePattern))
}

function Get-LicenseLensAdapterPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )
    if (-not (Test-LicenseLensAdapterName -Name $Name)) {
        throw "adapter not allowlisted: $Name"
    }
    $adaptersRoot = Join-Path -Path $PSScriptRoot -ChildPath 'adapters'
    $candidate = Join-Path -Path $adaptersRoot -ChildPath ($Name + '.ps1')
    $resolved = [System.IO.Path]::GetFullPath($candidate)
    $rootFull = [System.IO.Path]::GetFullPath($adaptersRoot)
    if (-not $resolved.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "adapter not allowlisted: $Name"
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "adapter not allowlisted: $Name"
    }
    return $resolved
}

function New-LicenseLensAdapterError {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('module_missing', 'unavailable', 'denied', 'unsupported', 'disconnected', 'adapter_failed')]
        [string] $Code,
        [Parameter(Mandatory = $true)]
        [string] $Message
    )
    $ex = [System.Exception]::new("${Code}: ${Message}")
    $ex.Data['ll_code'] = $Code
    return $ex
}

function Get-LicenseLensParamValue {
    param(
        [Parameter(Mandatory = $true)]
        $Params,
        [Parameter(Mandatory = $true)]
        [string] $Name
    )
    if ($null -eq $Params) {
        return $null
    }
    if ($Params -is [System.Collections.IDictionary]) {
        if ($Params.Contains($Name)) {
            return $Params[$Name]
        }
        return $null
    }
    foreach ($prop in $Params.PSObject.Properties) {
        if ($prop.Name -eq $Name) {
            return $prop.Value
        }
    }
    return $null
}

function Get-LicenseLensFixtureData {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )
    if ($null -eq $Request.params) {
        return $null
    }
    if (-not [bool] (Get-LicenseLensParamValue -Params $Request.params -Name 'fixture_mode')) {
        return $null
    }
    $data = Get-LicenseLensParamValue -Params $Request.params -Name 'fixture_data'
    if ($null -ne $data) {
        return $data
    }
    return [pscustomobject]@{ fixture = $true }
}

function Test-LicenseLensModuleAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )
    return $null -ne (Get-Module -ListAvailable -Name $Name | Select-Object -First 1)
}

function Test-LicenseLensCommandAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )
    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Assert-LicenseLensNoWriteCmdlet {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )
    if ($Name -match $script:WriteCmdletPattern) {
        throw (New-LicenseLensAdapterError -Code 'adapter_failed' -Message "write cmdlet blocked: $Name")
    }
}

function Invoke-LicenseLensReadCommand {
    <#
    .SYNOPSIS
        Invoke a Get-* (read-only) command by name with optional splat. Blocks write verbs.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [hashtable] $Arguments = @{}
    )
    Assert-LicenseLensNoWriteCmdlet -Name $Name
    if (-not (Test-LicenseLensCommandAvailable -Name $Name)) {
        throw (New-LicenseLensAdapterError -Code 'unavailable' -Message "command not available: $Name")
    }
    return & $Name @Arguments
}

function Assert-LicenseLensExoSession {
    param(
        [string[]] $Modules = @('ExchangeOnlineManagement')
    )
    $found = $false
    foreach ($mod in $Modules) {
        if (Test-LicenseLensModuleAvailable -Name $mod) {
            $found = $true
            Import-Module -Name $mod -ErrorAction SilentlyContinue | Out-Null
            break
        }
    }
    if (-not $found) {
        throw (New-LicenseLensAdapterError -Code 'module_missing' -Message ($Modules -join ' or '))
    }
    if (-not (Test-LicenseLensCommandAvailable -Name 'Get-OrganizationConfig')) {
        throw (New-LicenseLensAdapterError -Code 'disconnected' -Message 'Exchange Online session not connected')
    }
}

function Assert-LicenseLensSccSession {
    $modules = @('ExchangeOnlineManagement', 'Microsoft.Graph.SecurityComplianceCenter')
    $found = $false
    foreach ($mod in $modules) {
        if (Test-LicenseLensModuleAvailable -Name $mod) {
            $found = $true
            Import-Module -Name $mod -ErrorAction SilentlyContinue | Out-Null
            break
        }
    }
    if (-not $found) {
        throw (New-LicenseLensAdapterError -Code 'module_missing' -Message 'ExchangeOnlineManagement (IPPS) required for compliance')
    }
    $probe = @('Get-DlpCompliancePolicy', 'Get-Label', 'Get-AdminAuditLogConfig')
    $any = $false
    foreach ($cmd in $probe) {
        if (Test-LicenseLensCommandAvailable -Name $cmd) {
            $any = $true
            break
        }
    }
    if (-not $any) {
        throw (New-LicenseLensAdapterError -Code 'disconnected' -Message 'Security & Compliance session not connected')
    }
}

function Assert-LicenseLensTeamsSession {
    $modules = @('MicrosoftTeams')
    $found = $false
    foreach ($mod in $modules) {
        if (Test-LicenseLensModuleAvailable -Name $mod) {
            $found = $true
            Import-Module -Name $mod -ErrorAction SilentlyContinue | Out-Null
            break
        }
    }
    if (-not $found) {
        throw (New-LicenseLensAdapterError -Code 'module_missing' -Message 'MicrosoftTeams')
    }
    $probe = @(
        'Get-CsTeamsMeetingPolicy'
        'Get-CsTenantFederationConfiguration'
        'Get-CsTeamsClientConfiguration'
        'Get-CsTenant'
    )
    $any = $false
    foreach ($cmd in $probe) {
        if (Test-LicenseLensCommandAvailable -Name $cmd) {
            $any = $true
            break
        }
    }
    if (-not $any) {
        throw (New-LicenseLensAdapterError -Code 'disconnected' -Message 'Microsoft Teams session not connected')
    }
}

function Assert-LicenseLensSpoSession {
    $modules = @('Microsoft.Online.SharePoint.PowerShell', 'Microsoft.Online.SharePoint.PowerShell.Core')
    $found = $false
    foreach ($mod in $modules) {
        if (Test-LicenseLensModuleAvailable -Name $mod) {
            $found = $true
            Import-Module -Name $mod -ErrorAction SilentlyContinue | Out-Null
            break
        }
    }
    if (-not $found) {
        throw (New-LicenseLensAdapterError -Code 'module_missing' -Message 'Microsoft.Online.SharePoint.PowerShell')
    }
    if (-not (Test-LicenseLensCommandAvailable -Name 'Get-SPOTenant')) {
        throw (New-LicenseLensAdapterError -Code 'disconnected' -Message 'SharePoint Online session not connected')
    }
}

function Assert-LicenseLensPowerAppsSession {
    $modules = @('Microsoft.PowerApps.Administration.PowerShell', 'Microsoft.PowerApps.PowerShell')
    $found = $false
    foreach ($mod in $modules) {
        if (Test-LicenseLensModuleAvailable -Name $mod) {
            $found = $true
            Import-Module -Name $mod -ErrorAction SilentlyContinue | Out-Null
            break
        }
    }
    if (-not $found) {
        throw (New-LicenseLensAdapterError -Code 'module_missing' -Message 'Microsoft.PowerApps.Administration.PowerShell')
    }
    $probe = @('Get-TenantSettings', 'Get-AdminPowerAppEnvironment', 'Get-DlpPolicy', 'Get-PowerAppTenantIsolationPolicy')
    $any = $false
    foreach ($cmd in $probe) {
        if (Test-LicenseLensCommandAvailable -Name $cmd) {
            $any = $true
            break
        }
    }
    if (-not $any) {
        throw (New-LicenseLensAdapterError -Code 'disconnected' -Message 'Power Platform admin session not connected')
    }
}

function Assert-LicenseLensPowerBISession {
    $modules = @('MicrosoftPowerBIMgmt', 'MicrosoftPowerBIMgmt.Admin', 'MicrosoftPowerBIMgmt.Profile')
    $found = $false
    foreach ($mod in $modules) {
        if (Test-LicenseLensModuleAvailable -Name $mod) {
            $found = $true
            Import-Module -Name $mod -ErrorAction SilentlyContinue | Out-Null
        }
    }
    if (-not $found) {
        throw (New-LicenseLensAdapterError -Code 'module_missing' -Message 'MicrosoftPowerBIMgmt')
    }
    $probe = @(
        'Get-PowerBITenantSetting'
        'Get-FabricTenantSetting'
        'Get-PowerBIWorkspace'
    )
    $any = $false
    foreach ($cmd in $probe) {
        if (Test-LicenseLensCommandAvailable -Name $cmd) {
            $any = $true
            break
        }
    }
    if (-not $any) {
        throw (New-LicenseLensAdapterError -Code 'disconnected' -Message 'Power BI admin session not connected or module-version drift')
    }
}

function Assert-LicenseLensPurviewSession {
    # Purview governance surfaces ride the IPPS / SCC session (ExchangeOnlineManagement).
    Assert-LicenseLensSccSession
}

function Invoke-LicenseLensPagedGet {
    <#
    .SYNOPSIS
        Invoke a Get-* cmdlet and follow common continuation tokens until exhausted.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [hashtable] $Arguments = @{},
        [int] $MaxPages = 50
    )
    Assert-LicenseLensNoWriteCmdlet -Name $Name
    if (-not (Test-LicenseLensCommandAvailable -Name $Name)) {
        throw (New-LicenseLensAdapterError -Code 'unavailable' -Message "command not available: $Name")
    }

    $all = New-Object System.Collections.Generic.List[object]
    $page = 0
    $args = @{} + $Arguments
    while ($page -lt $MaxPages) {
        $page++
        $result = & $Name @args
        if ($null -eq $result) {
            break
        }
        $batch = @($result)
        # Some admin cmdlets wrap rows under .value
        if ($batch.Count -eq 1 -and $null -ne $batch[0] -and $batch[0].PSObject.Properties.Name -contains 'value') {
            foreach ($row in @($batch[0].value)) { [void] $all.Add($row) }
            $token = $null
            if ($batch[0].PSObject.Properties.Name -contains 'ContinuationToken') {
                $token = $batch[0].ContinuationToken
            }
            elseif ($batch[0].PSObject.Properties.Name -contains 'nextLink') {
                $token = $batch[0].nextLink
            }
            if ([string]::IsNullOrWhiteSpace([string]$token)) {
                break
            }
            $args['ContinuationToken'] = $token
            continue
        }
        foreach ($row in $batch) { [void] $all.Add($row) }
        break
    }
    return @($all.ToArray())
}

function Get-LicenseLensGroupPolicyAssignments {
    <#
    .SYNOPSIS
        Read group policy assignments for a Teams policy type (Get-* only).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string] $PolicyType
    )
    $byPolicy = @{}
    if (-not (Test-LicenseLensCommandAvailable -Name 'Get-CsGroupPolicyAssignment')) {
        return $byPolicy
    }
    try {
        $rows = @(Invoke-LicenseLensReadCommand -Name 'Get-CsGroupPolicyAssignment' -Arguments @{
                PolicyType = $PolicyType
            })
        foreach ($row in $rows) {
            $policyName = $null
            if ($row.PSObject.Properties.Name -contains 'PolicyName') {
                $policyName = [string] $row.PolicyName
            }
            elseif ($row.PSObject.Properties.Name -contains 'Policy') {
                $policyName = [string] $row.Policy
            }
            if ([string]::IsNullOrWhiteSpace($policyName)) {
                continue
            }
            $groupId = ''
            if ($row.PSObject.Properties.Name -contains 'GroupId') {
                $groupId = [string] $row.GroupId
            }
            elseif ($row.PSObject.Properties.Name -contains 'Identity') {
                $groupId = [string] $row.Identity
            }
            if (-not $byPolicy.ContainsKey($policyName)) {
                $byPolicy[$policyName] = New-Object System.Collections.Generic.List[string]
            }
            if (-not [string]::IsNullOrWhiteSpace($groupId)) {
                [void] $byPolicy[$policyName].Add($groupId)
            }
        }
    }
    catch {
        # Partial access: leave assignments empty rather than failing the surface.
    }
    return $byPolicy
}

function New-LicenseLensSurfaceResult {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Surface,
        [Parameter(Mandatory = $true)]
        [ValidateSet('ok', 'denied', 'unavailable', 'unsupported', 'error', 'disconnected')]
        [string] $Status,
        [string] $Reason = '',
        [object[]] $Items = @(),
        [bool] $NationalCloudLimited = $false
    )
    return [ordered]@{
        surface                 = $Surface
        status                  = $Status
        reason                  = $Reason
        items                   = @($Items)
        raw_count               = @($Items).Count
        national_cloud_limited  = $NationalCloudLimited
    }
}

function ConvertTo-LicenseLensPolicyItem {
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,
        [string] $Kind = 'custom',
        [string[]] $PropertyNames = @()
    )
    $name = $null
    foreach ($candidate in @('Name', 'Identity', 'Guid', 'Id', 'DistinguishedName')) {
        if ($InputObject.PSObject.Properties.Name -contains $candidate) {
            $val = $InputObject.$candidate
            if ($null -ne $val -and [string]$val -ne '') {
                $name = [string] $val
                break
            }
        }
    }
    if ($null -eq $name) {
        $name = 'unknown'
    }

    $identity = $null
    if ($InputObject.PSObject.Properties.Name -contains 'Identity') {
        $identity = [string] $InputObject.Identity
    }
    elseif ($InputObject.PSObject.Properties.Name -contains 'Guid') {
        $identity = [string] $InputObject.Guid
    }

    $enabled = $null
    foreach ($flag in @('Enabled', 'IsEnabled', 'Enable', 'Mode')) {
        if ($InputObject.PSObject.Properties.Name -contains $flag) {
            $raw = $InputObject.$flag
            if ($flag -eq 'Mode') {
                $enabled = ([string]$raw -notin @('Disabled', 'Off', ''))
            }
            else {
                $enabled = [bool] $raw
            }
            break
        }
    }

    $props = [ordered]@{}
    foreach ($propName in $PropertyNames) {
        if ($InputObject.PSObject.Properties.Name -contains $propName) {
            $props[$propName] = $InputObject.$propName
        }
    }

    $assignments = @()
    foreach ($assignProp in @('SentTo', 'SentToMemberOf', 'RecipientDomainIs', 'ExceptIfSentTo', 'Priority', 'State')) {
        if ($InputObject.PSObject.Properties.Name -contains $assignProp) {
            $val = $InputObject.$assignProp
            if ($null -ne $val) {
                if ($val -is [System.Array]) {
                    foreach ($item in $val) { $assignments += [string] $item }
                }
                else {
                    $assignments += [string] $val
                }
            }
        }
    }

    return [ordered]@{
        name        = $name
        identity    = $identity
        kind        = $Kind
        enabled     = $enabled
        properties  = [pscustomobject]$props
        assignments = @($assignments | Select-Object -Unique)
    }
}

function Get-LicenseLensPolicyKind {
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )
    $name = ''
    if ($InputObject.PSObject.Properties.Name -contains 'Name') {
        $name = [string] $InputObject.Name
    }
    elseif ($InputObject.PSObject.Properties.Name -contains 'Identity') {
        $name = [string] $InputObject.Identity
    }
    $isDefault = $false
    if ($InputObject.PSObject.Properties.Name -contains 'IsDefault') {
        $isDefault = [bool] $InputObject.IsDefault
    }
    # Teams org-wide default is Identity/Name "Global".
    if ($isDefault -or $name -eq 'Global' -or $name -match '^(Default|Office365|Built-In|Global\b)') {
        return 'default'
    }
    if ($name -match 'Standard Preset|Strict Preset|Preset Security') {
        if ($name -match 'Strict') { return 'preset_strict' }
        return 'preset_standard'
    }
    return 'custom'
}

function ConvertTo-LicenseLensTeamsPolicyItem {
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,
        [string[]] $PropertyNames = @(),
        [hashtable] $AssignmentsByPolicy = @{}
    )
    $kind = Get-LicenseLensPolicyKind -InputObject $InputObject
    $item = ConvertTo-LicenseLensPolicyItem -InputObject $InputObject -Kind $kind -PropertyNames $PropertyNames
    $keyCandidates = @()
    if ($item.name) { $keyCandidates += [string] $item.name }
    if ($item.identity) { $keyCandidates += [string] $item.identity }
    $extra = @()
    foreach ($key in $keyCandidates) {
        if ($AssignmentsByPolicy.ContainsKey($key)) {
            foreach ($a in @($AssignmentsByPolicy[$key])) {
                $extra += [string] $a
            }
        }
    }
    if ($kind -eq 'default' -and $extra.Count -eq 0) {
        $extra = @('All')
    }
    if ($extra.Count -gt 0) {
        $item.assignments = @($extra | Select-Object -Unique)
    }
    return $item
}

function Invoke-LicenseLensCollectorAdapter {
    <#
    .SYNOPSIS
        Load one checked-in adapter and return its data object (no remediation).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $adapterName = [string] $Request.adapter

    # Normalize params to a PSCustomObject so direct callers passing a hashtable
    # (Pester contract tests) and the JSON bridge (ConvertFrom-Json produces a
    # PSCustomObject) observe the same member/property contract. A hashtable's
    # PSObject.Properties exposes the collection's own members (Keys, Values,
    # Count, …), not its key/value pairs, so without this the fixture/echo path
    # silently drops params and adapters fall through to real module checks.
    if ($null -ne $Request.params -and $Request.params -is [System.Collections.IDictionary]) {
        $Request.params = [pscustomobject]$Request.params
    }

    $path = Get-LicenseLensAdapterPath -Name $adapterName

    # Dot-source only a path we resolved under adapters/.
    . $path

    if (-not (Get-Command -Name 'Invoke-LicenseLensAdapter' -ErrorAction SilentlyContinue)) {
        throw "adapter missing Invoke-LicenseLensAdapter: $adapterName"
    }

    return Invoke-LicenseLensAdapter -Request $Request
}

Export-ModuleMember -Function Invoke-LicenseLensCollectorAdapter
