# LicenseLens PowerShell bridge entrypoint.
# Contract: UTF-8 JSON on stdin -> UTF-8 JSON on stdout. No shell interpolation.
# Invoked only via: pwsh -NoProfile -NonInteractive -File this.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$script:ProtocolVersion = '1.0'
$script:ModuleVersion = '0.1.0'

function Write-BridgeResponse {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Payload
    )
    $json = $Payload | ConvertTo-Json -Compress -Depth 12
    [Console]::Out.Write($json)
}

function Write-BridgeError {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Code,
        [Parameter(Mandatory = $true)]
        [string] $Message,
        [string] $Adapter = '',
        [string] $Cloud = 'public'
    )
    Write-BridgeResponse -Payload @{
        protocol_version = $script:ProtocolVersion
        ok               = $false
        adapter          = $Adapter
        module_version   = $script:ModuleVersion
        cloud            = $Cloud
        data             = $null
        error            = @{
            code    = $Code
            message = $Message
        }
    }
}

try {
    $stdinText = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($stdinText)) {
        Write-BridgeError -Code 'malformed_request' -Message 'empty stdin'
        exit 2
    }

    $request = $stdinText | ConvertFrom-Json
    if ($null -eq $request) {
        Write-BridgeError -Code 'malformed_request' -Message 'stdin JSON was null'
        exit 2
    }

    $adapter = [string] $request.adapter
    $cloud = if ($request.cloud) { [string] $request.cloud } else { 'public' }
    $version = [string] $request.protocol_version

    if ($version -ne $script:ProtocolVersion) {
        Write-BridgeError -Code 'protocol_mismatch' -Message "unsupported protocol_version: $version" -Adapter $adapter -Cloud $cloud
        exit 2
    }

    if ($cloud -ne 'public') {
        Write-BridgeError -Code 'unsupported_cloud' -Message "unsupported cloud: $cloud" -Adapter $adapter -Cloud $cloud
        exit 0
    }

    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LicenseLens.Collectors.psd1'
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        Write-BridgeError -Code 'module_missing' -Message 'LicenseLens.Collectors module not found' -Adapter $adapter -Cloud $cloud
        exit 0
    }

    Import-Module -Name $modulePath -Force -ErrorAction Stop
    $data = Invoke-LicenseLensCollectorAdapter -Request $request

    Write-BridgeResponse -Payload @{
        protocol_version = $script:ProtocolVersion
        ok               = $true
        adapter          = $adapter
        module_version   = $script:ModuleVersion
        cloud            = $cloud
        data             = $data
        error            = $null
    }
    exit 0
}
catch {
    $msg = $_.Exception.Message
    $code = 'adapter_failed'
    if ($null -ne $_.Exception.Data -and $_.Exception.Data.Contains('ll_code')) {
        $code = [string] $_.Exception.Data['ll_code']
    }
    elseif ($msg -like 'adapter not allowlisted*') {
        $code = 'adapter_not_allowlisted'
    }
    elseif ($msg -like 'module_missing:*') {
        $code = 'module_missing'
    }
    elseif ($msg -like 'disconnected:*') {
        $code = 'unavailable'
    }
    elseif ($msg -like 'denied:*') {
        $code = 'denied'
    }
    elseif ($msg -like 'unsupported:*') {
        $code = 'unsupported'
    }
    elseif ($msg -like 'unavailable:*') {
        $code = 'unavailable'
    }
    # disconnected maps to unavailable for Python EvidenceHealth
    if ($code -eq 'disconnected') {
        $code = 'unavailable'
    }
    $adapterName = ''
    $cloudName = 'public'
    try {
        if ($null -ne $request) {
            $adapterName = [string] $request.adapter
            if ($request.cloud) { $cloudName = [string] $request.cloud }
        }
    }
    catch {
        # keep defaults
    }
    Write-BridgeError -Code $code -Message $msg -Adapter $adapterName -Cloud $cloudName
    # Typed collection failures exit 0 so Python maps error.code (not nonzero exit).
    if ($code -in @('module_missing', 'unavailable', 'denied', 'unsupported', 'disconnected')) {
        exit 0
    }
    exit 1
}
