# Contract-test adapter only. Echoes request params; no network, no mutation.

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $params = @{}
    if ($null -ne $Request.params) {
        foreach ($prop in $Request.params.PSObject.Properties) {
            $params[$prop.Name] = $prop.Value
        }
    }

    $result = [ordered]@{
        adapter         = 'fake_echo'
        module_version  = '0.1.0'
        cloud           = [string] $Request.cloud
        protocol_version = [string] $Request.protocol_version
        params          = $params
    }

    # Flatten common contract markers for Python assertions.
    if ($params.ContainsKey('marker')) {
        $result['marker'] = $params['marker']
    }
    if ($params.ContainsKey('live')) {
        $result['live'] = $params['live']
    }
    if ($params.ContainsKey('probe')) {
        $result['probe'] = $params['probe']
    }

    return [pscustomobject]$result
}
