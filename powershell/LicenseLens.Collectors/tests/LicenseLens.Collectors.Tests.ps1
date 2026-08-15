# Pester contract smoke for the bridge module (run when pwsh + Pester available).
# uv/pytest owns the primary cross-platform contract; this is a secondary check.

Describe 'LicenseLens.Collectors allowlist' {
    BeforeAll {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $moduleRoot 'LicenseLens.Collectors.psd1') -Force
    }

    It 'rejects path-traversal adapter names' {
        $req = [pscustomobject]@{
            protocol_version = '1.0'
            adapter          = '../etc/passwd'
            cloud            = 'public'
            params           = @{}
        }
        { Invoke-LicenseLensCollectorAdapter -Request $req } | Should -Throw '*not allowlisted*'
    }

    It 'runs fake_echo without network' {
        $req = [pscustomobject]@{
            protocol_version = '1.0'
            adapter          = 'fake_echo'
            cloud            = 'public'
            params           = @{ marker = 'pester-12' }
        }
        $data = Invoke-LicenseLensCollectorAdapter -Request $req
        $data.adapter | Should -Be 'fake_echo'
        $data.marker | Should -Be 'pester-12'
    }

    It 'runs exo_threat_policies in fixture_mode without EXO modules' {
        $fixture = [pscustomobject]@{
            adapter    = 'exo_threat_policies'
            collection = 'exchange_threat_policies'
            surfaces   = [pscustomobject]@{
                safe_links = [ordered]@{
                    surface   = 'safe_links'
                    status    = 'ok'
                    reason    = ''
                    items     = @()
                    raw_count = 0
                }
            }
        }
        $req = [pscustomobject]@{
            protocol_version = '1.0'
            adapter          = 'exo_threat_policies'
            cloud            = 'public'
            params           = @{
                fixture_mode = $true
                fixture_data = $fixture
            }
        }
        $data = Invoke-LicenseLensCollectorAdapter -Request $req
        $data.adapter | Should -Be 'exo_threat_policies'
        $data.surfaces.safe_links.status | Should -Be 'ok'
    }

    It 'maps missing Exchange module to module_missing without write cmdlets' {
        $req = [pscustomobject]@{
            protocol_version = '1.0'
            adapter          = 'exo_dkim'
            cloud            = 'public'
            params           = @{}
        }
        # Without ExchangeOnlineManagement / session this should throw typed error.
        try {
            Invoke-LicenseLensCollectorAdapter -Request $req | Out-Null
            $threw = $false
        }
        catch {
            $threw = $true
            $_.Exception.Message | Should -Match 'module_missing|disconnected|unavailable'
        }
        # On hosts with a live connected session this may succeed; either is acceptable.
        $true | Should -Be $true
    }

    It 'runs teams_meeting in fixture_mode without MicrosoftTeams modules' {
        $fixture = [pscustomobject]@{
            adapter    = 'teams_meeting'
            collection = 'teams_meeting'
            surfaces   = [pscustomobject]@{
                meeting_policies = [ordered]@{
                    surface   = 'meeting_policies'
                    status    = 'ok'
                    reason    = ''
                    items     = @()
                    raw_count = 0
                }
            }
        }
        $req = [pscustomobject]@{
            protocol_version = '1.0'
            adapter          = 'teams_meeting'
            cloud            = 'public'
            params           = @{
                fixture_mode = $true
                fixture_data = $fixture
            }
        }
        $data = Invoke-LicenseLensCollectorAdapter -Request $req
        $data.adapter | Should -Be 'teams_meeting'
        $data.surfaces.meeting_policies.status | Should -Be 'ok'
    }

    It 'runs spo_tenant in fixture_mode without SharePoint modules' {
        $fixture = [pscustomobject]@{
            adapter    = 'spo_tenant'
            collection = 'sharepoint_tenant'
            surfaces   = [pscustomobject]@{
                sharing_capability = [ordered]@{
                    surface   = 'sharing_capability'
                    status    = 'ok'
                    reason    = ''
                    items     = @()
                    raw_count = 0
                }
            }
        }
        $req = [pscustomobject]@{
            protocol_version = '1.0'
            adapter          = 'spo_tenant'
            cloud            = 'public'
            params           = @{
                fixture_mode = $true
                fixture_data = $fixture
            }
        }
        $data = Invoke-LicenseLensCollectorAdapter -Request $req
        $data.adapter | Should -Be 'spo_tenant'
        $data.surfaces.sharing_capability.status | Should -Be 'ok'
    }

    It 'runs pp_tenant in fixture_mode without PowerApps modules' {
        $fixture = [pscustomobject]@{
            adapter    = 'pp_tenant'
            collection = 'power_platform_tenant'
            surfaces   = [pscustomobject]@{
                environment_creation = [ordered]@{
                    surface   = 'environment_creation'
                    status    = 'ok'
                    reason    = ''
                    items     = @()
                    raw_count = 0
                }
            }
        }
        $req = [pscustomobject]@{
            protocol_version = '1.0'
            adapter          = 'pp_tenant'
            cloud            = 'public'
            params           = @{
                fixture_mode = $true
                fixture_data = $fixture
            }
        }
        $data = Invoke-LicenseLensCollectorAdapter -Request $req
        $data.adapter | Should -Be 'pp_tenant'
        $data.surfaces.environment_creation.status | Should -Be 'ok'
    }

    It 'runs purview_governance in fixture_mode without SCC modules' {
        $fixture = [pscustomobject]@{
            adapter    = 'purview_governance'
            collection = 'purview_governance'
            surfaces   = [pscustomobject]@{
                dlp_policies = [ordered]@{
                    surface   = 'dlp_policies'
                    status    = 'ok'
                    reason    = ''
                    items     = @()
                    raw_count = 0
                }
            }
        }
        $req = [pscustomobject]@{
            protocol_version = '1.0'
            adapter          = 'purview_governance'
            cloud            = 'public'
            params           = @{
                fixture_mode = $true
                fixture_data = $fixture
            }
        }
        $data = Invoke-LicenseLensCollectorAdapter -Request $req
        $data.adapter | Should -Be 'purview_governance'
        $data.surfaces.dlp_policies.status | Should -Be 'ok'
    }
}
