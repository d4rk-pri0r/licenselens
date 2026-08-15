# Read-only: Teams meeting + live-event broadcast policies (global + custom).
# Official module: MicrosoftTeams. Get-* only; no Grant-/Set- remediation.

function Invoke-LicenseLensAdapter {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Request
    )

    $fixture = Get-LicenseLensFixtureData -Request $Request
    if ($null -ne $fixture) {
        return $fixture
    }

    Assert-LicenseLensTeamsSession

    $meetingProps = @(
        'AllowExternalParticipantGiveRequestControl'
        'AllowAnonymousUsersToStartMeeting'
        'AutoAdmittedUsers'
        'AllowPSTNUsersToBypassLobby'
        'AllowCloudRecording'
        'AllowTranscription'
        'AllowMeetingReactions'
        'DesignatedPresenterRoleMode'
        'MeetingChatEnabledType'
        'WhoCanRegister'
    )
    $broadcastProps = @(
        'BroadcastRecordingMode'
        'AllowBroadcastScheduling'
        'AllowBroadcastTranscription'
        'BroadcastAttendeeVisibilityMode'
    )

    $surfaces = [ordered]@{}

    # Meeting policies (Global + custom); assignments via group policy assignment when available.
    try {
        if (-not (Test-LicenseLensCommandAvailable -Name 'Get-CsTeamsMeetingPolicy')) {
            $surfaces['meeting_policies'] = New-LicenseLensSurfaceResult `
                -Surface 'meeting_policies' `
                -Status 'unsupported' `
                -Reason 'cmdlet not present: Get-CsTeamsMeetingPolicy'
        }
        else {
            $assignMap = Get-LicenseLensGroupPolicyAssignments -PolicyType 'TeamsMeetingPolicy'
            $policies = @(Invoke-LicenseLensReadCommand -Name 'Get-CsTeamsMeetingPolicy')
            $items = @()
            foreach ($policy in $policies) {
                $items += ConvertTo-LicenseLensTeamsPolicyItem `
                    -InputObject $policy `
                    -PropertyNames $meetingProps `
                    -AssignmentsByPolicy $assignMap
            }
            $surfaces['meeting_policies'] = New-LicenseLensSurfaceResult `
                -Surface 'meeting_policies' `
                -Status 'ok' `
                -Items $items
        }
    }
    catch {
        $surfaces['meeting_policies'] = New-LicenseLensSurfaceResult `
            -Surface 'meeting_policies' `
            -Status 'denied' `
            -Reason $_.Exception.Message
    }

    # Live events / broadcast recording policies.
    try {
        $cmd = $null
        if (Test-LicenseLensCommandAvailable -Name 'Get-CsTeamsMeetingBroadcastPolicy') {
            $cmd = 'Get-CsTeamsMeetingBroadcastPolicy'
        }
        elseif (Test-LicenseLensCommandAvailable -Name 'Get-CsTeamsEventsPolicy') {
            $cmd = 'Get-CsTeamsEventsPolicy'
        }
        if ($null -eq $cmd) {
            $surfaces['broadcast_policies'] = New-LicenseLensSurfaceResult `
                -Surface 'broadcast_policies' `
                -Status 'unsupported' `
                -Reason 'broadcast/events policy cmdlets not present'
        }
        else {
            $assignMap = Get-LicenseLensGroupPolicyAssignments -PolicyType 'TeamsMeetingBroadcastPolicy'
            $policies = @(Invoke-LicenseLensReadCommand -Name $cmd)
            $items = @()
            foreach ($policy in $policies) {
                $items += ConvertTo-LicenseLensTeamsPolicyItem `
                    -InputObject $policy `
                    -PropertyNames $broadcastProps `
                    -AssignmentsByPolicy $assignMap
            }
            $surfaces['broadcast_policies'] = New-LicenseLensSurfaceResult `
                -Surface 'broadcast_policies' `
                -Status 'ok' `
                -Items $items
        }
    }
    catch {
        $surfaces['broadcast_policies'] = New-LicenseLensSurfaceResult `
            -Surface 'broadcast_policies' `
            -Status 'denied' `
            -Reason $_.Exception.Message
    }

    return [pscustomobject][ordered]@{
        adapter      = 'teams_meeting'
        module       = 'MicrosoftTeams'
        collection   = 'teams_meeting'
        surfaces     = [pscustomobject]$surfaces
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
}
