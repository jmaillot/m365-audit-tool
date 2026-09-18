<#
.SYNOPSIS
  Teams meeting / messaging / live-events policies for migration prep
  (admin layer): the policy surface that Microsoft Graph does NOT expose.

  Teams meeting policies, messaging policies and live-events (broadcast)
  policies exist only in the Teams PowerShell module / Teams admin center -
  which is why this lives here, not in the SaaS worker (delegated Graph
  tokens cannot query them, and the worker has no Teams module).

  Meeting policy reference:
  https://learn.microsoft.com/microsoftteams/meeting-policies-in-teams
  Messaging policy reference:
  https://learn.microsoft.com/microsoftteams/messaging-policy
  Live events reference:
  https://learn.microsoft.com/microsoftteams/teams-live-events/what-are-teams-live-events

.REQUIREMENTS
  Module MicrosoftTeams (5.x+), Teams administrator role (or Global admin).
  Install-Module MicrosoftTeams -Scope CurrentUser

.EXAMPLE
  .\Get-TeamsPolicyInventory.ps1 -OutDir .\out
  # Definitions + per-user assignments (ResultSize 10000).

.EXAMPLE
  .\Get-TeamsPolicyInventory.ps1 -DefinitionsOnly -OutDir .\out
  # Policy definitions only (fast, no per-user pass).

.OUTPUTS (; -delimited UTF-8, same convention as the SaaS audit tool)
  TeamsMeetingPolicies.csv, TeamsMessagingPolicies.csv,
  TeamsBroadcastPolicies.csv, UserPolicyAssignments.csv
  (assignments are best-effort: unresolvable users keep raw values)
#>
[CmdletBinding()]
param(
    [string]$OutDir = ".",
    [int]$UserResultSize = 10000,
    [switch]$DefinitionsOnly   # skip the per-user assignment pass
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

function Join-Multi($v) { ((@($v) | ForEach-Object { [string]$_ }) | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',' }

function Export-Out($rows, $name) {
    $path = Join-Path $OutDir $name
    @($rows) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host ("Wrote {0} ({1} row(s))." -f $path, @($rows).Count)
}

Write-Host 'Connecting MicrosoftTeams module...'
Connect-MicrosoftTeams

# ---------------------------------------------------------- 1. Meeting policies
Write-Host 'Reading meeting policies (Get-CsTeamsMeetingPolicy)...'
$mpols = @()
try { $mpols = @(Get-CsTeamsMeetingPolicy -ErrorAction Stop) } catch { Write-Warning ("Get-CsTeamsMeetingPolicy failed: " + $_.Exception.Message) }
$mpRows = foreach ($p in $mpols) {
    [pscustomobject]@{
        Identity                              = $p.Identity
        Description                           = $p.Description
        AllowMeetNow                          = $p.AllowMeetNow
        AllowChannelMeetingScheduling         = $p.AllowChannelMeetingScheduling
        AllowPrivateMeetingScheduling         = $p.AllowPrivateMeetingScheduling
        AllowPrivateMeetNow                   = $p.AllowPrivateMeetNow
        MeetingChatEnabledType                = $p.MeetingChatEnabledType
        AllowCloudRecording                   = $p.AllowCloudRecording
        AllowRecordingStorageOutsideRegion    = $p.AllowRecordingStorageOutsideRegion
        AllowTranscription                    = $p.AllowTranscription
        AllowLiveCaptions                     = $p.AllowLiveCaptions
        AllowBreakoutRooms                    = $p.AllowBreakoutRooms
        AllowMeetingReactions                 = $p.AllowMeetingReactions
        AllowPSTNUsersToBypassLobby           = $p.AllowPSTNUsersToBypassLobby
        AutoAdmittedUsers                     = $p.AutoAdmittedUsers
        AllowAnonymousUsersToDialOut          = $p.AllowAnonymousUsersToDialOut
        AllowAnonymousUsersToJoinMeeting      = $p.AllowAnonymousUsersToJoinMeeting
        AllowExternalParticipantGiveRequestControl = $p.AllowExternalParticipantGiveRequestControl
        AllowPowerPointSharing                = $p.AllowPowerPointSharing
        AllowWhiteboard                       = $p.AllowWhiteboard
        AllowSharedNotes                      = $p.AllowSharedNotes
        AllowIPVideo                          = $p.AllowIPVideo
        AllowNDIStreaming                     = $p.AllowNDIStreaming
        MediaBitRateKb                        = $p.MediaBitRateKb
        ScreenSharingMode                     = $p.ScreenSharingMode
        AllowParticipantGiveRequestControl    = $p.AllowParticipantGiveRequestControl
        AllowExternalNonTrustedMeetingChat    = $p.AllowExternalNonTrustedMeetingChat
        AllowMeetingRegistration              = $p.AllowMeetingRegistration
        AllowWatermarkForCameraVideo          = $p.AllowWatermarkForCameraVideo
        AllowWatermarkForScreenSharing        = $p.AllowWatermarkForScreenSharing
        AllowSegmentedMeetingRecording        = $p.AllowSegmentedMeetingRecording
        AllowAvatarsInGallery                 = $p.AllowAvatarsInGallery
    }
}
Export-Out $mpRows 'TeamsMeetingPolicies.csv'

# ---------------------------------------------------------- 2. Messaging policies
Write-Host 'Reading messaging policies (Get-CsTeamsMessagingPolicy)...'
$gpols = @()
try { $gpols = @(Get-CsTeamsMessagingPolicy -ErrorAction Stop) } catch { Write-Warning ("Get-CsTeamsMessagingPolicy failed: " + $_.Exception.Message) }
$gmRows = foreach ($p in $gpols) {
    [pscustomobject]@{
        Identity                 = $p.Identity
        Description              = $p.Description
        AllowUserChat            = $p.AllowUserChat
        AllowUserDeleteMessage   = $p.AllowUserDeleteMessage
        AllowUserEditMessage     = $p.AllowUserEditMessage
        AllowOwnerDeleteMessage  = $p.AllowOwnerDeleteMessage
        AllowGiphy               = $p.AllowGiphy
        GiphyRatingType          = $p.AllowGiphyRatingType
        AllowMemes               = $p.AllowMemes
        AllowStickers            = $p.AllowStickers
        AllowUrlPreviews         = $p.AllowUrlPreviews
        AllowImmersiveReader     = $p.AllowImmersiveReader
        AllowFullChatPermissionUserToDeleteAnyMessage = $p.AllowFullChatPermissionUserToDeleteAnyMessage
        AllowPriorityMessages    = $p.AllowPriorityMessages
        AllowSmartCompose        = $p.AllowSmartCompose
        AllowVideoMessages       = $p.AllowVideoMessages
        AllowChatWithoutPhoneNumber = $p.AllowChatWithoutPhoneNumber
        ChannelsInChatListEnabled = $p.ChannelsInChatListEnabled
        AllowSideloadingInChat   = $p.AllowSideloadingInChat
    }
}
Export-Out $gmRows 'TeamsMessagingPolicies.csv'

# ---------------------------------------------------------- 3. Live events (broadcast) policies
Write-Host 'Reading broadcast policies (Get-CsTeamsMeetingBroadcastPolicy)...'
$bpols = @()
try { $bpols = @(Get-CsTeamsMeetingBroadcastPolicy -ErrorAction Stop) } catch { Write-Warning ("Get-CsTeamsMeetingBroadcastPolicy failed: " + $_.Exception.Message) }
$bpRows = foreach ($p in $bpols) {
    [pscustomobject]@{
        Identity                 = $p.Identity
        Description              = $p.Description
        AllowBroadcastScheduling = $p.AllowBroadcastScheduling
        AllowBroadcastTranscription = $p.AllowBroadcastTranscription
        BroadcastRecordingMode   = $p.BroadcastRecordingMode
        AllowSideloadingInMeetings = $p.AllowSideloadingInMeetings
    }
}
Export-Out $bpRows 'TeamsBroadcastPolicies.csv'

# ---------------------------------------------------------- 4. Per-user assignments (best-effort)
if (-not $DefinitionsOnly) {
    Write-Host 'Reading per-user policy assignments (Get-CsOnlineUser)...'
    $users = @()
    try { $users = @(Get-CsOnlineUser -ResultSize $UserResultSize -ErrorAction Stop) } catch { Write-Warning ("Get-CsOnlineUser failed: " + $_.Exception.Message) }
    Write-Host ("Retrieved {0} user(s)." -f $users.Count)
    $asgRows = foreach ($u in $users) {
        [pscustomobject]@{
            UserPrincipalName  = $u.UserPrincipalName
            TeamsMeetingPolicy = $u.TeamsMeetingPolicy
            TeamsMessagingPolicy = $u.TeamsMessagingPolicy
            TeamsCallingPolicy = $u.TeamsCallingPolicy
            BroadcastPolicy    = $u.TeamsMeetingBroadcastPolicy
        }
    }
    Export-Out $asgRows 'UserPolicyAssignments.csv'
} else {
    Write-Host 'Skipping per-user assignments (-DefinitionsOnly).'
}

Write-Host 'Done. Disconnecting...'
try { Disconnect-MicrosoftTeams -Confirm:$false } catch { }
Write-Host 'Export complete.'
