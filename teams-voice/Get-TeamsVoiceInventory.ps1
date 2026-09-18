<#
.SYNOPSIS
  Teams Phone/voice inventory for migration prep (admin layer): the voice
  surface that Microsoft Graph does NOT expose.

  The SaaS "Phone numbers" section covers via Graph beta (one row per Teams
  telephone number): TelephoneNumber, NumberType, NumberSource,
  ActivationState, AssignmentStatus, AssignmentCategory, Capabilities,
  AssignedTo/AssigneeType. Everything below needs the MicrosoftTeams
  PowerShell module - which is why it lives here, not in the SaaS worker
  (delegated Graph tokens cannot open the Teams PowerShell connection, and
  calling policies / voice routing have no Graph API at all).

  Calling policy reference:
  https://learn.microsoft.com/microsoftteams/teams-calling-policy
  Voice routing reference:
  https://learn.microsoft.com/microsoftteams/manage-voice-routing-policies

.REQUIREMENTS
  Module MicrosoftTeams (5.x+), Teams administrator role (or Global admin).
  Install-Module MicrosoftTeams -Scope CurrentUser

.EXAMPLE
  .\Get-TeamsVoiceInventory.ps1 -OutDir .\out
  # All users (ResultSize 10000), all voice objects.

.EXAMPLE
  .\Get-TeamsVoiceInventory.ps1 -VoiceOnly -OutDir .\out
  # Only EnterpriseVoice-enabled users in UserVoice.csv (faster triage).

.OUTPUTS (; -delimited UTF-8, same convention as the SaaS audit tool)
  TeamsCallingPolicies.csv, UserVoice.csv, VoiceRoutingPolicies.csv,
  VoiceRoutes.csv, PstnUsages.csv, DirectRoutingSBCs.csv
  (PhoneNumberAssignments-PS.csv best-effort - skipped with a warning when
  the cmdlet is unavailable in the installed module version.)
#>
[CmdletBinding()]
param(
    [string]$OutDir = ".",
    [int]$UserResultSize = 10000,
    [switch]$VoiceOnly,          # only EnterpriseVoice-enabled users in UserVoice.csv
    [string]$TenantId = ""       # optional: Connect-MicrosoftTeams -TenantId
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
if ($TenantId) { Connect-MicrosoftTeams -TenantId $TenantId } else { Connect-MicrosoftTeams }

# ---------------------------------------------------------- 1. Calling policies
Write-Host 'Reading calling policies (Get-CsTeamsCallingPolicy)...'
$pols = @(Get-CsTeamsCallingPolicy)
$polRows = foreach ($p in $pols) {
    [pscustomobject]@{
        Identity                        = $p.Identity
        Description                     = $p.Description
        AllowPrivateCalling             = $p.AllowPrivateCalling
        AllowCloudRecordingForCalls     = $p.AllowCloudRecordingForCalls
        AllowTranscriptionForCalling    = $p.AllowTranscriptionForCalling
        AllowCallForwardingToUser       = $p.AllowCallForwardingToUser
        AllowCallForwardingToPhone      = $p.AllowCallForwardingToPhone
        AllowVoicemail                  = $p.AllowVoicemail
        AllowCallGroups                 = $p.AllowCallGroups
        AllowDelegation                 = $p.AllowDelegation
        PreventTollBypass               = $p.PreventTollBypass
        BusyOnBusyEnabled               = $p.BusyOnBusyEnabled
        MusicOnHoldEnabled              = $p.MusicOnHoldEnabled
        AllowWebPSTNCalling             = $p.AllowWebPSTNCalling
    }
}
Export-Out $polRows 'TeamsCallingPolicies.csv'

# ---------------------------------------------------------- 2. Per-user voice state
Write-Host 'Reading users (Get-CsOnlineUser)...'
$users = @(Get-CsOnlineUser -ResultSize $UserResultSize)
if ($VoiceOnly) { $users = @($users | Where-Object { [bool]$_.EnterpriseVoiceEnabled }) }
Write-Host ("Retrieved {0} user(s)." -f $users.Count)
$userRows = foreach ($u in $users) {
    [pscustomobject]@{
        UserPrincipalName        = $u.UserPrincipalName
        EnterpriseVoiceEnabled   = $u.EnterpriseVoiceEnabled
        HostedVoiceMail          = $u.HostedVoiceMail
        LineUri                  = $u.LineUri
        TeamsCallingPolicy       = $u.TeamsCallingPolicy
        OnlineVoiceRoutingPolicy = $u.OnlineVoiceRoutingPolicy
    }
}
Export-Out $userRows 'UserVoice.csv'

# ---------------------------------------------------------- 3. Voice routing policies
Write-Host 'Reading voice routing policies (Get-CsOnlineVoiceRoutingPolicy)...'
$vrps = @(Get-CsOnlineVoiceRoutingPolicy)
$vrpRows = foreach ($v in $vrps) {
    [pscustomobject]@{
        Identity          = $v.Identity
        Description       = $v.Description
        OnlinePstnUsages  = Join-Multi $v.OnlinePstnUsages
    }
}
Export-Out $vrpRows 'VoiceRoutingPolicies.csv'

# ---------------------------------------------------------- 4. Voice routes
Write-Host 'Reading voice routes (Get-CsOnlineVoiceRoute)...'
$routes = @(Get-CsOnlineVoiceRoute)
$routeRows = foreach ($r in $routes) {
    [pscustomobject]@{
        Identity               = $r.Identity
        Description            = $r.Description
        NumberPattern          = [string]$r.NumberPattern
        Priority               = $r.Priority
        OnlinePstnUsages       = Join-Multi $r.OnlinePstnUsages
        OnlinePstnGatewayList  = Join-Multi $r.OnlinePstnGatewayList
    }
}
Export-Out $routeRows 'VoiceRoutes.csv'

# ---------------------------------------------------------- 5. PSTN usages (+ policy cross-reference)
Write-Host 'Reading PSTN usages (Get-CsOnlinePstnUsage)...'
$usages = @()
try {
    $g = Get-CsOnlinePstnUsage
    $usages = @($g.Usage)
} catch { Write-Warning ("Get-CsOnlinePstnUsage failed: " + $_.Exception.Message) }
$usageRows = foreach ($un in $usages) {
    $usedBy = @($vrpRows | Where-Object { @($_.OnlinePstnUsages -split ',') -contains $un } | ForEach-Object { [string]$_.Identity })
    [pscustomobject]@{
        Usage        = $un
        UsedByPolicies = ($usedBy -join ',')
    }
}
Export-Out $usageRows 'PstnUsages.csv'

# ---------------------------------------------------------- 6. Direct Routing SBCs
Write-Host 'Reading Direct Routing gateways (Get-CsOnlinePSTNGateway)...'
$sbcs = @()
try { $sbcs = @(Get-CsOnlinePSTNGateway) } catch { Write-Warning ("Get-CsOnlinePSTNGateway failed: " + $_.Exception.Message) }
$sbcRows = foreach ($s in $sbcs) {
    [pscustomobject]@{
        Fqdn                 = $s.Identity
        Description          = $s.Description
        Enabled              = $s.Enabled
        SipSignalingPort     = $s.SipSignalingPort
        FailoverTimeSeconds  = $s.FailoverTimeSeconds
        ForwardCallHistory   = $s.ForwardCallHistory
        ForwardPai           = $s.ForwardPai
        SendSipOptions       = $s.SendSipOptions
        MaxConcurrentSessions = $s.MaxConcurrentSessions
    }
}
Export-Out $sbcRows 'DirectRoutingSBCs.csv'

# ---------------------------------------------------------- 7. Phone number assignments (best-effort)
Write-Host 'Reading phone number assignments (Get-CsPhoneNumberAssignment, best-effort)...'
try {
    $asg = @(Get-CsPhoneNumberAssignment -ResultSize $UserResultSize)
    $asgRows = foreach ($a in $asg) {
        [pscustomobject]@{
            TelephoneNumber      = $a.TelephoneNumber
            NumberType           = $a.NumberType
            IsoCountryCode       = $a.IsoCountryCode
            City                 = $a.City
            AssignmentStatus     = $a.AssignmentStatus
            AssignedPstnTargetId = $a.AssignedPstnTargetId
        }
    }
    Export-Out $asgRows 'PhoneNumberAssignments-PS.csv'
} catch { Write-Warning ("Skipped (cmdlet unavailable here): " + $_.Exception.Message) }

Write-Host 'Done. Disconnecting...'
try { Disconnect-MicrosoftTeams -Confirm:$false } catch { }
Write-Host 'Export complete.'
