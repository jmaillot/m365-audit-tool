# Teams voice toolkit (admin layer — outside the SaaS)

Companion to the SaaS collector (**Teams** product tab) for Teams Phone
migration prep. The SaaS runs on delegated tokens (Graph REST only):
everything below requires the MicrosoftTeams PowerShell module and therefore
runs here, from an admin workstation — and calling policies plus voice
routing have no Graph API at all (not even beta).

Call-detail records are deliberately out of scope: the Graph callRecords API
is application-permission only (`CallRecords.Read.All`, no delegated
support), so a delegated-token tool cannot collect per-call logs.

## Coverage: what lives where

| Data | SaaS (Graph) | This folder (admin) |
|---|---|---|
| Telephone numbers: number, type (Calling Plan / Operator Connect / Direct Routing), source, activation + assignment state, assignee | ✅ **Phone numbers** section (Graph beta) | best-effort cross-check `PhoneNumberAssignments-PS.csv` |
| Calling policies (who may call, forwarding, voicemail, delegation, toll bypass…) | — (no Graph API) | ✅ `TeamsCallingPolicies.csv` |
| Per-user voice state: LineUri, EnterpriseVoiceEnabled, assigned calling + voice-routing policies | — (no Graph API) | ✅ `UserVoice.csv` |
| Voice routing policies + their PSTN usages | — (no Graph API) | ✅ `VoiceRoutingPolicies.csv` |
| Voice routes (number patterns, priority, usages, SBC list) | — (no Graph API) | ✅ `VoiceRoutes.csv` |
| PSTN usages + which policies reference them | — (no Graph API) | ✅ `PstnUsages.csv` |
| Direct Routing SBCs (FQDN, enabled, ports, failover) | — (no Graph API) | ✅ `DirectRoutingSBCs.csv` |
| Meeting policies (chat, recording, transcription, lobby, sharing, reactions…) | — (no Graph API) | ✅ `TeamsMeetingPolicies.csv` (policy script) |
| Messaging policies (chat, edit/delete, Giphy, stickers, memos, priority…) | — (no Graph API) | ✅ `TeamsMessagingPolicies.csv` (policy script) |
| Live events (broadcast) policies (scheduling, transcription, recording) | — (no Graph API) | ✅ `TeamsBroadcastPolicies.csv` (policy script) |
| Per-user policy assignments (meeting + messaging + calling + broadcast) | — (no Graph API) | ✅ `UserPolicyAssignments.csv` (policy script, best-effort) |

All CSVs are `;`-delimited, UTF-8 — same convention as the SaaS tool.

## Prerequisites

- **Teams administrator** role (or Global admin) on the source tenant.
- PowerShell 7.x + module:
  `Install-Module MicrosoftTeams -Scope CurrentUser` (5.x+).
- Interactive sign-in (or certificate auth, see `Connect-MicrosoftTeams` docs).

## Usage

```powershell
# Full inventory (users capped at -UserResultSize, default 10000)
.\scripts\Get-TeamsVoiceInventory.ps1 -OutDir .\out
# -> TeamsCallingPolicies.csv, UserVoice.csv, VoiceRoutingPolicies.csv,
#    VoiceRoutes.csv, PstnUsages.csv, DirectRoutingSBCs.csv
#    (+ PhoneNumberAssignments-PS.csv when the cmdlet exists)

# Faster triage: only EnterpriseVoice-enabled users in UserVoice.csv
.\scripts\Get-TeamsVoiceInventory.ps1 -VoiceOnly -OutDir .\out
```

Tip: join `UserVoice.csv` (column `LineUri`) with the SaaS
`TeamsPhoneNumbers-*.csv` (column `TelephoneNumber`) in Excel to spot
numbers assigned outside Teams admin or users missing a voice routing
policy before migration.

## Policy inventory (meeting / messaging / live events)

```powershell
# Policy definitions + per-user assignments
.\scripts\Get-TeamsPolicyInventory.ps1 -OutDir .\out
# -> TeamsMeetingPolicies.csv, TeamsMessagingPolicies.csv,
#    TeamsBroadcastPolicies.csv, UserPolicyAssignments.csv

# Definitions only (no per-user pass)
.\scripts\Get-TeamsPolicyInventory.ps1 -DefinitionsOnly -OutDir .\out
```

Tip: join `UserPolicyAssignments.csv` with the SaaS `TeamsActivity-*.csv`
(per-team) and `UserVoice.csv` (per-user voice) to rebuild the full
per-user Teams experience in the target tenant (policies don't migrate
with teams or users).
