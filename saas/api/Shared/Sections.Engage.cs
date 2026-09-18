using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Viva Engage" product tab (Microsoft Graph v1.0):
    //   engage-communities -> GET /employeeExperience/communities (one row
    //     per community: name, description, privacy, backing M365 group
    //     resolved to display name) + optional slow per-community /owners
    //     lookup (community admins). Empty when Viva Engage/Yammer is
    //     unused. groupId joins with the Entra ID Groups section for
    //     membership detail. Needs Community.Read.All.
    // All emitted cells are pre-joined scalars, so Select-Object takes plain
    // property names and the ';' CSV never clashes (multi-values are ','-joined).
    internal static class SectionsEngage
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildCommunitiesSection());
        }

        private static List<string> Collect(AuditSelection sel, params string[] groupKeys)
        {
            return PsScriptHelpers.Collect(sel, groupKeys);
        }

        private const string GraphHeaders =
            "$headers = @{ Authorization = ('Bearer ' + $env:MAT_GRAPH_TOKEN); ConsistencyLevel = 'eventual' }";

        private static AuditSection BuildCommunitiesSection()
        {
            var section = new AuditSection(
                "engage-communities",
                "Communities",
                "Viva Engage communities export",
                "Audit Viva Engage communities via Graph: privacy, backing Microsoft 365 group and admins (one row per community). Empty when Viva Engage is unused.",
                "engage",
                AuditScope.Graph);
            section.Category = "Viva Engage";
            section.Product = "Viva Engage";
            section.DefaultFileName = "EngageCommunities.csv";

            var community = new AuditOptionGroup("community", "Community", GroupMode.MultiCheck); community.Columns = 2;
            community.AddProp("DisplayName", true);
            community.AddProp("Description", true);
            community.AddProp("Privacy", true);
            community.AddProp("GroupName", true);
            community.AddProp("GroupId", true);
            section.AddGroup(community);

            var owners = new AuditOptionGroup("owners", "Admins (slow per-community lookup)", GroupMode.MultiCheck); owners.Columns = 1;
            owners.Hint = "One owners query per community (max 100 admins each). Needs the Community.Read.All consent.";
            owners.Add(AuditOption.Prop("Owners", false).MarkSlow());
            section.AddGroup(owners);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "community", "owners");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                bool wantOwners = chosen.Contains("Owners");
                bool wantGroup = chosen.Contains("GroupName");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Viva Engage communities (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$coms = @()");
                sb.AppendLine("try {");
                sb.AppendLine("    $curi = 'https://graph.microsoft.com/v1.0/employeeExperience/communities'");
                sb.AppendLine("    while ($curi) { $cr = Invoke-RestMethod -Uri $curi -Headers $headers -Method Get -ErrorAction Stop; $coms += @($cr.value); $curi = $cr.'@odata.nextLink' }");
                sb.AppendLine("    Write-Host (\"Retrieved {0} communitie(s).\" -f $coms.Count)");
                sb.AppendLine("} catch { Write-Host ('WARNING: communities query failed (' + $_.Exception.Message + ' - consent for Community.Read.All?)'); $coms = @() }");
                sb.AppendLine("if ($coms.Count -eq 0) { Write-Host 'No communities found - Viva Engage not in use, or consent is missing.' }");
                if (wantGroup)
                {
                    sb.AppendLine("$gCache6 = @{}");
                    sb.AppendLine("$script:g6Fail = 0");
                    sb.AppendLine("function Resolve-EngageGroup { param($gid) if (-not $gid) { return '' }; if ($gCache6.ContainsKey($gid)) { return $gCache6[$gid] }; $nm = $gid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $nm = [string]$o.displayName } } catch { $script:g6Fail++ }; $gCache6[$gid] = $nm; return $nm }");
                }
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantOwners) sb.AppendLine("$ownFail = 0");
                sb.AppendLine("foreach ($c in $coms) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $coms.Count) }");
                sb.AppendLine("    $cid = [string]$c.id");
                if (wantGroup)
                {
                    sb.AppendLine("    $gn = Resolve-EngageGroup ([string]$c.groupId)");
                }
                if (wantOwners)
                {
                    sb.AppendLine("    $ow = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $ol = @(); $ouri = \"https://graph.microsoft.com/v1.0/employeeExperience/communities/\" + $cid + \"/owners?$select=userPrincipalName,displayName\"");
                    sb.AppendLine("        while ($ouri) { $orr = Invoke-RestMethod -Uri $ouri -Headers $headers -Method Get -ErrorAction Stop; $ol += @($or.value); $ouri = $orr.'@odata.nextLink' }");
                    sb.AppendLine("        $ow = ((@($ol | ForEach-Object { $s = [string]$_.userPrincipalName; if (-not $s) { $s = [string]$_.displayName }; $s } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ')");
                    sb.AppendLine("    } catch { $ownFail++ }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        DisplayName = $c.displayName; Description = $c.description; Privacy = $c.privacy;");
                sb.AppendLine("        GroupName = " + (wantGroup ? "$gn" : "''") + "; GroupId = $c.groupId; Owners = " + (wantOwners ? "$ow" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantGroup) sb.AppendLine("if ($script:g6Fail -gt 0) { Write-Host (\"WARNING: {0} backing group(s) could not be resolved to names.\" -f $script:g6Fail) }");
                if (wantOwners) sb.AppendLine("if ($ownFail -gt 0) { Write-Host (\"WARNING: {0} owner querie(s) failed (consent for Community.Read.All?).\" -f $ownFail) }");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ DisplayName = ''; Description = ''; Privacy = ''; GroupName = ''; GroupId = ''; Owners = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }
    }
}
