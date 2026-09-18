using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Conditional Access" product tab (Microsoft Graph, NOT Exchange Online):
    //   ca-policies -> GET /identity/conditionalAccess/policies (one row per
    //     policy: state, dates, user/app/network/risk conditions with group,
    //     user, app, role, location, strength and ToU names resolved via cached
    //     lookups, grant + session controls). CA stores raw group/app GUIDs
    //     that would not survive a migration unresolved. Needs Policy.Read.All
    //     (+ Group/User/Application/Directory/RoleManagement.Read for name
    //     resolution, Agreement.Read.All for ToU names).
    //   ca-locations -> GET /identity/conditionalAccess/namedLocations (IP
    //     ranges, trusted flag, countries). Needs Policy.Read.All.
    //   ca-strengths -> GET /policies/authenticationStrengthPolicies
    //     (allowed MFA combinations). Needs Policy.Read.All + the auditor
    //     holding Conditional Access administrator, Security Administrator
    //     or Security Reader (Graph enforces the role on top of consent).
    //   ca-tou -> GET /identityGovernance/termsOfUse/agreements (+ ?$expand=
    //     files per agreement for document names). Needs Agreement.Read.All.
    // Risk *policies* (sign-in/user risk configuration) have no Graph v1.0 API
    // (portal-only); risk-driven enforcement IS captured per-policy in the
    // RiskLevels column of ca-policies. All emitted cells are pre-joined
    // scalars, so Select-Object takes plain property names and the ';' CSV
    // never clashes (multi-values are ','-joined).
    internal static class SectionsConditionalAccess
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildCaPoliciesSection());
            AuditRegistry.Register(BuildCaLocationsSection());
            AuditRegistry.Register(BuildCaStrengthsSection());
            AuditRegistry.Register(BuildTouSection());
        }

        private static List<string> Collect(AuditSelection sel, params string[] groupKeys)
        {
            return PsScriptHelpers.Collect(sel, groupKeys);
        }

        private const string GraphHeaders =
            "$headers = @{ Authorization = ('Bearer ' + $env:MAT_GRAPH_TOKEN); ConsistencyLevel = 'eventual' }";

        // ============================================================ 1. CA POLICIES
        private static AuditSection BuildCaPoliciesSection()
        {
            var section = new AuditSection(
                "ca-policies",
                "CA policies",
                "Conditional Access policies export",
                "Audit Conditional Access policies via Graph: conditions (users, apps, networks, risk) with IDs resolved to names, plus grant and session controls.",
                "key",
                AuditScope.Graph);
            section.Category = "Conditional Access";
            section.Product = "Conditional Access";
            section.DefaultFileName = "CaPolicies.csv";

            var identity = new AuditOptionGroup("identity", "Policy", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("DisplayName", true);
            identity.AddProp("State", true);
            identity.AddProp("CreatedDateTime", true);
            identity.AddProp("ModifiedDateTime", true);
            section.AddGroup(identity);

            var users = new AuditOptionGroup("users", "User conditions", GroupMode.MultiCheck); users.Columns = 1;
            users.Hint = "Users (UPN), groups (group:Name), directory roles (role:Name) and guest types. Raw GUIDs would not resolve post-migration, hence the lookups.";
            users.AddProp("IncludedUsers", true);
            users.AddProp("ExcludedUsers", true);
            section.AddGroup(users);

            var apps = new AuditOptionGroup("apps", "App & client conditions", GroupMode.MultiCheck); apps.Columns = 1;
            apps.Hint = "Target apps resolved to display names (All/None/Office365 kept literal); client app types and platforms appended.";
            apps.AddProp("IncludedApps", true);
            apps.AddProp("ExcludedApps", true);
            section.AddGroup(apps);

            var context = new AuditOptionGroup("context", "Network & risk conditions", GroupMode.MultiCheck); context.Columns = 1;
            context.AddProp("Networks", true);
            context.AddProp("RiskLevels", true);
            section.AddGroup(context);

            var controls = new AuditOptionGroup("controls", "Controls", GroupMode.MultiCheck); controls.Columns = 1;
            controls.AddProp("GrantControls", true);
            controls.AddProp("SessionControls", true);
            section.AddGroup(controls);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "users", "apps", "context", "controls");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Conditional Access policies + reference data (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$pols = @()");
                sb.AppendLine("$puri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'");
                sb.AppendLine("while ($puri) { $pr = Invoke-RestMethod -Uri $puri -Headers $headers -Method Get -ErrorAction Stop; $pols += @($pr.value); $puri = $pr.'@odata.nextLink' }");
                sb.AppendLine("Write-Host (\"Retrieved {0} CA policies.\" -f $pols.Count)");
                sb.AppendLine("$roleMap = @{}");
                sb.AppendLine("try { $ruri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'; while ($ruri) { $rr = Invoke-RestMethod -Uri $ruri -Headers $headers -Method Get -ErrorAction Stop; foreach ($d in @($rr.value)) { $roleMap[[string]$d.id] = [string]$d.displayName }; $ruri = $rr.'@odata.nextLink' } } catch { Write-Host 'WARNING: roleDefinitions query failed (consent for RoleManagement.Read.Directory?) - role conditions will show raw IDs.' }");
                sb.AppendLine("$locMap = @{}");
                sb.AppendLine("try { $luri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'; while ($luri) { $lr = Invoke-RestMethod -Uri $luri -Headers $headers -Method Get -ErrorAction Stop; foreach ($l in @($lr.value)) { $locMap[[string]$l.id] = [string]$l.displayName }; $luri = $lr.'@odata.nextLink' } } catch { Write-Host 'WARNING: namedLocations query failed (consent for Policy.Read.All?) - network conditions will show raw IDs.' }");
                sb.AppendLine("$strMap = @{}");
                sb.AppendLine("try { $suri = 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies'; while ($suri) { $sr2 = Invoke-RestMethod -Uri $suri -Headers $headers -Method Get -ErrorAction Stop; foreach ($s in @($sr2.value)) { $strMap[[string]$s.id] = [string]$s.displayName }; $suri = $sr2.'@odata.nextLink' } } catch { Write-Host 'WARNING: authenticationStrengthPolicies query failed (consent for Policy.Read.All + a Conditional Access administrator, Security Administrator or Security Reader role?) - strengths will show raw IDs.' }");
                sb.AppendLine("$touMap = @{}");
                sb.AppendLine("try { $turi = 'https://graph.microsoft.com/v1.0/identityGovernance/termsOfUse/agreements'; while ($turi) { $tr = Invoke-RestMethod -Uri $turi -Headers $headers -Method Get -ErrorAction Stop; foreach ($t in @($tr.value)) { $touMap[[string]$t.id] = [string]$t.displayName }; $turi = $tr.'@odata.nextLink' } } catch { Write-Host 'WARNING: agreements query failed (consent for Agreement.Read.All?) - terms of use will show raw IDs.' }");
                sb.AppendLine("$ucache = @{}; $gcache2 = @{}; $acache = @{}");
                sb.AppendLine("$script:caResFail = 0");
                sb.AppendLine("function Resolve-CaUser { param($uid) if ($ucache.ContainsKey($uid)) { return $ucache[$uid] }; $nm = $uid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop; $nm = [string]$o.userPrincipalName; if (-not $nm) { $nm = [string]$o.displayName } } catch { $script:caResFail++ }; $ucache[$uid] = $nm; return $nm }");
                sb.AppendLine("function Resolve-CaGroup { param($gid) if ($gcache2.ContainsKey($gid)) { return $gcache2[$gid] }; $nm = $gid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $nm = [string]$o.displayName } } catch { $script:caResFail++ }; $gcache2[$gid] = $nm; return $nm }");
                sb.AppendLine("function Resolve-CaApp { param($appid) if ($acache.ContainsKey($appid)) { return $acache[$appid] }; $nm = $appid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals(appId='\" + $appid + \"')?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $nm = [string]$o.displayName } } catch { $script:caResFail++ }; $acache[$appid] = $nm; return $nm }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                sb.AppendLine("foreach ($p in $pols) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $pols.Count) }");
                sb.AppendLine("    $iu = @($p.conditions.users.includeUsers); $ig = @($p.conditions.users.includeGroups); $ir = @($p.conditions.users.includeRoles)");
                sb.AppendLine("    if ($iu -contains 'All') { $inc = 'All users' }");
                sb.AppendLine("    else { $parts = @(); foreach ($x in @($iu | Where-Object { $_ -notin @('All', 'None') })) { if ($x) { $parts += Resolve-CaUser ([string]$x) } }; foreach ($x in @($ig)) { if ($x) { $parts += 'group:' + (Resolve-CaGroup ([string]$x)) } }; $rl = @(); foreach ($x in @($ir)) { if ($x) { $rn = [string]$x; if ($roleMap.ContainsKey($rn)) { $rn = $roleMap[$rn] }; if ($rn -and ($rl -notcontains $rn)) { $rl += $rn } } }; $rl = @($rl | Sort-Object -Unique); $gt = ''; try { $gt = ((@(@($p.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes) + @($p.conditions.users.includeGuestsOrExternalUsers.externalUserTypes) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')) } catch { }; $segs = @(); $base = ((@($parts | Sort-Object -Unique)) -join ', '); if ($base) { $segs += $base }; if ($gt) { $segs += 'guests : ' + $gt }; if ($rl.Count -gt 0) { $segs += 'roles : ' + ($rl -join ', ') }; $inc = ($segs -join ' / '); if (-not $inc) { $inc = 'None' } }");
                sb.AppendLine("    $xp = @(); foreach ($x in @($p.conditions.users.excludeUsers)) { if ($x) { $xp += Resolve-CaUser ([string]$x) } }; foreach ($x in @($p.conditions.users.excludeGroups)) { if ($x) { $xp += 'group:' + (Resolve-CaGroup ([string]$x)) } }; foreach ($x in @($p.conditions.users.excludeRoles)) { $rn = [string]$x; if ($roleMap.ContainsKey($rn)) { $rn = $roleMap[$rn] }; $xp += 'role:' + $rn }; $exc = (($xp | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("    $ia = @($p.conditions.applications.includeApplications)");
                sb.AppendLine("    if ($ia -contains 'All') { $inca = 'All Apps' } elseif ($ia -contains 'None') { $inca = 'None' } else { $inca = ((@($ia | ForEach-Object { $a = [string]$_; if ($a -eq 'Office365' -or -not $a) { $a } else { Resolve-CaApp $a } } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ') }");
                sb.AppendLine("    try { $ct = ((@($p.conditions.clientAppTypes) | Where-Object { $_ -ne '' }) -join ','); if ($ct -and $inca -notmatch '^(None)?$') { $inca = $inca + ' / Clients : ' + $ct } } catch { }");
                sb.AppendLine("    try { $pf = ((@($p.conditions.platforms.includePlatforms) | Where-Object { $_ -ne '' }) -join ','); if ($pf -and $pf -ne 'all') { $inca = $inca + ' / Platforms : ' + $pf } } catch { }");
                sb.AppendLine("    $exa = ((@($p.conditions.applications.excludeApplications | ForEach-Object { $a = [string]$_; if ($a -eq 'Office365' -or -not $a) { $a } else { Resolve-CaApp $a } } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ')");
                sb.AppendLine("    $nl = ''; try { $il = @($p.conditions.networks.includeLocations); if ($il -contains 'All') { $nl = 'All' } elseif ($il -contains 'AllTrusted') { $nl = 'AllTrusted' } else { $nl = ((@($il | ForEach-Object { $ln = [string]$_; if ($locMap.ContainsKey($ln)) { $ln = $locMap[$ln] }; $ln } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ') }; $el = @($p.conditions.networks.excludeLocations | ForEach-Object { $ln = [string]$_; if ($locMap.ContainsKey($ln)) { $ln = $locMap[$ln] }; $ln } | Where-Object { $_ -ne '' } | Sort-Object -Unique); if ($el.Count -gt 0) { if ($nl) { $nl = $nl + ' except ' + ($el -join ', ') } else { $nl = 'All except ' + ($el -join ', ') } } } catch { }");
                sb.AppendLine("    $rk = @(); try { foreach ($r in @($p.conditions.signInRiskLevels)) { if ($r -and $r -ne 'none') { $rk += 'signIn:' + [string]$r } } } catch { }; try { foreach ($r in @($p.conditions.userRiskLevels)) { if ($r -and $r -ne 'none') { $rk += 'user:' + [string]$r } } } catch { }; $risk = ($rk -join ', ')");
                sb.AppendLine("    $gc = ''; try { $gp = @(); $bop = ' OR '; try { if ([string]$p.grantControls.operator -eq 'AND') { $bop = ' AND ' } } catch { }; $bc = ((@($p.grantControls.builtInControls | Where-Object { $_ -ne '' } | ForEach-Object { 'Require: ' + [string]$_ })) -join $bop); if ($bc) { $gp += $bc }; try { $asid = [string]$p.grantControls.authenticationStrength.id; if ($asid) { $asn = $asid; if ($strMap.ContainsKey($asid)) { $asn = $strMap[$asid] }; $gp += 'strength: ' + $asn } } catch { }; try { $tous = @($p.grantControls.termsOfUse | ForEach-Object { $t = [string]$_; if ($touMap.ContainsKey($t)) { $touMap[$t] } else { $t } } | Where-Object { $_ -ne '' }); if ($tous.Count -gt 0) { $gp += 'ToU: ' + ($tous -join ', ') } } catch { }; try { $cf = @($p.grantControls.customAuthenticationFactors | Where-Object { $_ -ne '' }); if ($cf.Count -gt 0) { $gp += 'custom: ' + ($cf -join ', ') } } catch { }; $gc = ($gp -join ' | ') } catch { }");
                sb.AppendLine("    $sc2 = @(); try { if ([bool]$p.sessionControls.applicationEnforcedRestrictions.isEnabled) { $sc2 += 'appEnforcedRestrictions' } } catch { }; try { if ([bool]$p.sessionControls.cloudAppSecurity.isEnabled) { $sc2 += 'cloudAppSecurity(' + [string]$p.sessionControls.cloudAppSecurity.cloudAppSecurityType + ')' } } catch { }; try { if ([bool]$p.sessionControls.signInFrequency.isEnabled) { $sc2 += 'signInFrequency(' + [string]$p.sessionControls.signInFrequency.value + ' ' + [string]$p.sessionControls.signInFrequency.type + ')' } } catch { }; try { if ([bool]$p.sessionControls.persistentBrowser.isEnabled) { $sc2 += 'persistentBrowser(' + [string]$p.sessionControls.persistentBrowser.mode + ')' } } catch { }; try { if ([bool]$p.sessionControls.compliantDevice.isEnabled) { $sc2 += 'compliantDevice' } } catch { }; try { if ([bool]$p.sessionControls.domainJoinedDevice.isEnabled) { $sc2 += 'hybridJoinedDevice' } } catch { }; try { if ([bool]$p.sessionControls.disableResilienceDefaults.isEnabled) { $sc2 += 'disableResilienceDefaults' } } catch { }; try { if ([bool]$p.sessionControls.secureSignInSession.isEnabled) { $sc2 += 'secureSignInSession' } } catch { }; $sc = ($sc2 -join ', ')");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        DisplayName = $p.displayName; State = $p.state; CreatedDateTime = $p.createdDateTime; ModifiedDateTime = $p.modifiedDateTime;");
                sb.AppendLine("        IncludedUsers = $inc; ExcludedUsers = $exc; IncludedApps = $inca; ExcludedApps = $exa;");
                sb.AppendLine("        Networks = $nl; RiskLevels = $risk; GrantControls = $gc; SessionControls = $sc");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ DisplayName = ''; State = ''; CreatedDateTime = ''; ModifiedDateTime = ''; IncludedUsers = ''; ExcludedUsers = ''; IncludedApps = ''; ExcludedApps = ''; Networks = ''; RiskLevels = ''; GrantControls = ''; SessionControls = '' }) }");
                sb.AppendLine("if ($script:caResFail -gt 0) { Write-Host (\"WARNING: {0} user/group/app reference(s) could not be resolved to names.\" -f $script:caResFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 2. NAMED LOCATIONS
        private static AuditSection BuildCaLocationsSection()
        {
            var section = new AuditSection(
                "ca-locations",
                "Named locations",
                "Named locations export",
                "Audit Conditional Access named locations via Graph: trusted IPs, ranges and countries.",
                "key",
                AuditScope.Graph);
            section.Category = "Conditional Access";
            section.Product = "Conditional Access";
            section.DefaultFileName = "CaNamedLocations.csv";

            var identity = new AuditOptionGroup("identity", "Location", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("DisplayName", true);
            identity.AddProp("LocationType", true);
            identity.AddProp("IsTrusted", true);
            section.AddGroup(identity);

            var scope = new AuditOptionGroup("scope", "Scope", GroupMode.MultiCheck); scope.Columns = 1;
            scope.AddProp("IPRanges", true);
            scope.AddProp("Countries", true);
            section.AddGroup(scope);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "scope");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying named locations (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$locs = @()");
                sb.AppendLine("$luri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'");
                sb.AppendLine("while ($luri) { $lr = Invoke-RestMethod -Uri $luri -Headers $headers -Method Get -ErrorAction Stop; $locs += @($lr.value); $luri = $lr.'@odata.nextLink' }");
                sb.AppendLine("Write-Host (\"Retrieved {0} named location(s).\" -f $locs.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($l in $locs) {");
                sb.AppendLine("    $lt = ([string]$l.'@odata.type' -replace '^#microsoft.graph.', '')");
                sb.AppendLine("    $trust = ''; try { $trust = [string]$l.isTrusted } catch { }");
                sb.AppendLine("    $ips = ''; try { $ips = ((@($l.ipRanges) | ForEach-Object { [string]$_.cidrAddress } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',') } catch { }");
                sb.AppendLine("    $ct = ''; try { $ct = [string]$l.countryLookupMethod } catch { }; try { $cl = ((@($l.countriesAndRegions) | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ','); if ($cl) { if ($ct) { $ct = $ct + ': ' + $cl } else { $ct = $cl } } } catch { }");
                sb.AppendLine("    try { if ([bool]$l.includeUnknownCountriesAndRegions) { if ($ct) { $ct = $ct + ' (+unknown)' } else { $ct = '+unknown' } } } catch { }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{ DisplayName = $l.displayName; LocationType = $lt; IsTrusted = $trust; IPRanges = $ips; Countries = $ct })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ DisplayName = ''; LocationType = ''; IsTrusted = ''; IPRanges = ''; Countries = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 3. AUTH STRENGTHS
        private static AuditSection BuildCaStrengthsSection()
        {
            var section = new AuditSection(
                "ca-strengths",
                "Authentication strengths",
                "Authentication strengths export",
                "Audit Conditional Access authentication strengths via Graph: allowed MFA combinations per strength.",
                "key",
                AuditScope.Graph);
            section.Category = "Conditional Access";
            section.Product = "Conditional Access";
            section.DefaultFileName = "CaAuthStrengths.csv";

            var identity = new AuditOptionGroup("identity", "Strength", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("DisplayName", true);
            identity.AddProp("Description", true);
            identity.AddProp("AllowedCombinations", true);
            section.AddGroup(identity);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying authentication strengths (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$strs = @()");
                sb.AppendLine("try {");
                sb.AppendLine("    $suri = 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies'");
                sb.AppendLine("    while ($suri) { $sr = Invoke-RestMethod -Uri $suri -Headers $headers -Method Get -ErrorAction Stop; $strs += @($sr.value); $suri = $sr.'@odata.nextLink' }");
                sb.AppendLine("    Write-Host (\"Retrieved {0} authentication strength(s).\" -f $strs.Count)");
                sb.AppendLine("} catch { Write-Host 'WARNING: authenticationStrengthPolicies query failed (consent for Policy.Read.All + a Conditional Access administrator, Security Administrator or Security Reader role?) - export will be empty.' }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($s in $strs) {");
                sb.AppendLine("    $cb = ((@($s.allowedCombinations) | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')");
                sb.AppendLine("    $rows.Add([pscustomobject]@{ DisplayName = $s.displayName; Description = $s.description; AllowedCombinations = $cb })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ DisplayName = ''; Description = ''; AllowedCombinations = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 4. TERMS OF USE
        private static AuditSection BuildTouSection()
        {
            var section = new AuditSection(
                "ca-tou",
                "Terms of use",
                "Terms of use export",
                "Audit terms of use agreements via Graph: documents, acceptance and expiry settings.",
                "key",
                AuditScope.Graph);
            section.Category = "Conditional Access";
            section.Product = "Conditional Access";
            section.DefaultFileName = "CaTermsOfUse.csv";

            var identity = new AuditOptionGroup("identity", "Agreement", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("DisplayName", true);
            identity.AddProp("FileNames", true);
            section.AddGroup(identity);

            var settings = new AuditOptionGroup("settings", "Acceptance settings", GroupMode.MultiCheck); settings.Columns = 2;
            settings.AddProp("RequireView", true);
            settings.AddProp("RequirePerDevice", true);
            settings.AddProp("ReacceptFrequency", true);
            settings.AddProp("Expiration", true);
            section.AddGroup(settings);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "settings");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying terms of use agreements (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$ags = @()");
                sb.AppendLine("try {");
                sb.AppendLine("    $auri = 'https://graph.microsoft.com/v1.0/identityGovernance/termsOfUse/agreements'");
                sb.AppendLine("    while ($auri) { $ar = Invoke-RestMethod -Uri $auri -Headers $headers -Method Get -ErrorAction Stop; $ags += @($ar.value); $auri = $ar.'@odata.nextLink' }");
                sb.AppendLine("    Write-Host (\"Retrieved {0} agreement(s).\" -f $ags.Count)");
                sb.AppendLine("} catch { Write-Host 'WARNING: agreements query failed (consent for Agreement.Read.All?).' }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                sb.AppendLine("foreach ($a in $ags) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $ags.Count) }");
                sb.AppendLine("    $aid = [string]$a.id");
                sb.AppendLine("    $fn = ''");
                sb.AppendLine("    try { $ex = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/identityGovernance/termsOfUse/agreements/\" + $aid + \"?`$expand=files\") -Headers $headers -Method Get -ErrorAction Stop; $fn = ((@($ex.files) | ForEach-Object { [string]$_.displayName } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',') } catch { }");
                sb.AppendLine("    $exp = ''; try { $tx = $a.termsExpiration; if ($tx) { $exp = 'frequency: ' + [string]$tx.frequency + ', ' + [string]$tx.startDateTime + ' -> ' + [string]$tx.endDateTime } } catch { }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        DisplayName = $a.displayName; FileNames = $fn;");
                sb.AppendLine("        RequireView = $a.isViewingBeforeAcceptanceRequired; RequirePerDevice = $a.isPerDeviceAcceptanceRequired;");
                sb.AppendLine("        ReacceptFrequency = $a.userReacceptRequiredFrequency; Expiration = $exp");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ DisplayName = ''; FileNames = ''; RequireView = ''; RequirePerDevice = ''; ReacceptFrequency = ''; Expiration = '' }) }");
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
