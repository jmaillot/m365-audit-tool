using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Power Platform" product tab (unified Power Platform API,
    // https://api.powerplatform.com - NOT Graph and NOT Exchange Online):
    //   pp-environments -> GET /environmentmanagement/environments (one row
    //     per environment: SKU, default flag, region, state, Dataverse).
    //   pp-flows       -> per environment /powerautomate/environments/{id}/
    //     cloudFlows (one row per flow - slow per-environment lookup; 404
    //     means the environment has no Dataverse database).
    //   pp-apps        -> per environment /powerapps/environments/{id}/apps
    //     as administrator (one row per app, owner UPN inline - slow
    //     per-environment lookup, $skiptoken paging).
    //   pp-connectors  -> per environment /connectivity/environments/{id}/
    //     connectors?$filter=isCustomApi eq true (custom connectors only -
    //     the Entra-backed integrations that break quietly; slow
    //     per-environment lookup).
    // Auth is a third delegated token (MAT_POWER_TOKEN, audience
    // https://api.powerplatform.com) carrying the four Read scopes below -
    // see README setup. Needs those consents AND the auditor holding Power
    // Platform administrator (or equivalent). Paging is nextLink-in-body
    // (apps/connectors) - both link forms are followed.
    // NOTE: per-endpoint warnings name the failing call, so an API drift
    // shows up immediately in the job log instead of silently emptying
    // the CSV.
    // All emitted cells are pre-joined scalars, so Select-Object takes plain
    // property names and the ';' CSV never clashes (multi-values are ','-joined).
    internal static class SectionsPowerPlatform
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildEnvironmentsSection());
            AuditRegistry.Register(BuildFlowsSection());
            AuditRegistry.Register(BuildAppsSection());
            AuditRegistry.Register(BuildConnectorsSection());
        }

        private static List<string> Collect(AuditSelection sel, params string[] groupKeys)
        {
            return PsScriptHelpers.Collect(sel, groupKeys);
        }

        private const string PowerHeaders =
            "$pheaders = @{ Authorization = ('Bearer ' + $env:MAT_POWER_TOKEN) }";

        private static string SizePrelude(string size)
        {
            // NOTE: plain concatenation, NOT string.Format: the PowerShell body
            // contains literal { } blocks that string.Format would try to parse.
            return "$size = '" + size + "'\n$maxPP = -1\nif ($size -eq '100') { $maxPP = 100 } elseif ($size -eq '1000') { $maxPP = 1000 }";
        }

        private const string FetchEnvironments =
            "$envs = @()\n" +
            "$euri = 'https://api.powerplatform.com/environmentmanagement/environments?api-version=2024-10-01'\n" +
            "while ($euri -and ($maxPP -lt 0 -or $envs.Count -lt $maxPP)) {\n" +
            "    $er = Invoke-RestMethod -Uri $euri -Headers $pheaders -Method Get -ErrorAction Stop\n" +
            "    $envs += @($er.value)\n" +
            "    $euri = $er.nextLink; if (-not $euri) { $euri = $er.'@odata.nextLink' }\n" +
            "}\n" +
            "if ($maxPP -ge 0 -and $envs.Count -gt $maxPP) { $envs = $envs[0..($maxPP - 1)] }\n" +
            "Write-Host (\"Retrieved {0} environment(s).\" -f $envs.Count)\n" +
            "if ($envs.Count -eq 0) { Write-Host 'No environments found - auditor lacks Power Platform administrator, or consent for the Power Apps Service permission is missing.' }";

        // ============================================================ 1. ENVIRONMENTS
        private static AuditSection BuildEnvironmentsSection()
        {
            var section = new AuditSection(
                "pp-environments",
                "Environments",
                "Environments export",
                "Audit Power Platform environments via the Power Platform API: SKU, default flag, region, state and Dataverse presence (one row per environment).",
                "cloud",
                AuditScope.PowerPlatform);
            section.Category = "Power Platform";
            section.Product = "Power Platform";
            section.DefaultFileName = "PowerPlatformEnvironments.csv";

            var env = new AuditOptionGroup("env", "Environment", GroupMode.MultiCheck); env.Columns = 2;
            env.AddProp("EnvName", true);
            env.AddProp("DisplayName", true);
            env.AddProp("EnvironmentSku", true);
            env.AddProp("IsDefault", true);
            env.AddProp("Region", true);
            env.AddProp("State", true);
            env.AddProp("HasDataverse", true);
            env.AddProp("DataverseUrl", true);
            env.AddProp("DataverseVersion", true);
            env.AddProp("DataverseOrgId", true);
            env.AddProp("CreatedTime", true);
            env.AddProp("CreatedBy", true);
            section.AddGroup(env);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "env");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Power Platform environments (BAP admin API)...'");
                sb.AppendLine(PowerHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("try {");
                sb.AppendLine(FetchEnvironments);
                sb.AppendLine("} catch { Write-Host ('WARNING: environments query failed (' + $_.Exception.Message + ' - Power Apps Service consent + Power Platform administrator?)'); $envs = @() }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($e in $envs) {");
                sb.AppendLine("    $rg = [string]$e.location; if (-not $rg) { $rg = [string]$e.properties.azureRegion }");
                sb.AppendLine("    $st = ''; try { $sm = [string]$e.properties.states.management.id; $sr = [string]$e.properties.states.runtime.id; $st = $sm; if ($sr -and $sr -ne $sm) { $st = $st + ' / runtime ' + $sr } } catch { }; if (-not $st) { try { $st = [string]$e.properties.provisioningState } catch { } }");
                sb.AppendLine("    $dv = 'No'; $durl = ''; $dver = ''; $dorg = ''; try { if ($null -ne $e.properties.linkedEnvironmentMetadata) { $dv = 'Yes'; $durl = [string]$e.properties.linkedEnvironmentMetadata.instanceUrl; $dver = [string]$e.properties.linkedEnvironmentMetadata.version; $dorg = [string]$e.properties.linkedEnvironmentMetadata.resourceId } } catch { }");
                sb.AppendLine("    $cb = ''; try { $cb = [string]$e.properties.createdBy.displayName; if (-not $cb) { $cb = [string]$e.properties.createdBy.type } } catch { }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        EnvName = $e.name; DisplayName = $e.properties.displayName; EnvironmentSku = $e.properties.environmentSku; IsDefault = $e.properties.isDefault;");
                sb.AppendLine("        Region = $rg; State = $st; HasDataverse = $dv; DataverseUrl = $durl; DataverseVersion = $dver; DataverseOrgId = $dorg;");
                sb.AppendLine("        CreatedTime = $e.properties.createdTime; CreatedBy = $cb");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ EnvName = ''; DisplayName = ''; EnvironmentSku = ''; IsDefault = ''; Region = ''; State = ''; HasDataverse = ''; DataverseUrl = ''; DataverseVersion = ''; DataverseOrgId = ''; CreatedTime = ''; CreatedBy = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 2. FLOWS
        private static AuditSection BuildFlowsSection()
        {
            var section = new AuditSection(
                "pp-flows",
                "Flows",
                "Power Automate flows export",
                "Audit Power Automate flows per environment via the Power Platform API (one row per flow - slow per-environment lookup).",
                "flow",
                AuditScope.PowerPlatform);
            section.Category = "Power Platform";
            section.Product = "Power Platform";
            section.DefaultFileName = "PowerPlatformFlows.csv";

            var flow = new AuditOptionGroup("flow", "Flow", GroupMode.MultiCheck); flow.Columns = 2;
            flow.AddProp("Environment", true);
            flow.AddProp("FlowName", true);
            flow.AddProp("DisplayName", true);
            flow.AddProp("State", true);
            flow.AddProp("CreatedTime", true);
            flow.AddProp("CreatedBy", true);
            section.AddGroup(flow);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "flow");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Power Automate flows per environment (BAP admin API)...'");
                sb.AppendLine(PowerHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("try {");
                sb.AppendLine(FetchEnvironments);
                sb.AppendLine("} catch { Write-Host ('WARNING: environments query failed (' + $_.Exception.Message + ' - Power Apps Service consent + Power Platform administrator?)'); $envs = @() }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0; $flFail = 0");
                sb.AppendLine("foreach ($e in $envs) {");
                sb.AppendLine("    $i++; Write-Host (\"  [{0}/{1}] {2}\" -f $i, $envs.Count, $e.properties.displayName)");
                sb.AppendLine("    $enm = [string]$e.name; $edn = [string]$e.properties.displayName; if (-not $edn) { $edn = $enm }");
                sb.AppendLine("    try {");
                sb.AppendLine("        $fl = @(); $furi = \"https://api.powerplatform.com/powerautomate/environments/\" + $enm + \"/cloudFlows?api-version=2024-10-01\"");
                sb.AppendLine("        while ($furi) { $fr = Invoke-RestMethod -Uri $furi -Headers $pheaders -Method Get -ErrorAction Stop; $fl += @($fr.value); $furi = $fr.nextLink; if (-not $furi) { $furi = $fr.'@odata.nextLink' } }");
                sb.AppendLine("        foreach ($f in $fl) {");
                sb.AppendLine("            $fs = [string]$f.properties.state; if (-not $fs) { $fs = [string]$f.properties.status }");
                sb.AppendLine("            $fc = ''; try { $fc = [string]$f.properties.createdBy.displayName; if (-not $fc) { $fc = [string]$f.properties.creator.displayName } } catch { }");
                sb.AppendLine("            $rows.Add([pscustomobject]@{");
                sb.AppendLine("                Environment = $edn; FlowName = $f.name; DisplayName = $f.properties.displayName; State = $fs;");
                sb.AppendLine("                CreatedTime = $f.properties.createdTime; CreatedBy = $fc");
                sb.AppendLine("            })");
                sb.AppendLine("        }");
                sb.AppendLine("    } catch { $flFail++; Write-Host (\"  WARNING: flows of '{0}' failed: \" -f $edn + $_.Exception.Message) }");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ Environment = ''; FlowName = ''; DisplayName = ''; State = ''; CreatedTime = ''; CreatedBy = '' }); if ($flFail -eq 0 -and $envs.Count -gt 0) { Write-Host 'No flows found in the enumerated environments.' } }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 3. APPS
        private static AuditSection BuildAppsSection()
        {
            var section = new AuditSection(
                "pp-apps",
                "Power Apps",
                "Power Apps export",
                "Audit Power Apps per environment via the Power Platform API (one row per app - slow per-environment lookup).",
                "app",
                AuditScope.PowerPlatform);
            section.Category = "Power Platform";
            section.Product = "Power Platform";
            section.DefaultFileName = "PowerPlatformApps.csv";

            var app = new AuditOptionGroup("app", "App", GroupMode.MultiCheck); app.Columns = 2;
            app.AddProp("Environment", true);
            app.AddProp("AppName", true);
            app.AddProp("DisplayName", true);
            app.AddProp("AppType", true);
            app.AddProp("CreatedTime", true);
            app.AddProp("Owner", true);
            section.AddGroup(app);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "app");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Power Apps per environment (BAP admin API)...'");
                sb.AppendLine(PowerHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("try {");
                sb.AppendLine(FetchEnvironments);
                sb.AppendLine("} catch { Write-Host ('WARNING: environments query failed (' + $_.Exception.Message + ' - Power Apps Service consent + Power Platform administrator?)'); $envs = @() }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0; $appFail = 0");
                sb.AppendLine("foreach ($e in $envs) {");
                sb.AppendLine("    $i++; Write-Host (\"  [{0}/{1}] {2}\" -f $i, $envs.Count, $e.properties.displayName)");
                sb.AppendLine("    $enm = [string]$e.name; $edn = [string]$e.properties.displayName; if (-not $edn) { $edn = $enm }");
                sb.AppendLine("    try {");
                sb.AppendLine("        $al = @(); $auri = \"https://api.powerplatform.com/powerapps/environments/\" + $enm + \"/apps?`$top=100&api-version=2024-10-01\"");
                sb.AppendLine("        while ($auri) { $ar = Invoke-RestMethod -Uri $auri -Headers $pheaders -Method Get -ErrorAction Stop; $al += @($ar.value); $auri = $ar.nextLink; if (-not $auri) { $auri = $ar.'@odata.nextLink' } }");
                sb.AppendLine("        foreach ($a in $al) {");
                sb.AppendLine("            $at = [string]$a.properties.appKind; if (-not $at) { $at = [string]$a.properties.appType }; if (-not $at) { $at = [string]$a.type }");
                sb.AppendLine("            $ao = ''; try { $ao = [string]$a.properties.owner.userPrincipalName; if (-not $ao) { $ao = [string]$a.properties.owner.displayName }; if (-not $ao) { $ao = [string]$a.properties.owner.email }; if (-not $ao) { $ao = [string]$a.properties.createdBy.displayName } } catch { }");
                sb.AppendLine("            $rows.Add([pscustomobject]@{");
                sb.AppendLine("                Environment = $edn; AppName = $a.name; DisplayName = $a.properties.displayName; AppType = $at;");
                sb.AppendLine("                CreatedTime = $a.properties.createdTime; Owner = $ao");
                sb.AppendLine("            })");
                sb.AppendLine("        }");
                sb.AppendLine("    } catch { $appFail++; Write-Host (\"  WARNING: apps of '{0}' failed: \" -f $edn + $_.Exception.Message) }");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ Environment = ''; AppName = ''; DisplayName = ''; AppType = ''; CreatedTime = ''; Owner = '' }); if ($appFail -eq 0 -and $envs.Count -gt 0) { Write-Host 'No apps found in the enumerated environments.' } }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 4. CUSTOM CONNECTORS
        private static AuditSection BuildConnectorsSection()
        {
            var section = new AuditSection(
                "pp-connectors",
                "Custom connectors",
                "Custom connectors export",
                "Audit custom connectors per environment via the Power Platform API (one row per custom connector - slow per-environment lookup). These Entra-backed integrations break quietly on secret expiry or permission loss.",
                "plug",
                AuditScope.PowerPlatform);
            section.Category = "Power Platform";
            section.Product = "Power Platform";
            section.DefaultFileName = "PowerPlatformConnectors.csv";

            var conn = new AuditOptionGroup("conn", "Custom connector", GroupMode.MultiCheck); conn.Columns = 2;
            conn.AddProp("Environment", true);
            conn.AddProp("ConnectorName", true);
            conn.AddProp("DisplayName", true);
            conn.AddProp("Description", true);
            conn.AddProp("Publisher", true);
            conn.AddProp("CreatedTime", true);
            section.AddGroup(conn);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "conn");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying custom connectors per environment (BAP admin API)...'");
                sb.AppendLine(PowerHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("try {");
                sb.AppendLine(FetchEnvironments);
                sb.AppendLine("} catch { Write-Host ('WARNING: environments query failed (' + $_.Exception.Message + ' - Power Apps Service consent + Power Platform administrator?)'); $envs = @() }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0; $cxFail = 0");
                sb.AppendLine("foreach ($e in $envs) {");
                sb.AppendLine("    $i++; Write-Host (\"  [{0}/{1}] {2}\" -f $i, $envs.Count, $e.properties.displayName)");
                sb.AppendLine("    $enm = [string]$e.name; $edn = [string]$e.properties.displayName; if (-not $edn) { $edn = $enm }");
                sb.AppendLine("    try {");
                sb.AppendLine("        $cl = @(); $curi = \"https://api.powerplatform.com/connectivity/environments/\" + $enm + \"/connectors?`$filter=isCustomApi%20eq%20true&api-version=2024-10-01\"");
                sb.AppendLine("        while ($curi) { $cr = Invoke-RestMethod -Uri $curi -Headers $pheaders -Method Get -ErrorAction Stop; $cl += @($cr.value); $curi = $cr.nextLink; if (-not $curi) { $curi = $cr.'@odata.nextLink' } }");
                sb.AppendLine("        foreach ($c in $cl) {");
                sb.AppendLine("            $rows.Add([pscustomobject]@{");
                sb.AppendLine("                Environment = $edn; ConnectorName = $c.name; DisplayName = $c.properties.displayName; Description = $c.properties.description;");
                sb.AppendLine("                Publisher = $c.properties.publisher; CreatedTime = $c.properties.createdTime");
                sb.AppendLine("            })");
                sb.AppendLine("        }");
                sb.AppendLine("    } catch { $cxFail++; Write-Host (\"  WARNING: custom connectors of '{0}' failed: \" -f $edn + $_.Exception.Message) }");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ Environment = ''; ConnectorName = ''; DisplayName = ''; Description = ''; Publisher = ''; CreatedTime = '' }); if ($cxFail -eq 0 -and $envs.Count -gt 0) { Write-Host 'No custom connectors found in the enumerated environments.' } }");
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
