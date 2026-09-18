using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Purview" product tab (Security & Compliance PowerShell via
    // Connect-IPPSSession, same worker path as the Protection section):
    //   purview-dlp    -> Get-DlpPolicy (+ Get-DlpComplianceRule): DLP
    //     policies and rules. Deeper than the protection-policies DLP list
    //     (which only takes Name/State/Mode/Priority/Description).
    //   purview-labels -> Get-Label (+ Get-LabelPolicy): MIP sensitivity
    //     labels and label policies. Defender-focused protection-policies
    //     covers none of this.
    //   purview-holds  -> Get-ComplianceCase (enumerate eDiscovery cases) +
    //     Get-CaseHoldPolicy -Case / Get-CaseHoldRule -Policy (holds cannot
    //     be listed without a case/policy id). Per-mailbox litigation-hold
    //     flags already live in mailbox-list (Retention / compliance group) -
    //     this section covers the hold policies/rules side, not retention
    //     policies.
    // All three run under Connect-IPPSSession: the worker treats a script as
    // a protection run when it names one of the cmdlets below (see
    // worker/run_job.py is_protection - Get-Label/CasHold included).
    internal static class SectionsPurview
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildDlpSection());
            AuditRegistry.Register(BuildLabelsSection());
            AuditRegistry.Register(BuildHoldsSection());
        }

        // Properties that are collections -> joined with ',' so a ';' CSV never clashes.
        private static readonly List<string> MultiValued = new List<string>(new string[]
        {
            "Labels", "ExchangeLocation", "SharePointLocation", "OneDriveLocation",
            "TeamsLocation", "ModernGroupLocation"
        });

        private static string BuildSelectList(List<string> chosen)
        {
            var exprs = new List<string>();
            foreach (string v in chosen)
            {
                if (MultiValued.Contains(v))
                    exprs.Add("@{Name='" + v + "';Expression={($_." + v + " | ForEach-Object { [string]$_ }) -join ','}}");
                else exprs.Add(v);
            }
            if (exprs.Count == 0) exprs.Add("Name");
            return string.Join(", ", exprs.ToArray());
        }

        private static List<string> Collect(AuditSelection sel, params string[] groupKeys)
        {
            return PsScriptHelpers.Collect(sel, groupKeys);
        }

        // ============================================================ 1. DLP
        private static AuditSection BuildDlpSection()
        {
            var section = new AuditSection(
                "purview-dlp",
                "DLP policies",
                "DLP policy export",
                "Audit Purview DLP policies and compliance rules via Security & Compliance PowerShell (one object per run). Deeper than the protection-policies DLP list.",
                "shield",
                AuditScope.ExchangeOnline);
            section.Category = "DLP policies";
            section.Product = "Purview";
            section.DefaultFileName = "PurviewDlp.csv";

            var obj = new AuditOptionGroup("object", "Object", GroupMode.SingleChoice); obj.Columns = 1;
            obj.Add(new AuditOption("dlppolicy", "DLP policies (Get-DlpPolicy)", "dlppolicy", true));
            obj.Add(new AuditOption("dlprule", "DLP rules (Get-DlpComplianceRule)", "dlprule", false));
            section.AddGroup(obj);

            var policy = new AuditOptionGroup("policy", "DLP policy properties", GroupMode.MultiCheck); policy.Columns = 2;
            policy.AddProp("Name", true);
            policy.AddProp("State", true);
            policy.AddProp("Mode", true);
            policy.AddProp("Priority", true);
            policy.AddProp("Description", false);
            policy.AddProp("ExchangeLocation", false);
            policy.AddProp("SharePointLocation", false);
            policy.AddProp("OneDriveLocation", false);
            policy.AddProp("TeamsLocation", false);
            section.AddGroup(policy);

            var rule = new AuditOptionGroup("rule", "DLP rule properties", GroupMode.MultiCheck); rule.Columns = 2;
            rule.Hint = "Rules bind policies to content conditions; the linked policy column is added automatically.";
            rule.AddProp("Name", true);
            rule.AddProp("Policy", true);
            rule.AddProp("Priority", true);
            rule.AddProp("State", true);
            rule.AddProp("Disabled", false);
            rule.AddProp("Comment", true);
            section.AddGroup(rule);

            // Per-view defaults (the web resets checkboxes when the Object
            // radio changes): each view checks its own property group.
            section.ViewDefaults["dlppolicy"] = new List<string>
            {
                "policy::Name", "policy::State", "policy::Mode", "policy::Priority"
            };
            section.ViewDefaults["dlprule"] = new List<string>
            {
                "rule::Name", "rule::Policy", "rule::Priority", "rule::State",
                "rule::Comment"
            };

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                string which = sel.First("object", "dlppolicy");
                string cmdlet;
                string propGroup;
                string label;
                string ruleLink = null;
                if (which == "dlprule") { cmdlet = "Get-DlpComplianceRule"; propGroup = "rule"; label = "DLP rules"; ruleLink = "Policy"; }
                else { cmdlet = "Get-DlpPolicy"; propGroup = "policy"; label = "DLP policies"; }

                var chosen = Collect(sel, propGroup);
                if (ruleLink != null && !chosen.Contains(ruleLink)) chosen.Add(ruleLink);
                if (chosen.Count == 0) chosen.Add("Name");
                string selectList = BuildSelectList(chosen);

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying " + label + "...'");
                sb.AppendLine("try { $items = @(" + cmdlet + " -ErrorAction Stop); Write-Host (\"Retrieved {0} " + label + ".\" -f $items.Count) } catch { Write-Host ('WARNING: " + cmdlet + " failed (' + $_.Exception.Message + ')'); $items = @() }");
                sb.AppendLine("if ($items.Count -eq 0) { Write-Host 'No " + label + " found - none configured in this tenant.' }");
                sb.AppendLine("$rows = $items | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 2. LABELS
        private static AuditSection BuildLabelsSection()
        {
            var section = new AuditSection(
                "purview-labels",
                "Sensitivity labels",
                "Sensitivity label export",
                "Audit MIP sensitivity labels and label policies via Security & Compliance PowerShell (one object per run). Not covered by the Defender-focused protection-policies section.",
                "tag",
                AuditScope.ExchangeOnline);
            section.Category = "DLP policies";
            section.Product = "Purview";
            section.DefaultFileName = "PurviewLabels.csv";

            var obj = new AuditOptionGroup("object", "Object", GroupMode.SingleChoice); obj.Columns = 1;
            obj.Add(new AuditOption("labels", "Sensitivity labels (Get-Label)", "labels", true));
            obj.Add(new AuditOption("labelpolicies", "Label policies (Get-LabelPolicy)", "labelpolicies", false));
            section.AddGroup(obj);

            var label = new AuditOptionGroup("label", "Label properties", GroupMode.MultiCheck); label.Columns = 2;
            label.AddProp("Name", true);
            label.AddProp("DisplayName", true);
            label.AddProp("Description", true);
            label.AddProp("Priority", true);
            label.AddProp("ParentId", false);
            label.AddProp("ContentType", false);
            label.AddProp("Tooltip", false);
            section.AddGroup(label);

            var policy = new AuditOptionGroup("labelpolicy", "Label policy properties", GroupMode.MultiCheck); policy.Columns = 2;
            policy.Hint = "Policies publish labels to locations; labels list is joined automatically.";
            policy.AddProp("Name", true);
            policy.AddProp("ExchangeLocation", true);
            policy.AddProp("SharePointLocation", true);
            policy.AddProp("OneDriveLocation", true);
            policy.AddProp("TeamsLocation", true);
            policy.AddProp("ModernGroupLocation", true);
            section.AddGroup(policy);

            // Per-view defaults (the web resets checkboxes when the Object
            // radio changes): each view checks its own property group.
            section.ViewDefaults["labels"] = new List<string>
            {
                "label::Name", "label::DisplayName", "label::Description",
                "label::Priority"
            };
            section.ViewDefaults["labelpolicies"] = new List<string>
            {
                "labelpolicy::Name", "labelpolicy::ExchangeLocation",
                "labelpolicy::SharePointLocation", "labelpolicy::OneDriveLocation",
                "labelpolicy::TeamsLocation", "labelpolicy::ModernGroupLocation"
            };

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                string which = sel.First("object", "labels");
                string cmdlet;
                string propGroup;
                string label2;
                if (which == "labelpolicies") { cmdlet = "Get-LabelPolicy"; propGroup = "labelpolicy"; label2 = "label policies"; }
                else { cmdlet = "Get-Label"; propGroup = "label"; label2 = "sensitivity labels"; }

                var chosen = Collect(sel, propGroup);
                if (which == "labelpolicies" && !chosen.Contains("Labels")) chosen.Add("Labels");
                if (chosen.Count == 0) chosen.Add("Name");
                string selectList = BuildSelectList(chosen);

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying " + label2 + "...'");
                sb.AppendLine("try { $items = @(" + cmdlet + " -ErrorAction Stop); Write-Host (\"Retrieved {0} " + label2 + ".\" -f $items.Count) } catch { Write-Host ('WARNING: " + cmdlet + " failed (' + $_.Exception.Message + ')'); $items = @() }");
                sb.AppendLine("if ($items.Count -eq 0) { Write-Host 'No " + label2 + " found - none configured in this tenant.' }");
                sb.AppendLine("$rows = $items | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 3. HOLDS
        private static AuditSection BuildHoldsSection()
        {
            var section = new AuditSection(
                "purview-holds",
                "eDiscovery holds",
                "eDiscovery hold export",
                "Audit eDiscovery (case) hold policies and rules via Security & Compliance PowerShell (one object per run). Retention policies live elsewhere; this is the holds side.",
                "lock",
                AuditScope.ExchangeOnline);
            section.Category = "DLP policies";
            section.Product = "Purview";
            section.DefaultFileName = "PurviewHolds.csv";
            section.TipHtml = "Per-mailbox litigation-hold flags (LitigationHoldEnabled, InPlaceHolds) live in the Exchange Online <b>User mailboxes</b> section, Retention / compliance group.";

            var obj = new AuditOptionGroup("object", "Object", GroupMode.SingleChoice); obj.Columns = 1;
            obj.Add(new AuditOption("caseholdpolicy", "Case hold policies (per eDiscovery case)", "caseholdpolicy", true));
            obj.Add(new AuditOption("caseholdrule", "Case hold rules (per eDiscovery case)", "caseholdrule", false));
            obj.Add(new AuditOption("cases", "eDiscovery cases (Get-ComplianceCase)", "cases", false));
            section.AddGroup(obj);

            var policy = new AuditOptionGroup("holdpolicy", "Hold policy properties", GroupMode.MultiCheck); policy.Columns = 2;
            policy.Hint = "CaseName is the parent eDiscovery case (policies cannot be listed without one).";
            policy.AddProp("CaseName", true);
            policy.AddProp("Name", true);
            policy.AddProp("Enabled", true);
            policy.AddProp("Comment", false);
            policy.AddProp("ExchangeLocation", true);
            policy.AddProp("SharePointLocation", true);
            policy.AddProp("OneDriveLocation", true);
            policy.AddProp("ModernGroupLocation", true);
            section.AddGroup(policy);

            var rule = new AuditOptionGroup("holdrule", "Hold rule properties", GroupMode.MultiCheck); rule.Columns = 2;
            rule.Hint = "Rules bind hold policies to workloads; the parent case and linked policy columns are added automatically.";
            rule.AddProp("CaseName", true);
            rule.AddProp("Name", true);
            rule.AddProp("Policy", true);
            rule.AddProp("Disabled", true);
            rule.AddProp("Comment", true);
            section.AddGroup(rule);

            var cs = new AuditOptionGroup("case", "Case properties", GroupMode.MultiCheck); cs.Columns = 2;
            cs.AddProp("Name", true);
            cs.AddProp("Status", true);
            cs.AddProp("CaseType", true);
            cs.AddProp("Description", false);
            section.AddGroup(cs);

            // Per-view defaults (the web resets checkboxes when the Object
            // radio changes): each view checks its own property group.
            section.ViewDefaults["caseholdpolicy"] = new List<string>
            {
                "holdpolicy::CaseName", "holdpolicy::Name", "holdpolicy::Enabled",
                "holdpolicy::ExchangeLocation", "holdpolicy::SharePointLocation",
                "holdpolicy::OneDriveLocation", "holdpolicy::ModernGroupLocation"
            };
            section.ViewDefaults["caseholdrule"] = new List<string>
            {
                "holdrule::CaseName", "holdrule::Name", "holdrule::Policy",
                "holdrule::Disabled", "holdrule::Comment"
            };
            section.ViewDefaults["cases"] = new List<string>
            {
                "case::Name", "case::Status", "case::CaseType"
            };

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                string which = sel.First("object", "caseholdpolicy");

                var chosen = Collect(sel, "holdpolicy", "holdrule", "case");
                if (chosen.Count == 0) chosen.Add("Name");
                string selectList = BuildSelectList(chosen);

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying eDiscovery cases (Get-ComplianceCase)...'");
                sb.AppendLine("try { $cases = @(Get-ComplianceCase -ErrorAction Stop); Write-Host (\"Retrieved {0} eDiscovery case(s).\" -f $cases.Count) } catch { Write-Host ('WARNING: Get-ComplianceCase failed (' + $_.Exception.Message + ')'); $cases = @() }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                if (which == "cases")
                {
                    sb.AppendLine("foreach ($c in $cases) { $rows.Add(($c | Select-Object " + selectList + ")) }");
                }
                else if (which == "caseholdrule")
                {
                    sb.AppendLine("Write-Host 'Querying case hold rules per case...'");
                    sb.AppendLine("$caseFail = 0; $ruleFail = 0");
                    sb.AppendLine("foreach ($cs in $cases) {");
                    sb.AppendLine("    $cid = [string]$cs.Identity; if (-not $cid) { $cid = [string]$cs.Name }; $cn = [string]$cs.Name");
                    sb.AppendLine("    try { $pols2 = @(Get-CaseHoldPolicy -Case $cid -ErrorAction Stop) } catch { $caseFail++; continue }");
                    sb.AppendLine("    foreach ($po in $pols2) {");
                    sb.AppendLine("        $plid = [string]$po.Identity; if (-not $plid) { $plid = [string]$po.Name }");
                    sb.AppendLine("        try { $rows += @(Get-CaseHoldRule -Policy $plid -ErrorAction Stop | Select-Object " + selectList + " | ForEach-Object { $_ | Add-Member -NotePropertyName 'CaseName' -NotePropertyValue $cn -Force -PassThru }) } catch { $ruleFail++ }");
                    sb.AppendLine("    }");
                    sb.AppendLine("}");
                    sb.AppendLine("if ($caseFail -gt 0) { Write-Host (\"WARNING: {0} case(s) without readable hold policies.\" -f $caseFail) }");
                    sb.AppendLine("if ($ruleFail -gt 0) { Write-Host (\"WARNING: {0} policie(s) without readable hold rules.\" -f $ruleFail) }");
                }
                else
                {
                    sb.AppendLine("Write-Host 'Querying case hold policies per case...'");
                    sb.AppendLine("$caseFail = 0");
                    sb.AppendLine("foreach ($cs in $cases) {");
                    sb.AppendLine("    $cid = [string]$cs.Identity; if (-not $cid) { $cid = [string]$cs.Name }; $cn = [string]$cs.Name");
                    sb.AppendLine("    try { $rows += @(Get-CaseHoldPolicy -Case $cid -ErrorAction Stop | Select-Object " + selectList + " | ForEach-Object { $_ | Add-Member -NotePropertyName 'CaseName' -NotePropertyValue $cn -Force -PassThru }) } catch { $caseFail++ }");
                    sb.AppendLine("}");
                    sb.AppendLine("if ($caseFail -gt 0) { Write-Host (\"WARNING: {0} case(s) without readable hold policies.\" -f $caseFail) }");
                }
                sb.AppendLine("if ($rows.Count -eq 0) { Write-Host 'No rows exported - no eDiscovery cases (or no holds) in this tenant.' }");
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
