using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Governance" sub-category of the Purview product tab (Security &
    // Compliance PowerShell via Connect-IPPSSession, except purview-auditlog
    // which is a plain EXO cmdlet):
    //   purview-retention -> Get-ComplianceTag (MIP retention labels, also
    //     covering SharePoint/OneDrive/Teams - distinct from EXO retention
    //     policies) + Get-RetentionCompliancePolicy/Rule (Purview retention
    //     policies and rules with workload locations).
    //   purview-governance -> best-effort guarded trio (cmdlet names vary by
    //     module version - every object warns instead of dying):
    //     Get-InformationBarrierPolicy (+ segments), SupervisoryReview
    //     (communication compliance) and InsiderRisk policies. Empty when
    //     the feature is unused OR the cmdlet is absent here (the warning
    //     tells which).
    //   purview-auditlog  -> Get-AdminAuditLogConfig (Unified Audit Log
    //     ingestion switch, EXO scope). Fine-grained audit retention is
    //     portal-only (see README section 7).
    internal static class SectionsPurviewGovernance
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildRetentionSection());
            AuditRegistry.Register(BuildGovernanceSection());
            AuditRegistry.Register(BuildAuditLogSection());
        }

        private static readonly List<string> MultiValued = new List<string>(new string[]
        {
            "Labels", "ExchangeLocation", "SharePointLocation", "OneDriveLocation",
            "TeamsLocation", "TeamsChannelLocation", "TeamsChatLocation",
            "ModernGroupLocation", "SegmentsAllowed", "SegmentsBlocked"
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

        // ============================================================ 1. RETENTION
        private static AuditSection BuildRetentionSection()
        {
            var section = new AuditSection(
                "purview-retention",
                "Retention labels",
                "Retention label export",
                "Audit Purview retention labels, policies and rules via Security & Compliance PowerShell (one object per run). Labels apply to SharePoint/OneDrive/Teams too - distinct from Exchange retention policies.",
                "stamp",
                AuditScope.ExchangeOnline);
            section.Category = "Governance";
            section.Product = "Purview";
            section.DefaultFileName = "PurviewRetention.csv";

            var obj = new AuditOptionGroup("object", "Object", GroupMode.SingleChoice); obj.Columns = 1;
            obj.Add(new AuditOption("labels", "Retention labels (Get-ComplianceTag)", "labels", true));
            obj.Add(new AuditOption("retpolicies", "Retention policies (Get-RetentionCompliancePolicy)", "retpolicies", false));
            obj.Add(new AuditOption("retrules", "Retention rules (Get-RetentionComplianceRule)", "retrules", false));
            section.AddGroup(obj);

            var label = new AuditOptionGroup("label", "Label properties", GroupMode.MultiCheck); label.Columns = 2;
            label.AddProp("Name", true);
            label.AddProp("Comment", true);
            label.AddProp("RetentionAction", true);
            label.AddProp("RetentionDuration", true);
            label.AddProp("IsRecordLabel", false);
            section.AddGroup(label);

            var policy = new AuditOptionGroup("retpolicy", "Policy properties", GroupMode.MultiCheck); policy.Columns = 2;
            policy.Hint = "Workload locations show where the policy applies (Exchange, SharePoint, OneDrive, Teams...).";
            policy.AddProp("Name", true);
            policy.AddProp("Enabled", true);
            policy.AddProp("Comment", false);
            policy.AddProp("ExchangeLocation", true);
            policy.AddProp("SharePointLocation", true);
            policy.AddProp("OneDriveLocation", true);
            policy.AddProp("TeamsChannelLocation", false);
            policy.AddProp("TeamsChatLocation", false);
            policy.AddProp("ModernGroupLocation", false);
            section.AddGroup(policy);

            var rule = new AuditOptionGroup("retrule", "Rule properties", GroupMode.MultiCheck); rule.Columns = 2;
            rule.Hint = "Rules bind policies to content; the linked policy column is added automatically.";
            rule.AddProp("Name", true);
            rule.AddProp("Policy", true);
            rule.AddProp("Disabled", true);
            rule.AddProp("Comment", false);
            section.AddGroup(rule);

            section.ViewDefaults["labels"] = new List<string>
            {
                "label::Name", "label::Comment", "label::RetentionAction", "label::RetentionDuration"
            };
            section.ViewDefaults["retpolicies"] = new List<string>
            {
                "retpolicy::Name", "retpolicy::Enabled", "retpolicy::ExchangeLocation",
                "retpolicy::SharePointLocation", "retpolicy::OneDriveLocation"
            };
            section.ViewDefaults["retrules"] = new List<string>
            {
                "retrule::Name", "retrule::Policy", "retrule::Disabled"
            };

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                string which = sel.First("object", "labels");
                string cmdlet;
                string propGroup;
                string label2;
                string ruleLink = null;
                if (which == "retpolicies") { cmdlet = "Get-RetentionCompliancePolicy"; propGroup = "retpolicy"; label2 = "retention policies"; }
                else if (which == "retrules") { cmdlet = "Get-RetentionComplianceRule"; propGroup = "retrule"; label2 = "retention rules"; ruleLink = "Policy"; }
                else { cmdlet = "Get-ComplianceTag"; propGroup = "label"; label2 = "retention labels"; }

                var chosen = Collect(sel, propGroup);
                if (ruleLink != null && !chosen.Contains(ruleLink)) chosen.Add(ruleLink);
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

        // ============================================================ 2. GOVERNANCE (best-effort)
        private static AuditSection BuildGovernanceSection()
        {
            var section = new AuditSection(
                "purview-governance",
                "Governance policies",
                "Governance policy export",
                "Audit information barriers, communication compliance and insider risk policies via Security & Compliance PowerShell (one object per run, best-effort: cmdlet names vary by module version).",
                "scale",
                AuditScope.ExchangeOnline);
            section.Category = "Governance";
            section.Product = "Purview";
            section.DefaultFileName = "PurviewGovernance.csv";
            section.TipHtml = "Empty output with a cmdlet warning means this module version lacks the cmdlet - check the Microsoft Purview portal for that workload.";

            var obj = new AuditOptionGroup("object", "Object", GroupMode.SingleChoice); obj.Columns = 1;
            obj.Add(new AuditOption("barriers", "Information barrier policies", "barriers", true));
            obj.Add(new AuditOption("supervision", "Communication compliance policies", "supervision", false));
            obj.Add(new AuditOption("insider", "Insider risk policies", "insider", false));
            section.AddGroup(obj);

            var common = new AuditOptionGroup("common", "Policy properties", GroupMode.MultiCheck); common.Columns = 2;
            common.Hint = "Best-effort columns: missing properties stay empty when the cmdlet shape differs.";
            common.AddProp("Name", true);
            common.AddProp("Enabled", true);
            common.AddProp("Comment", false);
            common.AddProp("SegmentsAllowed", false);
            common.AddProp("SegmentsBlocked", false);
            section.AddGroup(common);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                string which = sel.First("object", "barriers");
                string cmdlets;
                string label;
                if (which == "supervision") { cmdlets = "Get-SupervisoryReviewPolicyV2,Get-SupervisoryReviewPolicy"; label = "communication compliance policies"; }
                else if (which == "insider") { cmdlets = "Get-InsiderRiskPolicy"; label = "insider risk policies"; }
                else { cmdlets = "Get-InformationBarrierPolicy"; label = "information barrier policies"; }

                var chosen = Collect(sel, "common");
                if (chosen.Count == 0) chosen.Add("Name");
                string selectList = BuildSelectList(chosen);

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying " + label + "...'");
                sb.AppendLine("$cmdlets = @('" + cmdlets.Replace(",", "','") + "')");
                sb.AppendLine("$items = @(); $tried = @()");
                sb.AppendLine("foreach ($cm in $cmdlets) {");
                sb.AppendLine("    if ($null -eq (Get-Command $cm -ErrorAction SilentlyContinue)) { $tried += ($cm + ' (absent)'); continue }");
                sb.AppendLine("    try { $items += @(& $cm -ErrorAction Stop) } catch { Write-Host ('WARNING: ' + $cm + ' failed (' + $_.Exception.Message + ')') }");
                sb.AppendLine("}");
                sb.AppendLine("Write-Host (\"Retrieved {0} " + label + ".\" -f $items.Count)");
                sb.AppendLine("if ($items.Count -eq 0) { if ($tried.Count -gt 0) { Write-Host ('No " + label + " found - feature unused, or cmdlet(s) absent here: ' + ($tried -join ', ')) } else { Write-Host 'No " + label + " found - none configured in this tenant.' } }");
                sb.AppendLine("$rows = $items | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 3. AUDIT LOG SWITCH
        private static AuditSection BuildAuditLogSection()
        {
            var section = new AuditSection(
                "purview-auditlog",
                "Audit log",
                "Audit log state export",
                "Audit Unified Audit Log ingestion state via Exchange Online (one row). Fine-grained audit retention is portal-only.",
                "log",
                AuditScope.ExchangeOnline);
            section.Category = "Governance";
            section.Product = "Purview";
            section.DefaultFileName = "PurviewAuditLog.csv";
            section.TipHtml = "Audit retention policies (beyond on/off) live in the Purview portal: Solutions > Audit > Audit retention policies.";

            var state = new AuditOptionGroup("state", "Ingestion", GroupMode.MultiCheck); state.Columns = 1;
            state.Hint = "UnifiedAuditLogIngestionEnabled = No means no audit records at all - enable before migration for traceability.";
            state.AddProp("UnifiedAuditLogIngestionEnabled", true);
            section.AddGroup(state);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "state");
                if (chosen.Count == 0) chosen.Add("UnifiedAuditLogIngestionEnabled");
                string selectList = BuildSelectList(chosen);

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying audit log config (EXO)...'");
                sb.AppendLine("try { $cfg = Get-AdminAuditLogConfig -ErrorAction Stop; $rows = @($cfg | Select-Object " + selectList + "); Write-Host 'Retrieved audit log config.' } catch { Write-Host ('WARNING: Get-AdminAuditLogConfig failed (' + $_.Exception.Message + ')'); $rows = @([pscustomobject]@{ UnifiedAuditLogIngestionEnabled = '' }) }");
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }
    }
}
