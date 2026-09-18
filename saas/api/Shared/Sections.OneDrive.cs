using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "SharePoint/OneDrive" sub-category of the SharePoint product tab
    // (Microsoft Graph): OneDrive-specific remainder of
    // GET /admin/sharepoint/settings (personal-site storage default,
    // departed-user retention, sync-app restrictions). The shared
    // capability/allowed-domains surface lives in the SharePoint Sharing
    // Policy section; per-site OneDrive inventory is SPO-cmdlet-only
    // (Get-SPOSite -IncludePersonalSite, see sp-migration) since usage
    // reports identify orphaned drives by unresolvable IDs.
    // Needs SharePointTenantSettings.Read.All (+ SharePoint/Global Reader
    // role for the auditor).
    // All emitted cells are pre-joined scalars, so Select-Object takes plain
    // property names and the ';' CSV never clashes (multi-values are ','-joined).
    internal static class SectionsOneDrive
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildSharingSection());
        }

        private static List<string> Collect(AuditSelection sel, params string[] groupKeys)
        {
            return PsScriptHelpers.Collect(sel, groupKeys);
        }

        private const string GraphHeaders =
            "$headers = @{ Authorization = ('Bearer ' + $env:MAT_GRAPH_TOKEN); ConsistencyLevel = 'eventual' }";

        private static AuditSection BuildSharingSection()
        {
            var section = new AuditSection(
                "onedrive-sharing",
                "Sharing settings",
                "OneDrive sharing settings export",
                "Audit OneDrive-specific tenant sharing settings via Graph (one row). Shared capability and domain lists live in the SharePoint Sharing Policy section.",
                "share",
                AuditScope.Graph);
            section.Category = "OneDrive";
            section.Product = "SharePoint/OneDrive";
            section.DefaultFileName = "OneDriveSharing.csv";
            section.TipHtml = "Link defaults, expirations and attestation need the standalone script: <a href='https://github.com/jmaillot/m365-audit-tool/tree/main/scripts/sp-migration' target='_blank' rel='noopener'>sp-migration on GitHub</a>.";

            var odb = new AuditOptionGroup("odb", "OneDrive settings", GroupMode.MultiCheck); odb.Columns = 1;
            odb.Hint = "OneDrive-specific remainder of /admin/sharepoint/settings (needs SharePointTenantSettings.Read.All plus a SharePoint Administrator or Global Reader role). DeletedUserPersonalSiteRetentionDays = retention of departed users' OneDrives. Owner-invitation notifications and people-picker guest settings are SPO-cmdlet-only (see sp-migration).";
            odb.AddProp("PersonalSiteDefaultStorageLimitMB", true);
            odb.AddProp("DeletedUserPersonalSiteRetentionDays", true);
            odb.AddProp("SyncButtonHiddenOnPersonalSite", true);
            odb.AddProp("UnmanagedSyncAppRestricted", true);
            odb.AddProp("MacSyncAppEnabled", true);
            odb.AddProp("SyncAllowedDomainGuids", true);
            odb.AddProp("SyncExcludedFileExtensions", true);
            section.AddGroup(odb);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "odb");
                if (chosen.Count == 0) chosen.Add("PersonalSiteDefaultStorageLimitMB");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying OneDrive sharing settings (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$st = $null");
                sb.AppendLine("try { $st = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -Headers $headers -Method Get -ErrorAction Stop } catch { Write-Host ('WARNING: sharepoint settings query failed (' + $_.Exception.Message + ' - consent for SharePointTenantSettings.Read.All + a SharePoint/Global Reader role?)') }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("if ($st) {");
                sb.AppendLine("    $sd = ((@($st.allowedDomainGuidsForSyncApp) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("    $se = ((@($st.excludedFileExtensionsForSyncApp) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        PersonalSiteDefaultStorageLimitMB = $st.personalSiteDefaultStorageLimitInMB; DeletedUserPersonalSiteRetentionDays = $st.deletedUserPersonalSiteRetentionPeriodInDays;");
                sb.AppendLine("        SyncButtonHiddenOnPersonalSite = $st.isSyncButtonHiddenOnPersonalSite; UnmanagedSyncAppRestricted = $st.isUnmanagedSyncAppForTenantRestricted; MacSyncAppEnabled = $st.isMacSyncAppEnabled;");
                sb.AppendLine("        SyncAllowedDomainGuids = $sd; SyncExcludedFileExtensions = $se");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ PersonalSiteDefaultStorageLimitMB = ''; DeletedUserPersonalSiteRetentionDays = ''; SyncButtonHiddenOnPersonalSite = ''; UnmanagedSyncAppRestricted = ''; MacSyncAppEnabled = ''; SyncAllowedDomainGuids = ''; SyncExcludedFileExtensions = '' }) }");
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
