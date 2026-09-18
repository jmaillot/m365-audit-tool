using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "OneDrive" category (Microsoft Graph, NOT Exchange Online) - personal
    // sites only, separate from the SharePoint Site Collections sections
    // (which skip OneDrive sites):
    //   onedrive-sites   -> reports/getOneDriveUsageDetail (one row per
    //     user: owner, deleted flag, last activity, file counts, storage
    //     used/allocated) + optional slow per-user /users/{upn}/drive
    //     lookup (OneDrive URL - the report carries no site URL - plus live
    //     quota). Needs Reports.Read.All (+ User.Read.All for the live
    //     lookups, already required).
    //   onedrive-sharing -> GET /admin/sharepoint/settings, OneDrive-specific
    //     remainder only (personal-site storage default, deleted-user
    //     retention, sync-app restrictions). The shared capability/allowed-
    //     domains surface lives in the SharePoint Sharing Policy section;
    //     owner-invitation notifications and people-picker guest settings are
    //     SPO-cmdlet-only (see sp-migration/Get-SPOTenantSharing).
    //     Needs SharePointTenantSettings.Read.All (+ SharePoint/Global Reader
    //     role for the auditor).
    // All emitted cells are pre-joined scalars, so Select-Object takes plain
    // property names and the ';' CSV never clashes (multi-values are ','-joined).
    internal static class SectionsOneDrive
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildSitesSection());
            AuditRegistry.Register(BuildSharingSection());
        }

        private static List<string> Collect(AuditSelection sel, params string[] groupKeys)
        {
            return PsScriptHelpers.Collect(sel, groupKeys);
        }

        private const string GraphHeaders =
            "$headers = @{ Authorization = ('Bearer ' + $env:MAT_GRAPH_TOKEN); ConsistencyLevel = 'eventual' }";

        private static string SizePrelude(string size)
        {
            // NOTE: plain concatenation, NOT string.Format: the PowerShell body
            // contains literal { } blocks that string.Format would try to parse.
            return "$size = '" + size + "'\n$maxDrives = -1\nif ($size -eq '100') { $maxDrives = 100 } elseif ($size -eq '1000') { $maxDrives = 1000 }";
        }

        // Column-name-tolerant accessor: report headers sometimes arrive with
        // BOM/whitespace/case variations - direct lookups would silently miss.
        private const string ColHelper =
            "function Get-Col($o, $name) {\n" +
            "    foreach ($p in @($o.PSObject.Properties)) { if ([string]$p.Name -eq $name) { return ([string]$p.Value).Trim() } }\n" +
            "    foreach ($p in @($o.PSObject.Properties)) { if (([string]$p.Name).Trim().Trim([char]0xFEFF).ToLower() -eq ([string]$name).ToLower()) { return ([string]$p.Value).Trim() } }\n" +
            "    return ''\n" +
            "}\n";

        private const string FetchUsageReport =
            "$repRows = @()\n" +
            "try {\n" +
            "    $repRaw = Invoke-WebRequest -Uri \"https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='D30')\" -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop\n" +
            "    $repTmp = [System.IO.Path]::GetTempFileName()\n" +
            "    if ($repRaw.Content -is [string] -and ([string]$repRaw.Content).Length -gt 0) {\n" +
            "        [System.IO.File]::WriteAllText($repTmp, [string]$repRaw.Content)\n" +
            "    } else {\n" +
            "        $rs = $repRaw.RawContentStream\n" +
            "        $rs.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null\n" +
            "        $fs = [System.IO.File]::Create($repTmp)\n" +
            "        try { $rs.CopyTo($fs) } finally { $fs.Dispose() }\n" +
            "    }\n" +
            "    $repRows = @(Import-Csv -LiteralPath $repTmp)\n" +
            "    Remove-Item -LiteralPath $repTmp -Force -ErrorAction SilentlyContinue\n" +
            "    Write-Host (\"Loaded OneDrive usage report ({0} rows, up to 48h stale).\" -f $repRows.Count)\n" +
            "} catch { Write-Host (\"WARNING: OneDrive usage report failed (consent for Reports.Read.All?) - no drives to process: \" + $_.Exception.Message) }\n";

        // ============================================================ 1. SITES
        private static AuditSection BuildSitesSection()
        {
            var section = new AuditSection(
                "onedrive-sites",
                "OneDrive sites",
                "OneDrive sites export",
                "Audit personal OneDrive sites via Graph: owner, storage and activity from the usage report plus live OneDrive URL and quota (slow per-user lookup).",
                "drive",
                AuditScope.Graph);
            section.Category = "OneDrive";
            section.Product = "OneDrive";
            section.DefaultFileName = "OneDriveSites.csv";
            section.TipHtml = "Owner IDs that resolve to nothing (0/17 with 404s) are orphaned sites of long-deleted users - Graph cannot name them. List them with real URLs/owners from an admin workstation: <b>Get-SPOSite -IncludePersonalSite $true -Limit All | Select Url, Owner, StorageUsageCurrent, Status</b>.";

            var report = new AuditOptionGroup("report", "Usage report (D30)", GroupMode.MultiCheck); report.Columns = 2;
            report.Hint = "Stale up to 48h. The report carries no site URL - LiveUrl fills that gap.";
            report.AddProp("OwnerUPN", true);
            report.AddProp("OwnerName", true);
            report.AddProp("IsDeleted", true);
            report.AddProp("DeletedDate", true);
            report.AddProp("LastActivityDate", true);
            report.AddProp("FileCount", true);
            report.AddProp("ActiveFileCount", true);
            report.AddProp("StorageUsedMB", true);
            report.AddProp("StorageAllocatedMB", true);
            section.AddGroup(report);

            var live = new AuditOptionGroup("live", "Live drive (slow per-user lookup)", GroupMode.MultiCheck); live.Columns = 2;
            live.Hint = "One /drive query per user (needs User.Read.All, already required). Empty for deleted OneDrives.";
            live.Add(AuditOption.Prop("LiveUrl", true).MarkSlow());
            live.Add(AuditOption.Prop("QuotaTotalMB", true).MarkSlow());
            live.Add(AuditOption.Prop("QuotaUsedMB", true).MarkSlow());
            live.Add(AuditOption.Prop("QuotaRemainingMB", true).MarkSlow());
            section.AddGroup(live);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "report", "live");
                if (chosen.Count == 0) chosen.Add("OwnerUPN");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantLive = chosen.Contains("LiveUrl") || chosen.Contains("QuotaTotalMB") || chosen.Contains("QuotaUsedMB") || chosen.Contains("QuotaRemainingMB");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying OneDrive usage report (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine(ColHelper);
                sb.AppendLine(FetchUsageReport);
                sb.AppendLine("if ($maxDrives -ge 0 -and $repRows.Count -gt $maxDrives) { $repRows = $repRows[0..($maxDrives - 1)] }");
                sb.AppendLine("$siteMap = @{}");
                sb.AppendLine("try {");
                sb.AppendLine("    $sbq = @{ requests = @(@{ entityTypes = @('site'); query = @{ queryString = 'contentclass:STS_Site' }; fields = @('webUrl', 'displayName', 'createdBy'); size = 500 }) } | ConvertTo-Json -Depth 6");
                sb.AppendLine("    $sr = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/search/query' -Headers $headers -Method Post -Body $sbq -ContentType 'application/json' -ErrorAction Stop");
                sb.AppendLine("    foreach ($h in @($sr.value[0].hitsContainers[0].hits)) {");
                sb.AppendLine("        $rid = ''; try { $rid = ([string]$h.resource.id).ToLower() } catch { }");
                sb.AppendLine("        if ($rid) { $u2 = ''; $n2 = ''; $wu = ''; try { $u2 = [string]$h.resource.createdBy.user.email } catch { }; try { if (-not $u2) { $u2 = [string]$h.resource.createdBy.user.displayName } } catch { }; try { $n2 = [string]$h.resource.createdBy.user.displayName } catch { }; try { $wu = [string]$h.resource.webUrl } catch { }; if (-not $wu) { try { $wu = [string]$h.hitId } catch { } }; $siteMap[$rid] = @{ Url = $wu; Upn = $u2; Name = $n2 } }");
                sb.AppendLine("    }");
                sb.AppendLine("    Write-Host (\"Indexed {0} site(s) for owner resolution.\" -f $siteMap.Count)");
                sb.AppendLine("} catch { Write-Host ('WARNING: site search failed (' + $_.Exception.Message + ') - opaque owner IDs stay unresolved.') }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                sb.AppendLine("$drvFail = 0; $resOk = 0; $firstErr = ''");
                sb.AppendLine("foreach ($rr in $repRows) {");
                sb.AppendLine("    $i++; if (($i % 50) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $repRows.Count) }");
                sb.AppendLine("    $upn = Get-Col $rr 'Owner Principal Name'; $onm = Get-Col $rr 'Owner Display Name'");
                sb.AppendLine("    $siteUrlDone = $false");
                sb.AppendLine("    if ($upn -and ($upn -notlike '*@*')) {");
                sb.AppendLine("        $lk0 = $upn; if ($lk0 -match '^[0-9a-fA-F]{32}$') { $lk0 = $lk0.Substring(0,8) + '-' + $lk0.Substring(8,4) + '-' + $lk0.Substring(12,4) + '-' + $lk0.Substring(16,4) + '-' + $lk0.Substring(20) }");
                sb.AppendLine("        if ($siteMap.ContainsKey($lk0.ToLower())) { $sm = $siteMap[$lk0.ToLower()]; if ($sm.Upn) { $upn = [string]$sm.Upn }; if ($sm.Name) { $onm = [string]$sm.Name }; if ($sm.Url) { $lurl = [string]$sm.Url; $siteUrlDone = $true } }");
                sb.AppendLine("    }");                sb.AppendLine("    if ($upn -and ($upn -notlike '*@*')) {");
                sb.AppendLine("        try {");
                sb.AppendLine("            $lk = $upn; if ($lk -match '^[0-9a-fA-F]{32}$') { $lk = $lk.Substring(0,8) + '-' + $lk.Substring(8,4) + '-' + $lk.Substring(12,4) + '-' + $lk.Substring(16,4) + '-' + $lk.Substring(20) }");
                sb.AppendLine("            $ru = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $lk + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("            $t1 = [string]$ru.userPrincipalName; if ($t1) { $upn = $t1 }");
                sb.AppendLine("            $t2 = [string]$ru.displayName; if ($t2) { $onm = $t2 }");
                sb.AppendLine("        } catch {");
                sb.AppendLine("            try {");
                sb.AppendLine("                $do = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/directoryObjects/\" + $lk) -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("                if ([string]$do.'@odata.type' -match 'group') { $go = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $lk + \"?`$select=displayName,mail\") -Headers $headers -Method Get -ErrorAction Stop; if ([string]$go.displayName) { $onm = [string]$go.displayName }; if ([string]$go.mail) { $upn = [string]$go.mail } }");
                sb.AppendLine("                else { throw 'not-a-group' }");
                sb.AppendLine("            } catch {");
                sb.AppendLine("                try {");
                sb.AppendLine("                    $del = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/directory/deletedItems/\" + $lk) -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("                    $du = [string]$del.userPrincipalName; if ($du) { $upn = $du }");
                sb.AppendLine("                    $dd = [string]$del.displayName; if ($dd) { $onm = $dd + ' (deleted)' }");
                sb.AppendLine("                    if (-not $du -and -not $dd) { throw 'no-deleted' }");
                sb.AppendLine("                } catch {");
                sb.AppendLine("                    try {");
                sb.AppendLine("                        $st2 = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/sites/\" + $lk + \"?`$select=id,displayName,webUrl,createdBy\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("                        $su2 = [string]$st2.webUrl; if ($su2) { $lurl = $su2; $siteUrlDone = $true }");
                sb.AppendLine("                        $cu = ''; try { $cu = [string]$st2.createdBy.user.email } catch { }; if (-not $cu) { try { $cu = [string]$st2.createdBy.user.displayName } catch { } }");
                sb.AppendLine("                        if ($cu) { $upn = $cu; if (-not $onm -or ($onm -notlike '*@*')) { try { $cd = [string]$st2.createdBy.user.displayName; if ($cd) { $onm = $cd } } catch { } } }");
                sb.AppendLine("                        else { $drvFail++ }");
                sb.AppendLine("                    } catch { if (-not $firstErr) { $firstErr = $_.Exception.Message }; $drvFail++ }");
                sb.AppendLine("                }");
                sb.AppendLine("            }");
                sb.AppendLine("        }");
                sb.AppendLine("    }");
                sb.AppendLine("    $su = 0; try { $sb2 = Get-Col $rr 'Storage Used (Byte)'; if ($sb2) { $su = [math]::Round(([double]$sb2) / 1MB, 2) } } catch { }");
                sb.AppendLine("    $sa = 0; try { $ab2 = Get-Col $rr 'Storage Allocated (Byte)'; if ($ab2) { $sa = [math]::Round(([double]$ab2) / 1MB, 2) } } catch { }");
                if (wantLive)
                {
                    sb.AppendLine("    $qt = ''; $qu = ''; $qr = ''");
                    sb.AppendLine("    if (-not $siteUrlDone) { $lurl = '' }");
                    sb.AppendLine("    if ($upn -and ($upn -like '*@*') -and (-not $siteUrlDone)) {");
                    sb.AppendLine("        try {");
                    sb.AppendLine("            $dv = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $upn + \"/drive?$select=id,name,webUrl,quota\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("            $lurl = [string]$dv.webUrl");
                    sb.AppendLine("            try { $t = $dv.quota.total; if ($t) { $qt = [math]::Round(([double]$t) / 1MB, 2) } } catch { }");
                    sb.AppendLine("            try { $u2 = $dv.quota.used; if ($u2) { $qu = [math]::Round(([double]$u2) / 1MB, 2) } } catch { }");
                    sb.AppendLine("            try { $r2 = $dv.quota.remaining; if ($r2) { $qr = [math]::Round(([double]$r2) / 1MB, 2) } } catch { }");
                    sb.AppendLine("        } catch { $drvFail++ }");
                    sb.AppendLine("    }");
                }
                sb.AppendLine("    if ($upn -like '*@*') { $resOk++ }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        OwnerUPN = $upn; OwnerName = $onm; IsDeleted = (Get-Col $rr 'Is Deleted'); DeletedDate = (Get-Col $rr 'Deleted Date');");
                sb.AppendLine("        LastActivityDate = (Get-Col $rr 'Last Activity Date'); FileCount = (Get-Col $rr 'File Count'); ActiveFileCount = (Get-Col $rr 'Active File Count');");
                sb.AppendLine("        StorageUsedMB = $su; StorageAllocatedMB = $sa;");
                sb.AppendLine("        LiveUrl = " + (chosen.Contains("LiveUrl") ? "$lurl" : "''") + "; QuotaTotalMB = " + (chosen.Contains("QuotaTotalMB") ? "$qt" : "''") + "; QuotaUsedMB = " + (chosen.Contains("QuotaUsedMB") ? "$qu" : "''") + "; QuotaRemainingMB = " + (chosen.Contains("QuotaRemainingMB") ? "$qr" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("Write-Host (\"Owner names resolved for {0}/{1} row(s).\" -f $resOk, $repRows.Count)");
                sb.AppendLine("if ($firstErr) { Write-Host (\"First lookup error detail: \" + $firstErr) }");
                if (wantLive) sb.AppendLine("if ($drvFail -gt 0) { Write-Host (\"WARNING: {0} user/drive querie(s) failed (deleted OneDrives, opaque owner IDs, or consent for User.Read.All?).\" -f $drvFail) }");
                else sb.AppendLine("if ($drvFail -gt 0) { Write-Host (\"WARNING: {0} owner-name querie(s) failed (consent for User.Read.All?).\" -f $drvFail) }");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ OwnerUPN = ''; OwnerName = ''; IsDeleted = ''; DeletedDate = ''; LastActivityDate = ''; FileCount = ''; ActiveFileCount = ''; StorageUsedMB = ''; StorageAllocatedMB = ''; LiveUrl = ''; QuotaTotalMB = ''; QuotaUsedMB = ''; QuotaRemainingMB = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 2. SHARING
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
            section.Product = "OneDrive";
            section.DefaultFileName = "OneDriveSharing.csv";
            section.TipHtml = "Link defaults, expirations and attestation need the standalone script: <a href='https://github.com/jmaillot/m365-audit-tool-saas/tree/main/sp-migration' target='_blank' rel='noopener'>sp-migration on GitHub</a>.";

            var odb = new AuditOptionGroup("odb", "OneDrive settings", GroupMode.MultiCheck); odb.Columns = 1;
            odb.Hint = "OneDrive-specific remainder of /admin/sharepoint/settings (needs SharePointTenantSettings.Read.All plus a SharePoint Administrator or Global Reader role). DeletedUserPersonalSiteRetentionDays = retention of departed users' OneDrives. Owner-invitation notifications and people-picker guest settings are SPO-cmdlet-only (see sp-migration).";
            odb.AddProp("PersonalSiteDefaultStorageLimitMB", true);
            odb.AddProp("DeletedUserPersonalSiteRetentionDays", true);
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
                if (chosen.Count == 0) chosen.Add("OneDriveForGuestsEnabled");
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
