using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Intune" product tab (Microsoft Graph, NOT Exchange Online):
    //   intune-devices -> GET /devices (Entra device identities, one row per
    //     device: identity, platform, join/trust derivation, compliance state
    //     plus optional slow per-device /registeredOwners lookup for Owners +
    //     OwnerType). JoinType is derived from trustType: AzureAd = Entra
    //     joined, Workplace = Entra registered, ServerAd = Hybrid Entra
    //     joined. This is the device-identity inventory, separate from the
    //     Exchange mobile-device partnerships (mobile-devices section) and
    //     from Intune managedDevices (a future section needing
    //     DeviceManagementManagedDevices.Read.All). Needs Device.Read.All.
    // All emitted cells are pre-joined scalars, so Select-Object takes plain
    // property names and the ';' CSV never clashes (multi-values are ','-joined).
    internal static class SectionsIntune
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildDevicesSection());
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
            return "$size = '" + size + "'\n$maxDevices = -1\nif ($size -eq '100') { $maxDevices = 100 } elseif ($size -eq '1000') { $maxDevices = 1000 }";
        }

        // ============================================================ 1. DEVICES
        private static AuditSection BuildDevicesSection()
        {
            var section = new AuditSection(
                "intune-devices",
                "Devices",
                "Intune devices export",
                "Audit Entra device identities via Graph: join type (Entra joined / registered / hybrid), trust type, compliance state and owner (slow per-device lookup). Identity inventory - separate from Exchange mobile-device partnerships.",
                "device",
                AuditScope.Graph);
            section.Category = "Intune";
            section.Product = "Intune";
            section.DefaultFileName = "IntuneDevices.csv";

            var identity = new AuditOptionGroup("identity", "Identity", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("Id", true);
            identity.AddProp("DisplayName", true);
            identity.AddProp("DeviceId", true);
            identity.AddProp("AccountEnabled", true);
            section.AddGroup(identity);

            var platform = new AuditOptionGroup("platform", "Platform", GroupMode.MultiCheck); platform.Columns = 2;
            platform.AddProp("OperatingSystem", true);
            platform.AddProp("OperatingSystemVersion", true);
            platform.AddProp("Manufacturer", true);
            platform.AddProp("Model", true);
            platform.AddProp("ProfileType", true);
            platform.AddProp("DeviceOwnership", true);
            platform.AddProp("DeviceCategory", true);
            platform.AddProp("EnrollmentProfileName", false);
            section.AddGroup(platform);

            var join = new AuditOptionGroup("join", "Join & trust", GroupMode.MultiCheck); join.Columns = 2;
            join.Hint = "JoinType is derived from trustType (AzureAd = Entra joined, Workplace = Entra registered, ServerAd = Hybrid Entra joined).";
            join.AddProp("JoinType", true);
            join.AddProp("TrustType", true);
            join.AddProp("OnPremisesSyncEnabled", true);
            join.AddProp("OnPremisesLastSyncDateTime", true);
            join.AddProp("RegistrationDateTime", true);
            section.AddGroup(join);

            var compliance = new AuditOptionGroup("compliance", "Compliance state", GroupMode.MultiCheck); compliance.Columns = 2;
            compliance.AddProp("IsCompliant", true);
            compliance.AddProp("IsManaged", true);
            compliance.AddProp("ManagementType", true);
            compliance.AddProp("EnrollmentType", true);
            compliance.AddProp("ApproximateLastSignInDateTime", true);
            compliance.AddProp("IsRooted", false);
            section.AddGroup(compliance);

            var owner = new AuditOptionGroup("owner", "Owner (slow per-device lookup)", GroupMode.MultiCheck); owner.Columns = 1;
            owner.Hint = "One registeredOwners query per device - slower on large tenants. Needs the Device.Read.All consent.";
            owner.Add(AuditOption.Prop("Owners", true).MarkSlow());
            owner.Add(AuditOption.Prop("OwnerType", true).MarkSlow());
            section.AddGroup(owner);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "platform", "join", "compliance", "owner");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantOwners = chosen.Contains("Owners") || chosen.Contains("OwnerType");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Entra device identities (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$select = 'id,displayName,deviceId,accountEnabled,operatingSystem,operatingSystemVersion,manufacturer,model,profileType,deviceOwnership,deviceCategory,trustType,onPremisesSyncEnabled,onPremisesLastSyncDateTime,registrationDateTime,approximateLastSignInDateTime,isCompliant,isManaged,isRooted,managementType,enrollmentType,enrollmentProfileName'");
                sb.AppendLine("$devices = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/devices?$select=' + $select + '&$top=999'");
                sb.AppendLine("while ($uri -and ($maxDevices -lt 0 -or $devices.Count -lt $maxDevices)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $devices += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxDevices -ge 0 -and $devices.Count -gt $maxDevices) { $devices = $devices[0..($maxDevices - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} device(s).\" -f $devices.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantOwners) sb.AppendLine("$ownFail = 0");
                sb.AppendLine("foreach ($d in $devices) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $devices.Count) }");
                sb.AppendLine("    $did = [string]$d.id");
                sb.AppendLine("    $tt = [string]$d.trustType");
                sb.AppendLine("    $jt = $tt");
                sb.AppendLine("    if ($tt -eq 'AzureAd') { $jt = 'Entra joined' }");
                sb.AppendLine("    elseif ($tt -eq 'Workplace') { $jt = 'Entra registered' }");
                sb.AppendLine("    elseif ($tt -eq 'ServerAd') { $jt = 'Hybrid Entra joined' }");
                if (wantOwners)
                {
                    sb.AppendLine("    $ow = ''; $ot = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $ol = @(); $ouri = \"https://graph.microsoft.com/v1.0/devices/\" + $did + \"/registeredOwners?`$select=id,displayName,userPrincipalName\"");
                    sb.AppendLine("        while ($ouri) { $owr = Invoke-RestMethod -Uri $ouri -Headers $headers -Method Get -ErrorAction Stop; $ol += @($owr.value); $ouri = $owr.'@odata.nextLink' }");
                    sb.AppendLine("        $ow = ((@($ol | ForEach-Object { $s = [string]$_.userPrincipalName; if (-not $s) { $s = [string]$_.displayName }; if (-not $s) { $s = [string]$_.id }; $s } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                    sb.AppendLine("        $ot = ((@($ol | ForEach-Object { $t = [string]$_.'@odata.type'; if ($t -match 'user') { 'User' } elseif ($t -match 'group') { 'Group' } elseif ($t -ne '') { $t } else { 'Other' } } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                    sb.AppendLine("    } catch { $ownFail++ }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        Id = $did; DisplayName = $d.displayName; DeviceId = $d.deviceId; AccountEnabled = $d.accountEnabled;");
                sb.AppendLine("        OperatingSystem = $d.operatingSystem; OperatingSystemVersion = $d.operatingSystemVersion; Manufacturer = $d.manufacturer; Model = $d.model;");
                sb.AppendLine("        ProfileType = $d.profileType; DeviceOwnership = $d.deviceOwnership; DeviceCategory = $d.deviceCategory; EnrollmentProfileName = $d.enrollmentProfileName;");
                sb.AppendLine("        JoinType = $jt; TrustType = $tt; OnPremisesSyncEnabled = $d.onPremisesSyncEnabled; OnPremisesLastSyncDateTime = $d.onPremisesLastSyncDateTime; RegistrationDateTime = $d.registrationDateTime;");
                sb.AppendLine("        IsCompliant = $d.isCompliant; IsManaged = $d.isManaged; ManagementType = $d.managementType; EnrollmentType = $d.enrollmentType;");
                sb.AppendLine("        ApproximateLastSignInDateTime = $d.approximateLastSignInDateTime; IsRooted = $d.isRooted;");
                sb.AppendLine("        Owners = " + (chosen.Contains("Owners") ? "$ow" : "''") + "; OwnerType = " + (chosen.Contains("OwnerType") ? "$ot" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantOwners) sb.AppendLine("if ($ownFail -gt 0) { Write-Host (\"WARNING: {0} owner querie(s) failed (consent for Device.Read.All?).\" -f $ownFail) }");
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
