using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Bookings" sub-category of the Exchange Online product tab (Microsoft
    // Graph, NOT Exchange Online cmdlets - Bookings mailboxes live in EXO
    // but the API is Graph):
    //   bookings-businesses -> GET /solutions/bookingBusinesses (list gives
    //     id+displayName only, max 500, no pagination) + GET per business
    //     (email, hours, scheduling policy) + optional slow per-business
    //     counts (services, staff, appointments, customers). Empty when
    //     Bookings is unused. Needs Bookings.Read.All.
    // All emitted cells are pre-joined scalars, so Select-Object takes plain
    // property names and the ';' CSV never clashes (multi-values are ','-joined).
    internal static class SectionsBookings
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildBusinessesSection());
        }

        private static List<string> Collect(AuditSelection sel, params string[] groupKeys)
        {
            return PsScriptHelpers.Collect(sel, groupKeys);
        }

        private const string GraphHeaders =
            "$headers = @{ Authorization = ('Bearer ' + $env:MAT_GRAPH_TOKEN); ConsistencyLevel = 'eventual' }";

        private static AuditSection BuildBusinessesSection()
        {
            var section = new AuditSection(
                "bookings-businesses",
                "Booking calendars",
                "Booking calendars export",
                "Audit Microsoft Bookings businesses via Graph: schedule, hours and policy per calendar plus service/staff/appointment counts (slow lookups). Empty when Bookings is unused.",
                "calendar",
                AuditScope.Graph);
            section.Category = "Bookings";
            section.Product = "Exchange Online";
            section.DefaultFileName = "BookingsBusinesses.csv";

            var business = new AuditOptionGroup("business", "Business", GroupMode.MultiCheck); business.Columns = 2;
            business.AddProp("DisplayName", true);
            business.AddProp("Email", true);
            business.AddProp("LanguageTag", true);
            business.AddProp("IsPublished", true);
            section.AddGroup(business);

            var schedule = new AuditOptionGroup("schedule", "Schedule & hours", GroupMode.MultiCheck); schedule.Columns = 1;
            schedule.AddProp("BusinessHours", true);
            schedule.AddProp("TimeSlotInterval", true);
            schedule.AddProp("MinimumLeadTimeMin", true);
            schedule.AddProp("MaximumAdvanceMin", true);
            section.AddGroup(schedule);

            var counts = new AuditOptionGroup("counts", "Contents (slow per-business lookup)", GroupMode.MultiCheck); counts.Columns = 2;
            counts.Hint = "Counts via one lightweight query per collection and business - slower on tenants with many calendars. Needs the Bookings.Read.All consent.";
            counts.Add(AuditOption.Prop("ServicesCount", true).MarkSlow());
            counts.Add(AuditOption.Prop("StaffCount", true).MarkSlow());
            counts.Add(AuditOption.Prop("AppointmentsCount", false).MarkSlow());
            counts.Add(AuditOption.Prop("CustomersCount", false).MarkSlow());
            section.AddGroup(counts);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "business", "schedule", "counts");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                bool wantCounts = chosen.Contains("ServicesCount") || chosen.Contains("StaffCount") || chosen.Contains("AppointmentsCount") || chosen.Contains("CustomersCount");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying booking businesses (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$biz = @()");
                sb.AppendLine("try { $br = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/solutions/bookingBusinesses' -Headers $headers -Method Get -ErrorAction Stop; $biz = @($br.value) } catch { Write-Host ('WARNING: bookingBusinesses query failed (' + $_.Exception.Message + ' - consent for Bookings.Read.All?)'); $biz = @() }");
                sb.AppendLine("Write-Host (\"Retrieved {0} booking business(es).\" -f $biz.Count)");
                sb.AppendLine("if ($biz.Count -eq 0) { Write-Host 'No booking businesses found - Bookings not in use, or consent is missing.' }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantCounts) sb.AppendLine("$cntFail = 0");
                sb.AppendLine("foreach ($b in $biz) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $biz.Count) }");
                sb.AppendLine("    $bid = [string]$b.id; $bnm = [string]$b.displayName");
                sb.AppendLine("    $det = $null");
                sb.AppendLine("    try { $det = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/solutions/bookingBusinesses/\" + $bid) -Headers $headers -Method Get -ErrorAction Stop } catch { Write-Host (\"  WARNING: business '{0}' detail failed: \" -f $bnm + $_.Exception.Message) }");
                sb.AppendLine("    if (-not $det) { continue }");
                sb.AppendLine("    $bh = ((@($det.businessHours) | ForEach-Object { $d = [string]$_.day; $ts = ''; try { $ts = ((@($_.timeSlots) | ForEach-Object { ([string]$_.startTime) + '-' + ([string]$_.endTime) }) -join ',') } catch { }; if ($d) { $d + ' ' + $ts } else { '' } } | Where-Object { $_ -ne '' }) -join '; ')");
                sb.AppendLine("    $tsi = ''; $min = ''; $max = ''; try { $tsi = [string]$det.schedulingPolicy.timeSlotInterval } catch { }; try { $min = [string]$det.schedulingPolicy.minimumLeadTimeInMinutes } catch { }; try { $max = [string]$det.schedulingPolicy.maximumAdvanceInMinutes } catch { }");
                sb.AppendLine("    $em = ''; try { $em = [string]$det.email } catch { }; $lt = ''; try { $lt = [string]$det.languageTag } catch { }; $pub = ''; try { $pub = [string]$det.isPublished } catch { }");
                if (wantCounts)
                {
                    sb.AppendLine("    $sc = ''; $stc = ''; $ac = ''; $cc = ''");
                    sb.AppendLine("    try { $q = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/solutions/bookingBusinesses/\" + $bid + \"/services/`$count\") -Headers $headers -Method Get -ErrorAction Stop; $sc = [string]$q } catch { $cntFail++ }");
                    sb.AppendLine("    try { $q = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/solutions/bookingBusinesses/\" + $bid + \"/staffMembers/`$count\") -Headers $headers -Method Get -ErrorAction Stop; $stc = [string]$q } catch { $cntFail++ }");
                    sb.AppendLine("    try { $q = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/solutions/bookingBusinesses/\" + $bid + \"/appointments/`$count\") -Headers $headers -Method Get -ErrorAction Stop; $ac = [string]$q } catch { $cntFail++ }");
                    sb.AppendLine("    try { $q = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/solutions/bookingBusinesses/\" + $bid + \"/customers/`$count\") -Headers $headers -Method Get -ErrorAction Stop; $cc = [string]$q } catch { $cntFail++ }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        DisplayName = $bnm; Email = $em; LanguageTag = $lt; IsPublished = $pub;");
                sb.AppendLine("        BusinessHours = $bh; TimeSlotInterval = $tsi; MinimumLeadTimeMin = $min; MaximumAdvanceMin = $max;");
                sb.AppendLine("        ServicesCount = " + (chosen.Contains("ServicesCount") ? "$sc" : "''") + "; StaffCount = " + (chosen.Contains("StaffCount") ? "$stc" : "''") + "; AppointmentsCount = " + (chosen.Contains("AppointmentsCount") ? "$ac" : "''") + "; CustomersCount = " + (chosen.Contains("CustomersCount") ? "$cc" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantCounts) sb.AppendLine("if ($cntFail -gt 0) { Write-Host (\"WARNING: {0} count querie(s) failed (consent for Bookings.Read.All?).\" -f $cntFail) }");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ DisplayName = ''; Email = ''; LanguageTag = ''; IsPublished = ''; BusinessHours = ''; TimeSlotInterval = ''; MinimumLeadTimeMin = ''; MaximumAdvanceMin = ''; ServicesCount = ''; StaffCount = ''; AppointmentsCount = ''; CustomersCount = '' }) }");
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
