using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Domains" product tab:
    //   domains-auth -> GET /domains (one row per domain: Managed vs
    //     Federated authentication type, verification, services) + optional
    //     slow per-domain /federationConfiguration lookup (IdP issuer and
    //     logon URLs - the ADFS/third-party reconfiguration scope). Federated
    //     domains are a very different migration path from managed ones.
    //     Needs Domain.Read.All (Graph).
    //   domains-dns  -> Get-AcceptedDomain (domain + domain type) +
    //     DNS-over-HTTPS per domain (MX, SPF TXT, DMARC TXT - Resolve-DnsName
    //     does not exist on Linux PowerShell, hence DoH) +
    //     Get-DkimSigningConfig (selectors + enabled state, then TXT probe
    //     per selector). Pure DNS + EXO cmdlets, no Graph token needed
    //     (runs on the EXO connection the worker opens anyway).
    // All emitted cells are pre-joined scalars, so Select-Object takes plain
    // property names and the ';' CSV never clashes (multi-values are ','-joined).
    internal static class SectionsDomains
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildAuthSection());
            AuditRegistry.Register(BuildDnsSection());
        }

        private static List<string> Collect(AuditSelection sel, params string[] groupKeys)
        {
            return PsScriptHelpers.Collect(sel, groupKeys);
        }

        private const string GraphHeaders =
            "$headers = @{ Authorization = ('Bearer ' + $env:MAT_GRAPH_TOKEN); ConsistencyLevel = 'eventual' }";

        // ============================================================ 1. AUTH TYPE
        private static AuditSection BuildAuthSection()
        {
            var section = new AuditSection(
                "domains-auth",
                "Domain authentication",
                "Domain authentication export",
                "Audit accepted domains via Graph: Managed vs Federated authentication type, verification and services, plus IdP details for federated domains (slow lookup).",
                "globe",
                AuditScope.Graph);
            section.Category = "Domains";
            section.Product = "Domains";
            section.DefaultFileName = "DomainsAuth.csv";

            var domain = new AuditOptionGroup("domain", "Domain", GroupMode.MultiCheck); domain.Columns = 2;
            domain.AddProp("Domain", true);
            domain.AddProp("AuthenticationType", true);
            domain.AddProp("IsVerified", true);
            domain.AddProp("IsRoot", true);
            domain.AddProp("IsDefault", true);
            domain.AddProp("SupportedServices", true);
            section.AddGroup(domain);

            var idp = new AuditOptionGroup("idp", "Federation IdP (slow per-domain lookup)", GroupMode.MultiCheck); idp.Columns = 1;
            idp.Hint = "One federationConfiguration query per federated domain only (managed domains skip it). Needs the Domain.Read.All consent.";
            idp.Add(AuditOption.Prop("FederationProvider", false).MarkSlow());
            idp.Add(AuditOption.Prop("IssuerUri", false).MarkSlow());
            idp.Add(AuditOption.Prop("ActiveLogOnUri", false).MarkSlow());
            idp.Add(AuditOption.Prop("MetadataExchangeUri", false).MarkSlow());
            section.AddGroup(idp);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "domain", "idp");
                if (chosen.Count == 0) chosen.Add("Domain");
                string selectList = string.Join(", ", chosen.ToArray());
                bool wantIdp = chosen.Contains("FederationProvider") || chosen.Contains("IssuerUri") || chosen.Contains("ActiveLogOnUri") || chosen.Contains("MetadataExchangeUri");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying domains (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$doms = @()");
                sb.AppendLine("try { $dr = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,authenticationType,isVerified,isRoot,isDefault,supportedServices' -Headers $headers -Method Get -ErrorAction Stop; $doms = @($dr.value) } catch { Write-Host ('WARNING: domains query failed (' + $_.Exception.Message + ' - consent for Domain.Read.All?)') }");
                sb.AppendLine("Write-Host (\"Retrieved {0} domain(s).\" -f $doms.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                if (wantIdp) sb.AppendLine("$fedFail = 0");
                sb.AppendLine("foreach ($d in $doms) {");
                sb.AppendLine("    $dn = [string]$d.id; $at = [string]$d.authenticationType");
                sb.AppendLine("    $ss = ((@($d.supportedServices) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ')");
                if (wantIdp)
                {
                    sb.AppendLine("    $fp = ''; $iu = ''; $alo = ''; $mex = ''");
                    sb.AppendLine("    if ($at -eq 'Federated') {");
                    sb.AppendLine("        try {");
                    sb.AppendLine("            $fc = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/domains/\" + $dn + \"/federationConfiguration\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("            $fo = @($fc.value)[0]");
                    sb.AppendLine("            $fp = [string]$fo.displayName; if (-not $fp) { $fp = [string]$fo.'@odata.type' }");
                    sb.AppendLine("            $iu = [string]$fo.issuerUri; $alo = [string]$fo.activeLogOnUri; $mex = [string]$fo.metadataExchangeUri");
                    sb.AppendLine("        } catch { $fedFail++ }");
                    sb.AppendLine("    }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        Domain = $dn; AuthenticationType = $at; IsVerified = $d.isVerified; IsRoot = $d.isRoot; IsDefault = $d.isDefault; SupportedServices = $ss;");
                sb.AppendLine("        FederationProvider = " + (chosen.Contains("FederationProvider") ? "$fp" : "''") + "; IssuerUri = " + (chosen.Contains("IssuerUri") ? "$iu" : "''") + "; ActiveLogOnUri = " + (chosen.Contains("ActiveLogOnUri") ? "$alo" : "''") + "; MetadataExchangeUri = " + (chosen.Contains("MetadataExchangeUri") ? "$mex" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantIdp) sb.AppendLine("if ($fedFail -gt 0) { Write-Host (\"WARNING: {0} federation querie(s) failed (consent for Domain.Read.All?).\" -f $fedFail) }");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ Domain = ''; AuthenticationType = ''; IsVerified = ''; IsRoot = ''; IsDefault = ''; SupportedServices = ''; FederationProvider = ''; IssuerUri = ''; ActiveLogOnUri = ''; MetadataExchangeUri = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 2. DNS RECORDS
        private static AuditSection BuildDnsSection()
        {
            var section = new AuditSection(
                "domains-dns",
                "DNS records",
                "DNS records export",
                "Audit mail-flow DNS per accepted domain via EXO + live DNS: domain type, MX, SPF, DMARC and DKIM selector state (one row per domain).",
                "dns",
                AuditScope.ExchangeOnline);
            section.Category = "Domains";
            section.Product = "Domains";
            section.DefaultFileName = "DomainsDns.csv";
            section.TipHtml = "DKIM selector TXT probes cover the selectors from Get-DkimSigningConfig (usually selector1/selector2). Domains with externally-managed DKIM selectors need those checked manually.";

            var domain = new AuditOptionGroup("domain", "Domain", GroupMode.MultiCheck); domain.Columns = 2;
            domain.AddProp("Domain", true);
            domain.AddProp("DomainType", true);
            section.AddGroup(domain);

            var mailflow = new AuditOptionGroup("mailflow", "MX & SPF", GroupMode.MultiCheck); mailflow.Columns = 1;
            mailflow.Hint = "Live DNS over HTTPS (Cloudflare, Google fallback) from the worker - no Graph or extra consent needed.";
            mailflow.AddProp("MXRecords", true);
            mailflow.AddProp("SPFRecord", true);
            section.AddGroup(mailflow);

            var dmarc = new AuditOptionGroup("dmarc", "DMARC", GroupMode.MultiCheck); dmarc.Columns = 1;
            dmarc.AddProp("DMARCRecord", true);
            section.AddGroup(dmarc);

            var dkim = new AuditOptionGroup("dkim", "DKIM", GroupMode.MultiCheck); dkim.Columns = 2;
            dkim.Hint = "Signing config from EXO (Get-DkimSigningConfig); selector TXT presence probed via live DNS.";
            dkim.AddProp("DKIMEnabled", true);
            dkim.AddProp("DKIMSelectors", true);
            dkim.AddProp("DKIMKeys", true);
            section.AddGroup(dkim);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "domain", "mailflow", "dmarc", "dkim");
                if (chosen.Count == 0) chosen.Add("Domain");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying accepted domains (EXO)...'");
                sb.AppendLine("try { $doms = @(Get-AcceptedDomain -ErrorAction Stop) } catch { Write-Host ('WARNING: Get-AcceptedDomain failed (' + $_.Exception.Message + ')'); $doms = @() }");
                sb.AppendLine("Write-Host (\"Retrieved {0} accepted domain(s).\" -f $doms.Count)");
                sb.AppendLine("try { $dkimCfg = @(Get-DkimSigningConfig -ErrorAction Stop) } catch { Write-Host ('WARNING: Get-DkimSigningConfig failed (' + $_.Exception.Message + ')'); $dkimCfg = @() }");
                sb.AppendLine("function Get-Doh { param($name, $type) try { $r = Invoke-RestMethod -Uri (\"https://cloudflare-dns.com/dns-query?name=\" + $name + \"&type=\" + $type) -Headers @{ Accept = 'application/dns-json' } -Method Get -ErrorAction Stop; return @(@($r.Answer) | ForEach-Object { [string]$_.data }) } catch { try { $g = Invoke-RestMethod -Uri (\"https://dns.google/resolve?name=\" + $name + \"&type=\" + $type) -Method Get -ErrorAction Stop; return @(@($g.Answer) | ForEach-Object { [string]$_.data }) } catch { $script:dnsFail++; return @() } } }");
                sb.AppendLine("function Get-DnsTxt { param($name) $o = @(); foreach ($s in @(Get-Doh $name 'TXT')) { $c = ($s -replace '\"','').Trim(); if ($c) { $o += $c } }; return (($o | Sort-Object -Unique) -join ' | ') }");
                sb.AppendLine("function Get-DnsMx { param($name) $o = @(); foreach ($s in @(Get-Doh $name 'MX')) { $p = $s -split '\\s+', 2; $pref = $p[0]; $ex = ''; if ($p.Count -gt 1) { $ex = $p[1].TrimEnd('.') }; $o += ($pref + ' ' + $ex).Trim() }; return (($o | Where-Object { $_ -ne '' } | Sort-Object) -join ' | ') }");
                sb.AppendLine("$script:dnsFail = 0");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($d in $doms) {");
                sb.AppendLine("    $dn = [string]$d.DomainName; if (-not $dn) { $dn = [string]$d.Name }");
                sb.AppendLine("    $mx = Get-DnsMx $dn");
                sb.AppendLine("    $txt = Get-DnsTxt $dn");
                sb.AppendLine("    $spf = ''; try { $spf = ((@($txt -split ' \\| ') | Where-Object { $_ -match '^v=spf1' }) -join ' | ') } catch { }");
                sb.AppendLine("    $dm = Get-DnsTxt ('_dmarc.' + $dn)");
                sb.AppendLine("    $dc = @($dkimCfg | Where-Object { [string]$_.Domain -eq $dn -or [string]$_.Identity -like ('*' + $dn + '*') }); $d0 = $dc | Select-Object -First 1");
                sb.AppendLine("    $de = ''; $ds = ''");
                sb.AppendLine("    if ($d0) { try { $de = [string]$d0.Enabled } catch { }; try { $s1 = [string]$d0.Selector1CNAME; $s2 = [string]$d0.Selector2CNAME; $ds = (($s1 + ',' + $s2) -split ',' | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ' } catch { }; if (-not $ds) { try { $ds = [string]$d0.Selector } catch { } } }");
                sb.AppendLine("    $dk = @(); foreach ($s in @($ds -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })) { $tr = Get-DnsTxt ($s + '._domainkey.' + $dn); if ($tr) { $dk += $s + ': present' } else { $dk += $s + ': MISSING' } }; $dks = ($dk -join ' | ')");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        Domain = $dn; DomainType = $d.DomainType; MXRecords = $mx; SPFRecord = $spf;");
                sb.AppendLine("        DMARCRecord = $dm; DKIMEnabled = $de; DKIMSelectors = $ds; DKIMKeys = $dks");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ Domain = ''; DomainType = ''; MXRecords = ''; SPFRecord = ''; DMARCRecord = ''; DKIMEnabled = ''; DKIMSelectors = ''; DKIMKeys = '' }) }");
                sb.AppendLine("if ($script:dnsFail -gt 0) { Write-Host (\"WARNING: {0} DNS querie(s) failed - worker container DNS may be restricted; empty cells may mean failure, not absence.\" -f $script:dnsFail) }");
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
