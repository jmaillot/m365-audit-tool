<#
.SYNOPSIS
  SharePoint hub sites inventory for migration prep (admin layer): hub
  registration and hub associations, which Microsoft Graph does NOT expose
  (no hub property or endpoint in v1.0).

  Run from an admin workstation with the SharePoint Online Management Shell.
  Hub navigation, theme inheritance and permissions must be rebuilt in the
  target tenant - this file scopes that work.

.REQUIREMENTS
  Module Microsoft.Online.SharePoint.PowerShell, SharePoint administrator
  role (or Global admin).

.EXAMPLE
  .\Get-SPOHubInventory.ps1 -AdminUrl https://TENANT-admin.sharepoint.com -OutDir .\out
  # -> HubSites.csv (one row per hub) + HubAssociations.csv (hub -> site)

.OUTPUTS (; -delimited UTF-8, same convention as the SaaS audit tool)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AdminUrl,          # e.g. https://contoso-admin.sharepoint.com
    [string]$OutDir = "."
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

function Join-Multi($v) { ((@($v) | ForEach-Object { [string]$_ }) | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',' }

function Export-Out($rows, $name) {
    $path = Join-Path $OutDir $name
    @($rows) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host ("Wrote {0} ({1} row(s))." -f $path, @($rows).Count)
}

Write-Host 'Connecting SharePoint Online Management Shell...'
Connect-SPOService -Url $AdminUrl

Write-Host 'Reading hub sites (Get-SPOHubSite)...'
$hubs = @()
try { $hubs = @(Get-SPOHubSite -ErrorAction Stop) } catch { Write-Warning ("Get-SPOHubSite failed: " + $_.Exception.Message) }
Write-Host ("Retrieved {0} hub site(s)." -f $hubs.Count)
$hubRows = foreach ($h in $hubs) {
    [pscustomobject]@{
        HubSiteId   = $h.ID
        SiteUrl     = $h.SiteUrl
        Title       = $h.Title
        Description = $h.Description
        LogoUrl     = $h.LogoUrl
    }
}
Export-Out $hubRows 'HubSites.csv'

Write-Host 'Reading all sites for hub associations (Get-SPOSite, can be slow)...'
$assoc = New-Object System.Collections.Generic.List[object]
try {
    $all = @(Get-SPOSite -Limit All -IncludePersonalSite $false -ErrorAction Stop)
    Write-Host ("Retrieved {0} site(s)." -f $all.Count)
    foreach ($s in $all) {
        $hid = [string]$s.HubSiteId
        if ($hid -and $hid -ne '00000000-0000-0000-0000-000000000000') {
            $hn = ''; $hub = @($hubs | Where-Object { [string]$_.ID -eq $hid }) | Select-Object -First 1
            if ($hub) { $hn = [string]$hub.Title }
            $assoc.Add([pscustomobject]@{
                HubSiteId = $hid
                HubTitle  = $hn
                SiteUrl   = $s.Url
                Template  = $s.Template
            })
        }
    }
} catch { Write-Warning ("Get-SPOSite failed: " + $_.Exception.Message) }
Export-Out $assoc 'HubAssociations.csv'

Write-Host 'Done. Disconnecting...'
try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch { }
Write-Host 'Export complete.'
