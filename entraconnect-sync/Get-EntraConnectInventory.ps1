<#
.SYNOPSIS
  Inventaire Entra Connect / Cloud Sync pour préparation de migration
  (couche admin) : ce que Microsoft Graph NE PEUT PAS exposer.

  Les règles de synchronisation, le scoping d'OU, le mappage d'attributs et
  la planification vivent dans la base du moteur de synchronisation sur le
  serveur Entra Connect lui-même (aucune API Graph, aucun PowerShell distant).
  Ce script se lance DONC SUR LE SERVEUR SOURCE (module ADSync) depuis une
  session admin locale.

  Pour la "source of authority" par objet (cloud vs synchronisé + DN/Domain/
  SAM/UPN on-premises), utilisez la section SaaS Entra ID > Standard Objects >
  Users, groupe "Hybrid sync".

.REQUIREMENTS
  Windows PowerShell 5.1 sur le serveur Entra Connect / Entra Cloud Sync,
  module ADSync (installé avec Entra Connect), exécution en administrateur.

.EXAMPLE
  .\Get-EntraConnectInventory.ps1 -OutDir .\out
  # -> SyncScheduler.csv, Connectors.csv, Partitions.csv, SyncRules.csv

.OUTPUTS (délimité ';', UTF-8, même convention que l'outil SaaS)
#>
[CmdletBinding()]
param(
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

try { Import-Module ADSync -ErrorAction Stop } catch { Write-Warning ("Module ADSync introuvable (lancer sur le serveur Entra Connect) : " + $_.Exception.Message) }

# ---------------------------------------------------------- 1. Planificateur
Write-Host 'Lecture du planificateur (Get-ADSyncScheduler)...'
$schedRows = @()
try {
    $s = Get-ADSyncScheduler -ErrorAction Stop
    $schedRows = @([pscustomobject]@{
        SyncCycleEnabled                 = $s.SyncCycleEnabled
        StagingModeEnabled               = $s.StagingModeEnabled
        SchedulerSuspended               = $s.SchedulerSuspended
        AllowedSyncCycleInterval         = $s.AllowedSyncCycleInterval
        CurrentlyEffectiveSyncCycleInterval = $s.CurrentlyEffectiveSyncCycleInterval
        CustomizedSyncCycleInterval      = $s.CustomizedSyncCycleInterval
        NextSyncCyclePolicyType          = $s.NextSyncCyclePolicyType
        NextSyncCycleStartTime           = $s.NextSyncCycleStartTime
        PurgeRunHistoryInterval          = $s.PurgeRunHistoryInterval
    })
} catch { Write-Warning ("Get-ADSyncScheduler échec : " + $_.Exception.Message) }
Export-Out $schedRows 'SyncScheduler.csv'

# ---------------------------------------------------------- 2. Connecteurs
Write-Host 'Lecture des connecteurs (Get-ADSyncConnector)...'
$connectors = @()
try { $connectors = @(Get-ADSyncConnector -ErrorAction Stop) } catch { Write-Warning ("Get-ADSyncConnector échec : " + $_.Exception.Message) }
Write-Host ("Retrieved {0} connecteur(s)." -f $connectors.Count)
$connRows = foreach ($c in $connectors) {
    [pscustomobject]@{
        Name        = $c.Name
        Identifier  = $c.Identifier
        Type        = $c.Type
        SubType     = $c.SubType
        Description = $c.Description
    }
}
Export-Out $connRows 'Connectors.csv'

# ---------------------------------------------------------- 3. Partitions (scoping OU)
Write-Host 'Lecture des partitions / scoping OU (Get-ADSyncConnectorPartition, best-effort)...'
$partRows = New-Object System.Collections.Generic.List[object]
$partFail = 0
foreach ($c in $connectors) {
    $plist = $null
    try { $plist = @(Get-ADSyncConnectorPartition -ConnectorName ([string]$c.Name) -ErrorAction Stop) }
    catch {
        try { $plist = @(Get-ADSyncConnectorPartition -ConnectorIdentifier ([string]$c.Identifier) -ErrorAction Stop) }
        catch { $partFail++ }
    }
    foreach ($p in @($plist)) {
        $partRows.Add([pscustomobject]@{
            Connector = $c.Name
            Name      = $p.Name
            DN        = $p.DN
            Selected  = $p.Selected
        })
    }
}
if ($partFail -gt 0) { Write-Warning ("Partitions illisibles pour {0} connecteur(s) - vérifier les noms de paramètres sur cette version du module ADSync." -f $partFail) }
Export-Out $partRows 'Partitions.csv'

# ---------------------------------------------------------- 4. Règles + mappages
Write-Host 'Lecture des règles de synchronisation (Get-ADSyncRule)...'
$rules = @()
try { $rules = @(Get-ADSyncRule -ErrorAction Stop) } catch { Write-Warning ("Get-ADSyncRule échec : " + $_.Exception.Message) }
Write-Host ("Retrieved {0} règle(s)." -f $rules.Count)
$ruleRows = foreach ($r in $rules) {
    $maps = @()
    try {
        foreach ($m in @($r.AttributeFlowMappings)) {
            $ms = [string]$m.Source; $md = [string]$m.Destination; $mf = [string]$m.FlowType
            if ($ms -or $md) { $maps += ($ms + ' -> ' + $md + ' [' + $mf + ']') }
        }
    } catch { }
    [pscustomobject]@{
        Name             = $r.Name
        Identifier       = $r.Identifier
        Precedence       = $r.Precedence
        ImmutableTag     = $r.ImmutableTag
        SourceObjectType = $r.SourceObjectType
        TargetObjectType = $r.TargetObjectType
        LinkType         = $r.LinkType
        Disabled         = $r.Disabled
        Description      = $r.Description
        Mappings         = ($maps -join '; ')
    }
}
Export-Out $ruleRows 'SyncRules.csv'

Write-Host 'Export complete.'
