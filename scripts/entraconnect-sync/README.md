# Entra Connect / Cloud Sync toolkit (couche admin — hors SaaS)

Compagnon du collecteur SaaS pour préparer une migration tenant à tenant
quand le tenant source est **hybride**. Le SaaS tourne avec des tokens
délégués (Graph REST uniquement) : tout ce qui vit dans le moteur de
synchronisation **sur le serveur Entra Connect** se fait ici, depuis ce
serveur (aucune API Graph ni PowerShell distant n'existe pour ça).

## Couverture : quoi chercher où

| Donnée | SaaS (Graph) | Ce dossier (serveur source) |
|---|---|---|
| Source of authority par objet (sync vs cloud + DN/domain/SAM/UPN on-premises) | ✅ Users, groupe « Hybrid sync » | — |
| Planificateur (cycle, staging mode, suspension, purge) | — | ✅ `SyncScheduler.csv` |
| Connecteurs (AD + Entra ID) | — | ✅ `Connectors.csv` |
| Scoping OU (partitions sélectionnées) | — | ✅ `Partitions.csv` (best-effort selon version du module ADSync) |
| Règles de sync + mappage d'attributs | — | ✅ `SyncRules.csv` (colonne `Mappings` : `Source -> Destination [FlowType]`) |
| État Password Hash Sync / Password Writeback | checklist manuelle (README §7) | état PHS/PW dans l'assistant Entra Connect (miisclient, fonctionnalités optionnelles) |

Tous les CSV sont `;`-délimités, UTF-8 — même convention que l'outil SaaS.

## Prérequis

- Windows PowerShell 5.1 **sur le serveur Entra Connect**, exécution en
  administrateur, module `ADSync` (installé avec Entra Connect).

## Usage

```powershell
.\scripts\Get-EntraConnectInventory.ps1 -OutDir .\out
# -> SyncScheduler.csv, Connectors.csv, Partitions.csv, SyncRules.csv
```

Astuce : croisez `SyncRules.csv` (précédence, règles désactivées, mappings)
avec la colonne `OnPremisesImmutableId` du CSV SaaS EntraUsers pour valider
quels objets sont réellement gouvernés on-premises avant la migration.
