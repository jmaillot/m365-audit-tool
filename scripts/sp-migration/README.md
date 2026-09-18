# SharePoint migration toolkit (couche admin — hors SaaS)

Compagnon du collecteur SaaS (onglet produit **SharePoint**) pour préparer une
migration SharePoint Online tenant à tenant. Le SaaS tourne avec des tokens
délégués (Graph REST uniquement) : tout ce qui exige SharePoint Online
Management Shell ou PnP PowerShell se fait ici, depuis un poste admin.

## Couverture : quoi chercher où

| Donnée | SaaS (Graph) | Ce dossier (admin) |
|---|---|---|
| Énumération des sites, URL, titre, dates | ✅ | — |
| Template (rapport ≤48h), FileCount, stockage live, propriétaires (rapport/groupe), GroupId, IsTeamsConnected, SensitivityLabelId (sites groupés), Status, MigrationWave/Decision | ✅ | — |
| LockState, SharingCapability, quotas admin, propriétaire SPO déclaratif, sites supprimés | — | ✅ `Get-SPOSiteInventory.ps1` |
| Sous-sites : IDs/URL/titres/dates | ✅ | — |
| Sous-sites : WebTemplate/Configuration/Language, permissions uniques, navigation, groupes/membres, features, pages modernes, WebParts, listes/champs/types de contenu, paramètres régionaux | — | ✅ `scripts/Get-PnPWebInventory.ps1` |
| Content types : nom, groupe, flag hidden, type de base, par site | ✅ section SaaS **Content types** (par collection de sites, filtre All / Non-hidden) | ✅ `scripts/Get-PnPWebInventory.ps1` (par web/liste — niveau fin, complément du niveau site SaaS) |
| Term store : groupes > sets + nombre de termes | ✅ section SaaS **Term store** | — (labels/hiérarchie des termes : portail ou PnP manuel) |
| OneDrive : quotas, sharing ODB, rétention post-départ (DeletedUserPersonalSiteRetentionDays) | ✅ SaaS SharePoint > **SharePoint/OneDrive** (settings) | ✅ `scripts/Get-SPOTenantSharing.ps1` (reste ODB : link defaults, expirations…) + `Get-SPOSite -IncludePersonalSite` (inventaire sites personnels + orphelins, propriétaires réels — seule source fiable, les rapports Graph identifiant les orphelins par IDs non résolvables) |
| Stratégie de partage tenant : TenantName, SharingCapability, RequireAcceptingAccountMatchInvitedAccount, SharingDomainRestrictionMode, Allowed/BlockedDomainList | ✅ | — |
| Stratégie de partage tenant : reste de `Get-SPOTenant` (DefaultSharingLinkType/Permission, expirations Anyone/Organization, EmailAttestation*, BccExternalSharing*, OneDriveForGuestsEnabled, ODBMembersCanShare, ODBAccessRequests, PeoplePicker guest suggestions…) | — | ✅ `Get-SPOTenantSharing.ps1` |

Tous les CSV sont `;`-délimités, UTF-8 — même convention que l'outil SaaS.

## Prérequis

- Rôle **SharePoint administrator** (ou Global admin) du tenant source.
- PowerShell 7.x + modules :
  `Install-Module Microsoft.Online.SharePoint.PowerShell`,
  `Install-Module PnP.PowerShell -Scope CurrentUser` (2.x/3.x).
- Authent interactive (ou certificat, voir commentaires dans les scripts).

## Usage

```powershell
# 1. Inventaire administratif global (rapide, 1 passage)
.\scripts\Get-SPOSiteInventory.ps1 -AdminUrl https://TENANT-admin.sharepoint.com -OutDir .\out
# -> Sites-Admin.csv, Sites-Deleted.csv

# 2. Deep-dive par site (long : ~1 connexion + N requêtes par site).
#    Alimentez -SiteUrls avec la colonne Url du CSV SaaS (filtrez d'abord
#    MigrationWave/Decision dans Excel).
.\scripts\Get-PnPWebInventory.ps1 -SiteUrls (Import-Csv .\SharePointSites-*.csv -Delimiter ';' | Select-Object -ExpandProperty Url) -OutDir .\out
# -> Webs.csv, Lists.csv, Fields.csv, ContentTypes.csv, Pages.csv,
#    WebParts.csv, Navigation.csv, Groups.csv, Permissions.csv, Features.csv
```

Astuce : la colonne vide `MigrationWave` du CSV SaaS est faite pour être
remplie dans Excel, puis utilisée pour filtrer les vagues avant l'étape 2
(`Where-Object { $_.MigrationWave -eq '1' }`).

## Stratégie de partage tenant (complément de la section SaaS)

La section SaaS **Sharing Policy** couvre via Graph : TenantName,
SharingCapability, RequireAcceptingAccountMatchInvitedAccount,
SharingDomainRestrictionMode, SharingAllowedDomainList,
SharingBlockedDomainList. Tout le reste de `Get-SPOTenant` n'existe pas en
Graph :

```powershell
.\scripts\Get-SPOTenantSharing.ps1 -AdminUrl https://TENANT-admin.sharepoint.com -OutDir .\out
# -> Tenant-Sharing.csv (une ligne : DefaultSharingLinkType,
#    DefaultLinkPermission, fenêtres d'expiration Anyone/Organization,
#    EmailAttestation*, BccExternalSharing*, OneDriveForGuestsEnabled,
#    ODBMembersCanShare, ODBAccessRequests,
#    ShowPeoplePickerSuggestionsForGuestUsers, ...)
```

## Hub sites (aucune API Graph)

Ni propriété ni endpoint hub en Graph v1.0 : enregistrement des hubs et
associations hub -> sites via SharePoint Online Management Shell. La
navigation hub, l'héritage de thème et les permissions se reconstruisent
dans le tenant cible — ce script dimensionne ce travail :

```powershell
.\scripts\Get-SPOHubInventory.ps1 -AdminUrl https://TENANT-admin.sharepoint.com -OutDir .\out
# -> HubSites.csv (un hub par ligne : ID, URL, titre, description, logo),
#    HubAssociations.csv (hub -> site + template, via un seul passage
#    Get-SPOSite filtré localement sur HubSiteId)
```
