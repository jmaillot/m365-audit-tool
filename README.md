# Microsoft 365 Audit Tool (Exchange Online + Entra ID + Licensing + Teams + SharePoint/OneDrive + Purview + Power Platform + Conditional Access + Intune + Domains + Viva Engage)

Dockerized SaaS port of the Exchange Audit Tool: 88 online audit sections (26 Exchange Online + 24 Entra ID + 4 Licensing + 10 Teams + 6 SharePoint/OneDrive + 6 Purview + 4 Power Platform + 4 Conditional Access + 2 Domains + 1 Intune + 1 Viva Engage, via Exchange Online / Microsoft Graph / Power Platform API — plus 2 on-premises-only sections hidden in SaaS) with the same selectable properties and `;`-delimited CSV + XLSX export, Azure Portal-style web UI, single multi-tenant Entra app (tokens in tab session only: F5-safe, dropped on disconnect or tab close).

Start here: [`saas/README.md`](saas/README.md) — multi-tenant app setup, Docker Compose setup, usage, API reference, troubleshooting.

```
saas/
  api/      → .NET 8 API (section catalog, job dispatch, XLSX export)
  api/Shared/ → audit DSL + section builders (Exchange Online + Graph + Power Platform)
  worker/   → pwsh 7.4 + ExchangeOnlineManagement job runner
  web/      → nginx + Portal-style UI (no build step)
  docker-compose.yml
scripts/
  sp-migration/    → SharePoint admin toolkit (hors SaaS, voir son README)
  teams-voice/     → Teams voice/policy toolkit (hors SaaS, voir son README)
  entraconnect-sync/ → Entra Connect sync toolkit (hors SaaS, voir son README)
```
