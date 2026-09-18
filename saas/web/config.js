/* M365 Audit SaaS - fallback web settings.
 * Preferred way: set these in saas/.env (MAT_CLIENT_ID, MAT_MSAL_SRC,
 * MAT_EXO_SCOPES) — the API serves them at /api/config and they win.
 * Anything set here is only used when /api/config is unreachable. */
window.MAT_CONFIG = {
  clientId: "",
  msalSources: ["./msal-browser.min.js"],
  exoScopes: ["https://outlook.office365.com/.default"],
  graphScopes: ["User.Read.All", "Organization.Read.All", "Group.Read.All", "Team.ReadBasic.All", "Channel.ReadBasic.All", "TeamMember.Read.All", "ChannelMember.Read.All", "TeamsAppInstallation.ReadForTeam", "TeamsTab.Read.All", "Reports.Read.All", "ChannelMessage.Read.All", "Sites.Read.All", "SharePointTenantSettings.Read.All", "AuditLog.Read.All", "UserAuthenticationMethod.Read.All", "RoleManagement.Read.Directory", "Directory.Read.All", "AdministrativeUnit.Read.All", "Policy.Read.All", "IdentityProvider.Read.All", "IdentityUserFlow.Read.All", "PrivilegedEligibilitySchedule.Read.AzureADGroup", "PrivilegedAssignmentSchedule.Read.AzureADGroup", "AccessReview.Read.All", "Application.Read.All", "Synchronization.Read.All", "Agreement.Read.All", "Device.Read.All", "TeamsTelephoneNumber.Read.All", "EntitlementManagement.Read.All", "CustomSecAttributeDefinition.Read.All", "CustomSecAttributeAssignment.Read.All", "Domain.Read.All", "IdentityRiskyUser.Read.All", "TermStore.Read.All", "Bookings.Read.All", "Community.Read.All"],
  powerScopes: ["https://api.powerplatform.com/EnvironmentManagement.Environments.Read", "https://api.powerplatform.com/PowerAutomate.Flows.Read", "https://api.powerplatform.com/PowerApps.Apps.Read", "https://api.powerplatform.com/Connectivity.Connectors.Read"]
};
