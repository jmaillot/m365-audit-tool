using System;
using System.Collections.Generic;
using System.Text;

namespace M365AuditTool
{
    // "Entra ID" category (Microsoft Graph, NOT Exchange Online):
    //   entra-users -> GET /users (one row per user: identity, account,
    //     organization, contact, address, on-premises sync) + optional
    //     per-user lookups, one query each, only when the column is checked:
    //     signInActivity.lastSignInDateTime (in the base query, needs
    //     AuditLog.Read.All or the whole query 403s),
    //     /users/{id}/authentication/methods (MFAEnabled = Yes when a
    //     non-password method is registered, needs
    //     UserAuthenticationMethod.Read.All),
    //     /users/{id}/transitiveMemberOf (AssignedRoles = directoryRole
    //     display names + GroupCount = group count, needs
    //     RoleManagement.Read.Directory),
    //     /users/{id}/manager (ManagerUPN, Get-MgUserManager equivalent).
    //   entra-groups -> GET /groups (one row per group: identity + description,
    //     createdDateTime, proxyAddresses, groupTypes, security/mail flags,
    //     dynamic rule, isAssignableToRole, hybrid sync state, M365 specifics
    //     incl. licenses/Teams/expiration/labels) + optional lookups, only when
    //     checked: owners/members UPN lists + counts (NestedGroups derived from
    //     member types), /sites/root per M365 group (SharePointSiteUrl),
    //     group-held directory roles (one shared roleAssignments fetch),
    //     appRoleAssignments with resolved app role names, Conditional Access
    //     policies referencing the group (one shared fetch), PIM-for-Groups
    //     eligible/active schedules. Needs Group.Read.All (+
    //     RoleManagement.Read.Directory, Directory.Read.All, Policy.Read.All,
    //     PrivilegedEligibilitySchedule.Read.AzureADGroup +
    //     PrivilegedAssignmentSchedule.Read.AzureADGroup for the extras).
    //   entra-guest-users -> GET /users $filter=userType eq 'Guest' (UPN,
    //     display name, mail, other mails, externalUserState, creationType,
    //     source IdP from identities, derived home tenant, optional last
    //     sign-in via signInActivity) + optional slow per-guest lookups, only
    //     when checked: /sponsors (Sponsors), /transitiveMemberOf (Groups +
    //     AssignedRoles), /appRoleAssignments (AppRoles). Needs User.Read.All
    //     (+ AuditLog.Read.All for sign-in, RoleManagement.Read.Directory for
    //     memberships, Directory.Read.All for app roles).
    //   entra-risky-users -> GET /identityProtection/riskyUsers (one row per
    //     at-risk user: level, state, detail, last update). Risk STATE only -
    //     no policy-config endpoint exists (even beta); enforcement is
    //     captured per CA policy in ca-policies RiskLevels. Needs
    //     IdentityRiskyUser.Read.All.
    //   entra-auth-methods -> GET /users (id, displayName, userPrincipalName) +
    //     one /users/{id}/authentication/methods query per user
    //     (Get-MgUserAuthenticationMethod equivalent, needs
    //     UserAuthenticationMethod.Read.All): per-method counts for
    //     MicrosoftAuthenticator, SMS, Voice, FIDO2, WindowsHello, Passkey and
    //     TemporaryAccessPass. v1.0 phoneAuthenticationMethod covers both SMS
    //     and voice, so one phone number counts +1 SMS and +1 Voice.
    //   entra-auth-policies -> GET /policies/authenticationMethodsPolicy (auto-
    //     expanded method configurations: one row per method with State +
    //     target summary) + SSPR allowed flag (authorizationPolicy) + SSPR
    //     migration state + MFA registration campaign. SSPR auth-method detail,
    //     banned passwords and smart-lockout tuning are NOT in Graph v1.0
    //     (portal-only). Needs Policy.Read.All.
    //   entra-security-defaults -> GET /policies/
    //     identitySecurityDefaultsEnforcementPolicy (isEnabled, one row).
    //     Mutually exclusive with Conditional Access. Needs Policy.Read.All.
    //   entra-pim-groups -> GET /identityGovernance/privilegedAccess/group/
    //     eligibilitySchedules + assignmentSchedules (one row per schedule:
    //     resolved group/principal, member/owner, eligible vs active,
    //     window; terminal states skipped). PIM for Groups, distinct from
    //     PIM for directory roles. Needs PrivilegedEligibilitySchedule.
    //     Read.AzureADGroup + PrivilegedAssignmentSchedule.Read.AzureADGroup.
    //   entra-schema-extensions -> GET /schemaExtensions (one row per
    //     extension: target types, properties, status, owning app resolved).
    //     Needs Application.Read.All.
    //   entra-directory-roles -> GET /roleManagement/directory/roleDefinitions
    //     (Get-MgDirectoryRole equivalent for migration: RoleName, Description,
    //     RoleKind Built-in/Custom, and for custom roles the full
    //     rolePermissions/allowedResourceActions set so they can be recreated
    //     in the target tenant). Needs RoleManagement.Read.Directory.
    //   entra-role-assignments -> roleAssignments (active) +
    //     roleEligibilitySchedules (PIM eligible) + roleAssignmentSchedules
    //     (PIM active): one row per assignment with RoleName, PrincipalName
    //     (UPN/display/app name, resolved - never raw IDs alone), PrincipalType,
    //     AssignmentType (Active / Eligible (PIM) / Active (PIM)), IsPermanent
    //     (Yes when no end date: permanent actives + noExpiration schedules),
    //     Scope (Tenant-wide or AU display name), StartDateTime/EndDateTime,
    //     plus optional best-effort Justification/TicketInfo from the PIM
    //     schedule requests. Needs RoleManagement.Read.Directory (+
    //     Directory.Read.All for service-principal names,
    //     AdministrativeUnit.Read.All for AU names).
    //   entra-pim-settings -> GET /policies/roleManagementPolicies (+ /rules
    //     per policy): RoleName, ActivationDuration (EndUser expiration),
    //     ApprovalRequired + Approvers (UPNs), RequireJustification,
    //     RequireTicket, RequireMFA, NotificationSummary. Needs
    //     RoleManagement.Read.Directory.
    //   entra-admin-units -> GET /directory/administrativeUnits (Id,
    //     DisplayName, Description, effective Visibility, MembershipType,
    //     MembershipRule, RuleProcessingState, RestrictedManagement) +
    //     per-unit /members split into UserMembers/GroupMembers/DeviceMembers,
    //     per-unit /scopedRoleMembers plus shared PIM schedules filtered by AU
    //     scope (AssignedRoles, AssignmentCount, AssignmentDetails with
    //     eligible vs active), and AU-scoped access reviews matched locally
    //     from one shared definitions fetch. Graph v1.0 has no AU creation
    //     date or provisioning source. Needs AdministrativeUnit.Read.All (+
    //     RoleManagement.Read.Directory, Directory.Read.All,
    //     AccessReview.Read.All).
    //   entra-external-settings -> tenant-wide External ID policies, one row:
    //     /policies/authorizationPolicy (who can invite, guest access level,
    //     email sign-up), /policies/authenticationFlowsPolicy (self-service
    //     sign-up) + /identity/b2xUserFlows (user flows). Domain allow/block
    //     lists are NOT exposed by Graph v1.0 (beta b2bManagementPolicy only)
    //     - review them in the Entra portal. Needs Policy.Read.All (+
    //     IdentityUserFlow.Read.All for user flows).
    //   entra-cross-tenant -> /policies/crossTenantAccessPolicy/default + one
    //     row per /partners tenant: inbound/outbound B2B collaboration and
    //     direct-connect summaries, inbound trust (MFA / compliant /
    //     hybrid-joined claims), tenant restrictions (users/apps/devices
    //     stance, same object - no extra query), automatic redemption +
    //     consent, optional slow per-partner identitySynchronization
    //     (cross-tenant sync scope). Needs Policy.Read.All.
    //   entra-external-idps -> GET /identity/identityProviders (configured
    //     Google/Facebook IdPs; SAML/WS-Fed custom IdPs are portal-only) +
    //     redemption order from the cross-tenant default configuration. Needs
    //     IdentityProvider.Read.All (+ Policy.Read.All for redemption order).
    //   entra-app-registrations -> GET /applications (DisplayName, AppId,
    //     SignInAudience, RedirectUris, ApiPermissions with delegated vs
    //     application split resolved via the resource SPs, Secrets/Certificates
    //     with expiry incl. EXPIRED flag - values never transfer and must be
    //     regenerated pre-cutover). Needs Application.Read.All.
    //   entra-enterprise-apps -> GET /servicePrincipals (Application type:
    //     SsoMode, Homepage, LoginUrl, Enabled, optional Hide-Microsoft-apps
    //     scope) + per-app /appRoleAssignedTo (AssignedUsers with app role
    //     names) + per-app /synchronization/jobs (Provisioning state/interval).
    //     Needs Application.Read.All (+ Synchronization.Read.All for
    //     provisioning).
    //   entra-consent-grants -> GET /oauth2PermissionGrants (delegated scopes:
    //     admin tenant-wide vs user consent + who consented) + optional slow
    //     per-client outgoing appRoleAssignments (application permissions) +
    //     optional Hide-Microsoft-clients scope. Needs Directory.Read.All (+
    //     Application.Read.All for role names).
    //   entra-access-packages -> GET /identityGovernance/entitlementManagement/
    //     accessPackages (+$expand=catalog) + one shared assignmentPolicies
    //     fetch matched locally (requestors incl. connected organizations,
    //     approval stages, duration) + one shared connectedOrganizations
    //     fetch + optional slow per-package accessPackageResourceRoleScopes
    //     (granted resources). Needs EntitlementManagement.Read.All + the
    //     auditor holding Catalog reader (least) or an Entra reader role.
    //   entra-access-reviews -> GET /identityGovernance/accessReviews/
    //     definitions (one row per review: resolved scope incl.
    //     instanceEnumerationScope, recurrence schedule, reviewers/fallback,
    //     decision settings; StageCount flags multi-stage reviews whose
    //     per-stage settings override the top-level columns). Needs
    //     AccessReview.Read.All.
    //   entra-custom-attributes -> GET /directory/customSecurityAttribute-
    //     Definitions (+?$expand=allowedValues) + slow per-user
    //     customSecurityAttributes lookups aggregated per definition
    //     (AssignedCount/AssignedTo). Needs CustomSecAttributeDefinition.
    //     Read.All (+ CustomSecAttributeAssignment.Read.All) + the auditor
    //     holding Attribute Definition Reader or similar (Global Admin
    //     alone 403s).
    //   entra-org-profile -> GET /organization (one row: technical/privacy
    //     contacts, tenant type, locale). Needs Organization.Read.All.
    //   entra-branding -> GET /organization/{id}/branding (Accept-Language:
    //     0; default-locale text + configured logo/image flags) + optional
    //     /branding/localizations (locale overrides). 404 = unconfigured
    //     (placeholder row). Needs Organization.Read.All + the auditor
    //     holding Global Reader or Organizational Branding Administrator.
    // All emitted cells are pre-joined scalars, so Select-Object takes plain
    // property names and the ';' CSV never clashes (multi-values are ','-joined).
    internal static class SectionsEntraID
    {
        public static void Register()
        {
            AuditRegistry.Register(BuildUsersSection());
            AuditRegistry.Register(BuildGroupsSection());
            AuditRegistry.Register(BuildGuestUsersSection());
            AuditRegistry.Register(BuildRiskyUsersSection());
            AuditRegistry.Register(BuildAuthMethodsSection());
            AuditRegistry.Register(BuildAuthPoliciesSection());
            AuditRegistry.Register(BuildDirectoryRolesSection());
            AuditRegistry.Register(BuildRoleAssignmentsSection());
            AuditRegistry.Register(BuildPimSettingsSection());
            AuditRegistry.Register(BuildAdminUnitsSection());
            AuditRegistry.Register(BuildExternalSettingsSection());
            AuditRegistry.Register(BuildCrossTenantSection());
            AuditRegistry.Register(BuildExternalIdpsSection());
            AuditRegistry.Register(BuildAppRegistrationsSection());
            AuditRegistry.Register(BuildEnterpriseAppsSection());
            AuditRegistry.Register(BuildConsentGrantsSection());
            AuditRegistry.Register(BuildAccessPackagesSection());
            AuditRegistry.Register(BuildAccessReviewsSection());
            AuditRegistry.Register(BuildCustomAttributesSection());
            AuditRegistry.Register(BuildOrgProfileSection());
            AuditRegistry.Register(BuildBrandingSection());
            AuditRegistry.Register(BuildSecurityDefaultsSection());
            AuditRegistry.Register(BuildPimGroupsSection());
            AuditRegistry.Register(BuildSchemaExtensionsSection());
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
            return "$size = '" + size + "'\n$maxUsers = -1\nif ($size -eq '100') { $maxUsers = 100 } elseif ($size -eq '1000') { $maxUsers = 1000 }";
        }

        // ============================================================ 1. USERS
        private static AuditSection BuildUsersSection()
        {
            var section = new AuditSection(
                "entra-users",
                "Users",
                "Entra ID users export",
                "Audit Entra ID users via Graph: identity, organization and contact plus MFA state, roles, group count and manager (slow per-user lookups).",
                "user",
                AuditScope.Graph);
            section.Category = "Standard Objects";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraUsers.csv";

            var identity = new AuditOptionGroup("identity", "Identity", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("Id", true);
            identity.AddProp("DisplayName", true);
            identity.AddProp("GivenName", true);
            identity.AddProp("Surname", true);
            identity.AddProp("UserPrincipalName", true);
            identity.AddProp("Mail", true);
            identity.AddProp("MailNickname", true);
            section.AddGroup(identity);

            var account = new AuditOptionGroup("account", "Account", GroupMode.MultiCheck); account.Columns = 2;
            account.AddProp("AccountEnabled", true);
            account.AddProp("UserType", true);
            account.AddProp("CreatedDateTime", true);
            account.AddProp("EmployeeId", true);
            section.AddGroup(account);

            var org = new AuditOptionGroup("organization", "Organization", GroupMode.MultiCheck); org.Columns = 2;
            org.AddProp("Department", true);
            org.AddProp("CompanyName", true);
            org.AddProp("JobTitle", true);
            org.AddProp("OfficeLocation", true);
            section.AddGroup(org);

            var contact = new AuditOptionGroup("contact", "Contact & locale", GroupMode.MultiCheck); contact.Columns = 2;
            contact.AddProp("MobilePhone", true);
            contact.AddProp("BusinessPhones", true);
            contact.AddProp("PreferredLanguage", true);
            contact.AddProp("UsageLocation", true);
            section.AddGroup(contact);

            var address = new AuditOptionGroup("address", "Address", GroupMode.MultiCheck); address.Columns = 2;
            address.AddProp("City", true);
            address.AddProp("Country", true);
            address.AddProp("StreetAddress", true);
            address.AddProp("PostalCode", true);
            address.AddProp("State", true);
            section.AddGroup(address);

            var onprem = new AuditOptionGroup("onprem", "Hybrid sync", GroupMode.MultiCheck); onprem.Columns = 2;
            onprem.Hint = "Source of authority: synced objects carry the on-premises distinguished name, domain and SAM/UPN values - cloud-only objects leave them empty.";
            onprem.AddProp("OnPremisesSyncEnabled", true);
            onprem.AddProp("OnPremisesImmutableId", true);
            onprem.AddProp("OnPremisesDistinguishedName", true);
            onprem.AddProp("OnPremisesDomainName", true);
            onprem.AddProp("OnPremisesSamAccountName", true);
            onprem.AddProp("OnPremisesUserPrincipalName", true);
            section.AddGroup(onprem);

            var signin = new AuditOptionGroup("signin", "Sign-in activity", GroupMode.MultiCheck); signin.Columns = 1;
            signin.Hint = "Needs the AuditLog.Read.All consent; without it the whole query is rejected - uncheck the column instead.";
            signin.AddProp("LastSignInDateTime", true);
            section.AddGroup(signin);

            var security = new AuditOptionGroup("security", "Authentication (slow per-user lookup)", GroupMode.MultiCheck); security.Columns = 1;
            security.Hint = "One authentication-methods query per user - slower on large tenants. Needs the UserAuthenticationMethod.Read.All consent.";
            security.Add(AuditOption.Prop("MFAEnabled", false).MarkSlow());
            section.AddGroup(security);

            var memberships = new AuditOptionGroup("memberships", "Roles & groups (slow per-user lookup)", GroupMode.MultiCheck); memberships.Columns = 2;
            memberships.Hint = "One transitive-membership query per user - slower on large tenants. Needs the RoleManagement.Read.Directory consent.";
            memberships.Add(AuditOption.Prop("AssignedRoles", false).MarkSlow());
            memberships.Add(AuditOption.Prop("GroupCount", false).MarkSlow());
            section.AddGroup(memberships);

            var manager = new AuditOptionGroup("manager", "Manager (slow per-user lookup)", GroupMode.MultiCheck); manager.Columns = 1;
            manager.Hint = "One manager query per user (Get-MgUserManager equivalent) - slower on large tenants. Empty when no manager is assigned.";
            manager.Add(AuditOption.Prop("ManagerUPN", false).MarkSlow());
            section.AddGroup(manager);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "account", "organization", "contact", "address", "onprem", "signin", "security", "memberships", "manager");
                if (chosen.Count == 0) chosen.Add("UserPrincipalName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                // signInActivity is only requested from Graph when its column
                // is checked: without AuditLog.Read.All the whole query 403s.
                bool wantSignIn = chosen.Contains("LastSignInDateTime");
                bool wantMfa = chosen.Contains("MFAEnabled");
                bool wantRoles = chosen.Contains("AssignedRoles");
                bool wantGroupCount = chosen.Contains("GroupCount");
                bool wantMembers = wantRoles || wantGroupCount;
                bool wantManager = chosen.Contains("ManagerUPN");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Entra ID users (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$select = 'id,displayName,givenName,surname,userPrincipalName,mail,mailNickname,accountEnabled,userType,createdDateTime,employeeId,department,companyName,jobTitle,officeLocation,mobilePhone,businessPhones,preferredLanguage,usageLocation,city,country,streetAddress,postalCode,state,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSamAccountName,onPremisesUserPrincipalName'");
                if (wantSignIn)
                    sb.AppendLine("$select += ',signInActivity'");
                sb.AppendLine("$users = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/users?$select=' + $select + '&$top=999'");
                sb.AppendLine("while ($uri -and ($maxUsers -lt 0 -or $users.Count -lt $maxUsers)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $users += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $users.Count -gt $maxUsers) { $users = $users[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} user(s).\" -f $users.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantMfa) sb.AppendLine("$mfaFail = 0");
                if (wantMembers) sb.AppendLine("$memFail = 0");
                sb.AppendLine("foreach ($u in $users) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $users.Count) }");
                sb.AppendLine("    $uid = [string]$u.id");
                sb.AppendLine("    $bp = ((@($u.businessPhones) | ForEach-Object { [string]$_ }) -join ',')");
                if (wantSignIn)
                    sb.AppendLine("    $ls = ''; try { if ($u.signInActivity) { $ls = [string]$u.signInActivity.lastSignInDateTime } } catch { }");
                if (wantMfa)
                {
                    sb.AppendLine("    $mf = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $mm = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"/authentication/methods\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        $strong = @(@($mm.value) | Where-Object { [string]$_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' })");
                    sb.AppendLine("        if ($strong.Count -gt 0) { $mf = 'Yes' } else { $mf = 'No' }");
                    sb.AppendLine("    } catch { $mfaFail++ }");
                }
                if (wantMembers)
                {
                    sb.AppendLine("    $ar = ''; $gc2 = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $tmo = @()");
                    sb.AppendLine("        $turi = \"https://graph.microsoft.com/v1.0/users/\" + $uid + \"/transitiveMemberOf?`$select=id,displayName\"");
                    sb.AppendLine("        while ($turi) { $tr = Invoke-RestMethod -Uri $turi -Headers $headers -Method Get -ErrorAction Stop; $tmo += @($tr.value); $turi = $tr.'@odata.nextLink' }");
                    sb.AppendLine("        $rn = @($tmo | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | ForEach-Object { [string]$_.displayName } | Where-Object { $_ -ne '' } | Sort-Object -Unique)");
                    sb.AppendLine("        $ar = ($rn -join ',')");
                    sb.AppendLine("        $gc2 = @($tmo | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.group' }).Count");
                    sb.AppendLine("    } catch { $memFail++ }");
                }
                if (wantManager)
                {
                    sb.AppendLine("    $mu = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $mg = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"/manager?`$select=userPrincipalName,mail\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        $mu = [string]$mg.userPrincipalName");
                    sb.AppendLine("        if (-not $mu) { $mu = [string]$mg.mail }");
                    sb.AppendLine("    } catch { }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        Id = $uid; DisplayName = $u.displayName; GivenName = $u.givenName; Surname = $u.surname;");
                sb.AppendLine("        UserPrincipalName = $u.userPrincipalName; MFAEnabled = " + (wantMfa ? "$mf" : "''") + "; Mail = $u.mail; MailNickname = $u.mailNickname;");
                sb.AppendLine("        AccountEnabled = $u.accountEnabled; UserType = $u.userType; CreatedDateTime = $u.createdDateTime;");
                sb.AppendLine("        LastSignInDateTime = " + (wantSignIn ? "$ls" : "''") + "; EmployeeId = $u.employeeId;");
                sb.AppendLine("        Department = $u.department; CompanyName = $u.companyName; JobTitle = $u.jobTitle; OfficeLocation = $u.officeLocation;");
                sb.AppendLine("        MobilePhone = $u.mobilePhone; BusinessPhones = $bp; PreferredLanguage = $u.preferredLanguage; UsageLocation = $u.usageLocation;");
                sb.AppendLine("        City = $u.city; Country = $u.country; StreetAddress = $u.streetAddress; PostalCode = $u.postalCode; State = $u.state;");
                sb.AppendLine("        OnPremisesSyncEnabled = $u.onPremisesSyncEnabled; OnPremisesImmutableId = $u.onPremisesImmutableId; OnPremisesDistinguishedName = $u.onPremisesDistinguishedName; OnPremisesDomainName = $u.onPremisesDomainName; OnPremisesSamAccountName = $u.onPremisesSamAccountName; OnPremisesUserPrincipalName = $u.onPremisesUserPrincipalName;");
                sb.AppendLine("        AssignedRoles = " + (wantRoles ? "$ar" : "''") + "; GroupCount = " + (wantGroupCount ? "$gc2" : "''") + "; ManagerUPN = " + (wantManager ? "$mu" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantMfa) sb.AppendLine("if ($mfaFail -gt 0) { Write-Host (\"WARNING: {0} MFA querie(s) failed (consent for UserAuthenticationMethod.Read.All?).\" -f $mfaFail) }");
                if (wantMembers) sb.AppendLine("if ($memFail -gt 0) { Write-Host (\"WARNING: {0} membership querie(s) failed (consent for RoleManagement.Read.Directory?).\" -f $memFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 2. AUTH METHODS
        // Get-MgUserAuthenticationMethod equivalent: one row per user with a
        // count per method type. Needs UserAuthenticationMethod.Read.All.
        private static AuditSection BuildAuthMethodsSection()
        {
            var section = new AuditSection(
                "entra-auth-methods",
                "Authentication methods (User)",
                "User authentication methods export",
                "Audit per-user authentication methods via Graph (Get-MgUserAuthenticationMethod equivalent): Microsoft Authenticator, SMS, voice, FIDO2, Windows Hello, passkey and Temporary Access Pass counts per user (slow per-user lookup).",
                "key",
                AuditScope.Graph);
            section.Category = "Standard Objects";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraAuthMethods.csv";

            var identity = new AuditOptionGroup("identity", "Identity", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("UserPrincipalName", true);
            identity.AddProp("DisplayName", true);
            section.AddGroup(identity);

            var methods = new AuditOptionGroup("methods", "Authentication methods (slow per-user lookup)", GroupMode.MultiCheck); methods.Columns = 2;
            methods.Hint = "One /authentication/methods query per user - slower on large tenants. Needs the UserAuthenticationMethod.Read.All consent. Each column is a registered-method count (phone numbers count for both SMS and Voice).";
            methods.Add(AuditOption.Prop("MicrosoftAuthenticator", true).MarkSlow());
            methods.Add(AuditOption.Prop("SMS", true).MarkSlow());
            methods.Add(AuditOption.Prop("Voice", true).MarkSlow());
            methods.Add(AuditOption.Prop("FIDO2", true).MarkSlow());
            methods.Add(AuditOption.Prop("WindowsHello", true).MarkSlow());
            methods.Add(AuditOption.Prop("Passkey", true).MarkSlow());
            methods.Add(AuditOption.Prop("TemporaryAccessPass", true).MarkSlow());
            section.AddGroup(methods);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "methods");
                if (chosen.Count == 0) chosen.Add("UserPrincipalName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Entra ID users + authentication methods (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$users = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName&$top=999'");
                sb.AppendLine("while ($uri -and ($maxUsers -lt 0 -or $users.Count -lt $maxUsers)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $users += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $users.Count -gt $maxUsers) { $users = $users[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} user(s).\" -f $users.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                sb.AppendLine("$authFail = 0");
                sb.AppendLine("foreach ($u in $users) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $users.Count) }");
                sb.AppendLine("    $uid = [string]$u.id");
                sb.AppendLine("    $ma = 0; $sms = 0; $voice = 0; $fido = 0; $wh = 0; $pk = 0; $tap = 0");
                sb.AppendLine("    try {");
                sb.AppendLine("        $mm = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"/authentication/methods\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("        foreach ($m in @($mm.value)) {");
                sb.AppendLine("            $t = [string]$m.'@odata.type'");
                sb.AppendLine("            if ($t -match 'microsoftAuthenticator') { $ma++ }");
                sb.AppendLine("            elseif ($t -match 'temporaryAccessPass') { $tap++ }");
                sb.AppendLine("            elseif ($t -match 'windowsHello') { $wh++ }");
                sb.AppendLine("            elseif ($t -match 'passkey') { $pk++ }");
                sb.AppendLine("            elseif ($t -match 'fido2') { $fido++ }");
                sb.AppendLine("            elseif ($t -match 'smsAuthentication') { $sms++ }");
                sb.AppendLine("            elseif ($t -match 'voiceAuthentication') { $voice++ }");
                sb.AppendLine("            elseif ($t -match 'phoneAuthentication') { $sms++; $voice++ }");
                sb.AppendLine("        }");
                sb.AppendLine("    } catch { $authFail++ }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        UserPrincipalName = $u.userPrincipalName; DisplayName = $u.displayName;");
                sb.AppendLine("        MicrosoftAuthenticator = $ma; SMS = $sms; Voice = $voice; FIDO2 = $fido;");
                sb.AppendLine("        WindowsHello = $wh; Passkey = $pk; TemporaryAccessPass = $tap");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($authFail -gt 0) { Write-Host (\"WARNING: {0} authentication-method querie(s) failed (consent for UserAuthenticationMethod.Read.All?).\" -f $authFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 2b. AUTH POLICIES
        // Org-wide authentication methods policy (which methods are enabled and
        // for whom) + SSPR/migration/registration-campaign state. SSPR method
        // detail, banned passwords and smart-lockout tuning are portal-only
        // (not in Graph v1.0). Needs Policy.Read.All (plus an
        // authentication-policy admin role for the auditor).
        private static AuditSection BuildAuthPoliciesSection()
        {
            var section = new AuditSection(
                "entra-auth-policies",
                "Authentication policies",
                "Authentication policies export",
                "Audit the org-wide authentication methods policy via Graph: per-method state and targeting, SSPR/migration state and registration campaign (per-user registrations live in Authentication methods).",
                "key",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraAuthPolicies.csv";

            var methods = new AuditOptionGroup("methods", "Method state & targeting", GroupMode.MultiCheck); methods.Columns = 2;
            methods.Hint = "One row per authentication method configuration. Selected groups are resolved to display names (cached lookups).";
            methods.AddProp("MethodName", true);
            methods.AddProp("State", true);
            methods.AddProp("TargetSummary", true);
            section.AddGroup(methods);

            var policy = new AuditOptionGroup("policy", "Policy state", GroupMode.MultiCheck); policy.Columns = 2;
            policy.Hint = "Tenant-level state repeated on every row. MigrationState shows Not reported when Graph omits it (legacy MFA/SSPR management retired Sep 2025). SSPR auth-method detail, banned passwords and smart-lockout tuning are portal-only (not exposed by Graph v1.0).";
            policy.AddProp("MigrationState", true);
            policy.AddProp("SsprAllowed", true);
            policy.AddProp("RegistrationCampaign", true);
            policy.AddProp("LastModified", true);
            section.AddGroup(policy);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "methods", "policy");
                if (chosen.Count == 0) chosen.Add("MethodName");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying authentication methods policy (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$pol = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("$sspr = ''");
                sb.AppendLine("try { $az = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy?$select=allowedToUseSSPR' -Headers $headers -Method Get -ErrorAction Stop; $sspr = [string]$az.allowedToUseSSPR } catch { Write-Host 'WARNING: authorizationPolicy query failed (consent for Policy.Read.All?).' }");
                sb.AppendLine("$camp = ''");
                sb.AppendLine("try { $rc = $pol.registrationEnforcement.authenticationMethodsRegistrationCampaign; if ($rc.state -eq 'enabled') { $tm = ((@($rc.includeTargets) | ForEach-Object { [string]$_.targetedAuthenticationMethod } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ','); $camp = 'Enabled (snooze ' + [string]$rc.snoozeDurationInDays + 'd, enforce: ' + [string]$rc.enforceRegistrationAfterAllowedSnoozes + ', methods: ' + $tm + ')' } else { $camp = 'Disabled' } } catch { }");
                sb.AppendLine("$gcache = @{}");
                sb.AppendLine("$script:gFail = 0");
                sb.AppendLine("function Format-PolicyTargets {");
                sb.AppendLine("    param($list)");
                sb.AppendLine("    $names = @()");
                sb.AppendLine("    foreach ($t in @($list)) {");
                sb.AppendLine("        $tid = [string]$t.id");
                sb.AppendLine("        if ($tid -eq 'all_users') { $names += 'All users' }");
                sb.AppendLine("        elseif ($tid) {");
                sb.AppendLine("            if (-not $gcache.ContainsKey($tid)) { $gn = $tid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $tid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $gn = [string]$o.displayName } } catch { $script:gFail++ }; $gcache[$tid] = $gn }");
                sb.AppendLine("            $nm = $gcache[$tid]; try { if ([bool]$t.isRegistrationRequired) { $nm = $nm + ' (registration required)' } } catch { }; $names += $nm");
                sb.AppendLine("        }");
                sb.AppendLine("    }");
                sb.AppendLine("    return (($names | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("}");
                sb.AppendLine("$mnames = @{ 'MicrosoftAuthenticator' = 'Microsoft Authenticator'; 'Sms' = 'SMS'; 'Voice' = 'Voice'; 'Fido2' = 'FIDO2'; 'WindowsHelloForBusiness' = 'Windows Hello'; 'TemporaryAccessPass' = 'Temporary Access Pass'; 'SoftwareOath' = 'Software OATH'; 'HardwareOath' = 'Hardware OATH'; 'Email' = 'Email (SSPR)'; 'X509Certificate' = 'Certificate (CBA)'; 'FederatedSingleFactor' = 'Federated SSO'; 'FederatedMultiFactor' = 'Federated MFA' }");
                sb.AppendLine("$mig = [string]$pol.policyMigrationState; if (-not $mig) { $mig = 'Not reported (legacy retired Sep 2025)' }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($c in @($pol.authenticationMethodConfigurations)) {");
                sb.AppendLine("    $mid = [string]$c.id; $mn = $mid; if ($mnames.ContainsKey($mid)) { $mn = $mnames[$mid] }");
                sb.AppendLine("    $tg = Format-PolicyTargets $c.includeTargets");
                sb.AppendLine("    try { $ex = Format-PolicyTargets $c.excludeTargets; if ($ex -ne '') { if ($tg -ne '') { $tg = $tg + ' except ' + $ex } else { $tg = 'All except ' + $ex } } } catch { }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        MethodName = $mn; State = $c.state; TargetSummary = $tg;");
                sb.AppendLine("        MigrationState = $mig; SsprAllowed = $sspr; RegistrationCampaign = $camp; LastModified = $pol.lastModifiedDateTime");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($script:gFail -gt 0) { Write-Host (\"WARNING: {0} target group(s) could not be resolved to names.\" -f $script:gFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 3. GROUPS
        // Get-MgGroup equivalent: one row per Entra ID group. Needs
        // Group.Read.All. OwnerCount / MemberCount are slow per-group
        // $count lookups, only queried when the column is checked.
        private static AuditSection BuildGroupsSection()
        {
            var section = new AuditSection(
                "entra-groups",
                "Groups",
                "Entra ID groups export",
                "Audit Entra ID groups via Graph (Get-MgGroup equivalent): type, mail/security flags, dynamic membership rule plus owner and member counts (slow per-group lookups).",
                "group",
                AuditScope.Graph);
            section.Category = "Standard Objects";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraGroups.csv";

            var identity = new AuditOptionGroup("identity", "Identity", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("GroupId", true);
            identity.AddProp("DisplayName", true);
            identity.AddProp("Description", true);
            identity.AddProp("Mail", true);
            identity.AddProp("MailNickname", true);
            identity.AddProp("CreatedDateTime", true);
            identity.AddProp("ProxyAddresses", true);
            section.AddGroup(identity);

            var type = new AuditOptionGroup("type", "Type & membership rule", GroupMode.MultiCheck); type.Columns = 2;
            type.AddProp("GroupType", true);
            type.AddProp("SecurityEnabled", true);
            type.AddProp("MailEnabled", true);
            type.AddProp("DynamicMembership", true);
            type.AddProp("MembershipRule", true);
            type.AddProp("IsRoleAssignable", true);
            section.AddGroup(type);

            var hybrid = new AuditOptionGroup("hybrid", "Hybrid sync", GroupMode.MultiCheck); hybrid.Columns = 2;
            hybrid.Hint = "Synced groups are often not directly portable - re-establish sync or convert to cloud-only in the target tenant.";
            hybrid.AddProp("OnPremisesSyncEnabled", true);
            hybrid.AddProp("OnPremisesSamAccountName", true);
            hybrid.AddProp("OnPremisesSecurityIdentifier", true);
            hybrid.AddProp("OnPremisesDistinguishedName", true);
            section.AddGroup(hybrid);

            var m365 = new AuditOptionGroup("m365", "Microsoft 365 specifics", GroupMode.MultiCheck); m365.Columns = 2;
            m365.Hint = "Only populated for Unified (Microsoft 365) groups. SharePointSiteUrl is one extra query per M365 group.";
            m365.AddProp("Visibility", true);
            m365.AddProp("PreferredDataLocation", true);
            m365.AddProp("AssignedLicenses", true);
            m365.AddProp("TeamsProvisioned", true);
            m365.Add(AuditOption.Prop("SharePointSiteUrl", false).MarkSlow());
            m365.AddProp("ExpirationDateTime", true);
            m365.AddProp("RenewedDateTime", true);
            m365.AddProp("SensitivityLabel", true);
            section.AddGroup(m365);

            var roles = new AuditOptionGroup("roles", "Directory roles held by the group", GroupMode.MultiCheck); roles.Columns = 1;
            roles.Hint = "Role-assignable groups (IsRoleAssignable) can hold directory roles - resolved locally from one roleAssignments fetch. Needs the RoleManagement.Read.Directory consent.";
            roles.AddProp("GroupRoleAssignments", true);
            section.AddGroup(roles);

            var counts = new AuditOptionGroup("members", "Owners & members (slow per-group lookup)", GroupMode.MultiCheck); counts.Columns = 2;
            counts.Hint = "UPN lists are exported for rebuild in the target tenant (counts alone only verify after the fact). NestedGroups is derived from the member enumeration (group-type members).";
            counts.Add(AuditOption.Prop("OwnerCount", true).MarkSlow());
            counts.Add(AuditOption.Prop("MemberCount", true).MarkSlow());
            counts.Add(AuditOption.Prop("Owners", true).MarkSlow());
            counts.Add(AuditOption.Prop("Members", true).MarkSlow());
            counts.Add(AuditOption.Prop("NestedGroups", false).MarkSlow());
            section.AddGroup(counts);

            var access = new AuditOptionGroup("access", "App & policy access", GroupMode.MultiCheck); access.Columns = 1;
            access.Hint = "AppRoles is one query per group (needs Directory.Read.All). CAPolicies is one shared Conditional Access fetch filtered locally (needs Policy.Read.All).";
            access.Add(AuditOption.Prop("AppRoles", false).MarkSlow());
            access.AddProp("CAPolicies", true);
            section.AddGroup(access);

            var pim = new AuditOptionGroup("pim", "PIM for Groups (slow lookup)", GroupMode.MultiCheck); pim.Columns = 2;
            pim.Hint = "Eligible vs active member/owner schedules from the PIM-for-Groups API (needs PrivilegedEligibilitySchedule.Read.AzureADGroup + PrivilegedAssignmentSchedule.Read.AzureADGroup). Empty unless PIM for Groups is used.";
            pim.Add(AuditOption.Prop("PimEligible", false).MarkSlow());
            pim.Add(AuditOption.Prop("PimActive", false).MarkSlow());
            section.AddGroup(pim);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "type", "hybrid", "m365", "roles", "members", "access", "pim");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantOwnerCount = chosen.Contains("OwnerCount");
                bool wantOwners = chosen.Contains("Owners");
                bool wantMemberCount = chosen.Contains("MemberCount");
                bool wantMembers = chosen.Contains("Members");
                bool wantNested = chosen.Contains("NestedGroups");
                bool wantMemberEnum = wantMembers || wantNested;
                bool wantCounts = (wantOwnerCount && !wantOwners) || (wantMemberCount && !wantMemberEnum);
                bool wantRoles = chosen.Contains("GroupRoleAssignments");
                bool wantLic = chosen.Contains("AssignedLicenses");
                bool wantSharePoint = chosen.Contains("SharePointSiteUrl");
                bool wantCA = chosen.Contains("CAPolicies");
                bool wantApps = chosen.Contains("AppRoles");
                bool wantPim = chosen.Contains("PimEligible") || chosen.Contains("PimActive");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Entra ID groups (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$groups = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description,mail,mailNickname,createdDateTime,proxyAddresses,groupTypes,securityEnabled,mailEnabled,membershipRule,visibility,preferredDataLocation,assignedLicenses,resourceProvisioningOptions,expirationDateTime,renewedDateTime,assignedLabels,isAssignableToRole,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesSecurityIdentifier,onPremisesDistinguishedName&$top=999'");
                sb.AppendLine("while ($uri -and ($maxUsers -lt 0 -or $groups.Count -lt $maxUsers)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $groups += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $groups.Count -gt $maxUsers) { $groups = $groups[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} group(s).\" -f $groups.Count)");
                if (wantRoles)
                {
                    sb.AppendLine("$roleMap = @{}");
                    sb.AppendLine("try {");
                    sb.AppendLine("    $ruri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'");
                    sb.AppendLine("    while ($ruri) { $rr = Invoke-RestMethod -Uri $ruri -Headers $headers -Method Get -ErrorAction Stop; foreach ($d in @($rr.value)) { $roleMap[[string]$d.id] = [string]$d.displayName }; $ruri = $rr.'@odata.nextLink' }");
                    sb.AppendLine("} catch { Write-Host 'WARNING: roleDefinitions query failed (consent for RoleManagement.Read.Directory?) - group roles will show raw IDs.' }");
                    sb.AppendLine("$allRoleAsg = @()");
                    sb.AppendLine("try {");
                    sb.AppendLine("    $rauri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'");
                    sb.AppendLine("    while ($rauri) { $ra = Invoke-RestMethod -Uri $rauri -Headers $headers -Method Get -ErrorAction Stop; $allRoleAsg += @($ra.value); $rauri = $ra.'@odata.nextLink' }");
                    sb.AppendLine("} catch { Write-Host 'WARNING: roleAssignments query failed (consent for RoleManagement.Read.Directory?) - group roles will be empty.' }");
                }
                if (wantLic)
                {
                    sb.AppendLine("$skuMap = @{}");
                    sb.AppendLine("try {");
                    sb.AppendLine("    $skuri = 'https://graph.microsoft.com/v1.0/subscribedSkus'");
                    sb.AppendLine("    while ($skuri) { $sk = Invoke-RestMethod -Uri $skuri -Headers $headers -Method Get -ErrorAction Stop; foreach ($s in @($sk.value)) { $skuMap[[string]$s.skuId] = [string]$s.skuPartNumber }; $skuri = $sk.'@odata.nextLink' }");
                    sb.AppendLine("} catch { Write-Host 'WARNING: subscribedSkus query failed - group licenses will show raw SKU IDs.' }");
                }
                if (wantCA)
                {
                    sb.AppendLine("$caps = @()");
                    sb.AppendLine("try {");
                    sb.AppendLine("    $cauri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'");
                    sb.AppendLine("    while ($cauri) { $ca = Invoke-RestMethod -Uri $cauri -Headers $headers -Method Get -ErrorAction Stop; $caps += @($ca.value); $cauri = $ca.'@odata.nextLink' }");
                    sb.AppendLine("    Write-Host (\"Retrieved {0} CA policie(s) for cross-reference.\" -f $caps.Count)");
                    sb.AppendLine("} catch { Write-Host 'WARNING: conditionalAccess policies query failed (consent for Policy.Read.All?) - CA cross-reference will be empty.' }");
                }
                if (wantPim)
                {
                    sb.AppendLine("$pimElig = @(); $pimAct = @()");
                    sb.AppendLine("try {");
                    sb.AppendLine("    $peuri = 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules'");
                    sb.AppendLine("    while ($peuri) { $pe = Invoke-RestMethod -Uri $peuri -Headers $headers -Method Get -ErrorAction Stop; $pimElig += @($pe.value); $peuri = $pe.'@odata.nextLink' }");
                    sb.AppendLine("    $pauri = 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules'");
                    sb.AppendLine("    while ($pauri) { $paa = Invoke-RestMethod -Uri $pauri -Headers $headers -Method Get -ErrorAction Stop; $pimAct += @($paa.value); $pauri = $paa.'@odata.nextLink' }");
                    sb.AppendLine("    Write-Host (\"Retrieved {0} PIM eligible + {1} PIM active group schedule(s).\" -f $pimElig.Count, $pimAct.Count)");
                    sb.AppendLine("} catch { Write-Host 'WARNING: PIM group schedules query failed (needs PrivilegedEligibilitySchedule.Read.AzureADGroup + PrivilegedAssignmentSchedule.Read.AzureADGroup) - PIM columns will be empty.' }");
                    sb.AppendLine("$pimCache = @{}");
                    sb.AppendLine("$script:pimResFail = 0");
                    sb.AppendLine("function Resolve-PimPrincipal {");
                    sb.AppendLine("    param($prId)");
                    sb.AppendLine("    if ($pimCache.ContainsKey($prId)) { return $pimCache[$prId] }");
                    sb.AppendLine("    $nm = $prId");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $prId + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        $nm = [string]$o.userPrincipalName; if (-not $nm) { $nm = [string]$o.displayName }");
                    sb.AppendLine("    } catch {");
                    sb.AppendLine("        try {");
                    sb.AppendLine("            $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $prId + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("            $nm = [string]$o.displayName");
                    sb.AppendLine("        } catch { $script:pimResFail++ }");
                    sb.AppendLine("    }");
                    sb.AppendLine("    $pimCache[$prId] = $nm");
                    sb.AppendLine("    return $nm");
                    sb.AppendLine("}");
                }
                if (wantApps)
                {
                    sb.AppendLine("$spCache = @{}");
                    sb.AppendLine("$script:spFail = 0");
                    sb.AppendLine("$appFail = 0");
                }
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantCounts || wantOwners || wantMemberEnum) sb.AppendLine("$memFail = 0");
                if (wantSharePoint) sb.AppendLine("$siteFail = 0");
                sb.AppendLine("foreach ($g in $groups) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $groups.Count) }");
                sb.AppendLine("    $gid = [string]$g.id");
                sb.AppendLine("    $gt = @($g.groupTypes)");
                sb.AppendLine("    $isDyn = 'No'; if ($gt -contains 'DynamicMembership') { $isDyn = 'Yes' }");
                sb.AppendLine("    $gtype = 'Other'");
                sb.AppendLine("    if ($gt -contains 'Unified') { $gtype = 'Microsoft 365' }");
                sb.AppendLine("    elseif ([bool]$g.securityEnabled -and [bool]$g.mailEnabled) { $gtype = 'Mail-enabled security' }");
                sb.AppendLine("    elseif ([bool]$g.securityEnabled) { $gtype = 'Security' }");
                sb.AppendLine("    elseif ([bool]$g.mailEnabled) { $gtype = 'Distribution' }");
                sb.AppendLine("    $mrule = ''; try { $mrule = [string]$g.membershipRule } catch { }");
                sb.AppendLine("    $isUni = $gt -contains 'Unified'");
                sb.AppendLine("    $pa = ((@($g.proxyAddresses) | ForEach-Object { [string]$_ }) -join ',')");
                sb.AppendLine("    $team = 'No'; try { if (@($g.resourceProvisioningOptions) -contains 'Team') { $team = 'Yes' } } catch { }");
                sb.AppendLine("    $labs = ((@($g.assignedLabels) | ForEach-Object { [string]$_.displayName } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')");
                if (wantLic)
                {
                    sb.AppendLine("    $lics = ((@($g.assignedLicenses) | ForEach-Object { $sk = [string]$_.skuId; if ($skuMap.ContainsKey($sk)) { $skuMap[$sk] } else { $sk } } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')");
                }
                if (wantOwners)
                {
                    sb.AppendLine("    $own = ''; $oc = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $ol = @(); $ouri = \"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"/owners?`$select=userPrincipalName,displayName&`$top=999\"");
                    sb.AppendLine("        while ($ouri) { $or = Invoke-RestMethod -Uri $ouri -Headers $headers -Method Get -ErrorAction Stop; $ol += @($or.value); $ouri = $or.'@odata.nextLink' }");
                    sb.AppendLine("        $own = ((@($ol) | ForEach-Object { $s = [string]$_.userPrincipalName; if (-not $s) { $s = [string]$_.displayName }; $s } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')");
                    sb.AppendLine("        $oc = $ol.Count");
                    sb.AppendLine("    } catch { $memFail++ }");
                }
                else if (wantOwnerCount)
                {
                    sb.AppendLine("    $oc = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $oc = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"/owners/`$count\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("    } catch { $memFail++ }");
                }
                if (wantMemberEnum)
                {
                    sb.AppendLine("    $mem = ''; $nest = ''; $mc = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $ml = @(); $muri = \"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"/members?`$select=id,displayName,userPrincipalName&`$top=999\"");
                    sb.AppendLine("        while ($muri) { $mr = Invoke-RestMethod -Uri $muri -Headers $headers -Method Get -ErrorAction Stop; $ml += @($mr.value); $muri = $mr.'@odata.nextLink' }");
                    sb.AppendLine("        $mem = ((@($ml) | ForEach-Object { $s = [string]$_.userPrincipalName; if (-not $s) { $s = [string]$_.displayName }; $s } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')");
                    sb.AppendLine("        $nest = ((@($ml | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { [string]$_.displayName } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                    sb.AppendLine("        $mc = $ml.Count");
                    sb.AppendLine("    } catch { $memFail++ }");
                }
                else if (wantMemberCount)
                {
                    sb.AppendLine("    $mc = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $mc = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"/members/`$count\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("    } catch { $memFail++ }");
                }
                if (wantSharePoint)
                {
                    sb.AppendLine("    $spurl = ''");
                    sb.AppendLine("    if ($isUni) { try { $sq = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"/sites/root?`$select=webUrl\") -Headers $headers -Method Get -ErrorAction Stop; $spurl = [string]$sq.webUrl } catch { $siteFail++ } }");
                }
                if (wantRoles)
                {
                    sb.AppendLine("    $gr = ((@($allRoleAsg | Where-Object { [string]$_.principalId -eq $gid } | ForEach-Object { $rid = [string]$_.roleDefinitionId; if ($roleMap.ContainsKey($rid)) { $roleMap[$rid] } else { $rid } } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                }
                if (wantCA)
                {
                    sb.AppendLine("    $cnames = @()");
                    sb.AppendLine("    foreach ($cp in $caps) { $hit = $false; try { if (@($cp.conditions.users.includeGroups) -contains $gid) { $hit = $true } } catch { }; try { if (@($cp.conditions.users.excludeGroups) -contains $gid) { $hit = $true } } catch { }; if ($hit) { $cn = [string]$cp.displayName; try { if ([string]$cp.state -ne 'enabled') { $cn = $cn + ' (disabled)' } } catch { }; $cnames += $cn } }");
                    sb.AppendLine("    $cap = ($cnames -join ',')");
                }
                if (wantApps)
                {
                    sb.AppendLine("    $ar2 = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $al = @(); $auri2 = \"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"/appRoleAssignments\"");
                    sb.AppendLine("        while ($auri2) { $ax = Invoke-RestMethod -Uri $auri2 -Headers $headers -Method Get -ErrorAction Stop; $al += @($ax.value); $auri2 = $ax.'@odata.nextLink' }");
                    sb.AppendLine("        $pairs = @()");
                    sb.AppendLine("        foreach ($ar in $al) {");
                    sb.AppendLine("            $rid = [string]$ar.resourceId; $rnm = [string]$ar.resourceDisplayName; if (-not $rnm) { $rnm = $rid }");
                    sb.AppendLine("            $rln = [string]$ar.appRoleId");
                    sb.AppendLine("            try {");
                    sb.AppendLine("                if (-not $spCache.ContainsKey($rid)) { $so = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $rid + \"?`$select=displayName,appRoles\") -Headers $headers -Method Get -ErrorAction Stop; $spCache[$rid] = $so }");
                    sb.AppendLine("                $so = $spCache[$rid]; if ($rnm -eq $rid -and $so.displayName) { $rnm = [string]$so.displayName }");
                    sb.AppendLine("                $m = @($so.appRoles | Where-Object { [string]$_.id -eq [string]$ar.appRoleId })[0]; if ($m) { $rln = [string]$m.displayName; if (-not $rln) { $rln = [string]$m.value } }");
                    sb.AppendLine("            } catch { $script:spFail++ }");
                    sb.AppendLine("            $pairs += $rnm + ': ' + $rln");
                    sb.AppendLine("        }");
                    sb.AppendLine("        $ar2 = (($pairs | Sort-Object -Unique) -join ',')");
                    sb.AppendLine("    } catch { $appFail++ }");
                }
                if (wantPim)
                {
                    sb.AppendLine("    $pe = ''; $pa2 = ''");
                    sb.AppendLine("    $el = @(); foreach ($s in @($pimElig | Where-Object { [string]$_.groupId -eq $gid })) { if ([string]$s.status -match 'Revoked|Canceled|Denied|Failed') { continue }; $mt2 = ''; try { $mt2 = [string]$s.memberType } catch { }; $el += (Resolve-PimPrincipal ([string]$s.principalId)) + ' (' + $mt2 + ')' }; if ($el.Count -gt 0) { $pe = (($el | Sort-Object -Unique) -join ',') }");
                    sb.AppendLine("    $ac = @(); foreach ($s in @($pimAct | Where-Object { [string]$_.groupId -eq $gid })) { if ([string]$s.status -match 'Revoked|Canceled|Denied|Failed') { continue }; $mt2 = ''; try { $mt2 = [string]$s.memberType } catch { }; $ac += (Resolve-PimPrincipal ([string]$s.principalId)) + ' (' + $mt2 + ')' }; if ($ac.Count -gt 0) { $pa2 = (($ac | Sort-Object -Unique) -join ',') }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        GroupId = $gid; DisplayName = $g.displayName; Description = $g.description; Mail = $g.mail; MailNickname = $g.mailNickname; CreatedDateTime = $g.createdDateTime; ProxyAddresses = $pa;");
                sb.AppendLine("        GroupType = $gtype; SecurityEnabled = $g.securityEnabled; MailEnabled = $g.mailEnabled; DynamicMembership = $isDyn; MembershipRule = $mrule; IsRoleAssignable = $g.isAssignableToRole;");
                sb.AppendLine("        OnPremisesSyncEnabled = $g.onPremisesSyncEnabled; OnPremisesSamAccountName = $g.onPremisesSamAccountName; OnPremisesSecurityIdentifier = $g.onPremisesSecurityIdentifier; OnPremisesDistinguishedName = $g.onPremisesDistinguishedName;");
                sb.AppendLine("        Visibility = $g.visibility; PreferredDataLocation = $g.preferredDataLocation; AssignedLicenses = " + (wantLic ? "$lics" : "''") + "; TeamsProvisioned = $team;");
                sb.AppendLine("        SharePointSiteUrl = " + (wantSharePoint ? "$spurl" : "''") + "; ExpirationDateTime = $g.expirationDateTime; RenewedDateTime = $g.renewedDateTime; SensitivityLabel = $labs;");
                sb.AppendLine("        GroupRoleAssignments = " + (wantRoles ? "$gr" : "''") + ";");
                sb.AppendLine("        OwnerCount = " + ((wantOwnerCount || wantOwners) ? "$oc" : "''") + "; MemberCount = " + ((wantMemberCount || wantMemberEnum) ? "$mc" : "''") + ";");
                sb.AppendLine("        Owners = " + (wantOwners ? "$own" : "''") + "; Members = " + (wantMembers ? "$mem" : "''") + "; NestedGroups = " + (wantNested ? "$nest" : "''") + ";");
                sb.AppendLine("        AppRoles = " + (wantApps ? "$ar2" : "''") + "; CAPolicies = " + (wantCA ? "$cap" : "''") + ";");
                sb.AppendLine("        PimEligible = " + (chosen.Contains("PimEligible") ? "$pe" : "''") + "; PimActive = " + (chosen.Contains("PimActive") ? "$pa2" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantCounts || wantOwners || wantMemberEnum) sb.AppendLine("if ($memFail -gt 0) { Write-Host (\"WARNING: {0} owner/member querie(s) failed (consent for Group.Read.All?).\" -f $memFail) }");
                if (wantSharePoint) sb.AppendLine("if ($siteFail -gt 0) { Write-Host (\"WARNING: {0} SharePoint site querie(s) failed.\" -f $siteFail) }");
                if (wantApps) sb.AppendLine("if ($appFail -gt 0) { Write-Host (\"WARNING: {0} app-role querie(s) failed (consent for Directory.Read.All?).\" -f $appFail) }");
                if (wantApps) sb.AppendLine("if ($script:spFail -gt 0) { Write-Host (\"WARNING: {0} app-role name(s) could not be resolved.\" -f $script:spFail) }");
                if (wantPim) sb.AppendLine("if ($script:pimResFail -gt 0) { Write-Host (\"WARNING: {0} PIM principal(s) could not be resolved.\" -f $script:pimResFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 4. DIRECTORY ROLES
        // Migration-ready role catalog: display names (portable across tenants,
        // unlike custom-role IDs) + full permission set for custom roles so they
        // can be recreated in the target tenant. Needs RoleManagement.Read.Directory.
        private static AuditSection BuildDirectoryRolesSection()
        {
            var section = new AuditSection(
                "entra-directory-roles",
                "Directory roles",
                "Directory roles export",
                "Audit built-in and custom directory roles via Graph: display name, description, built-in vs custom, and the full permission set of custom roles (allowedResourceActions) for target-tenant recreation.",
                "key",
                AuditScope.Graph);
            section.Category = "RBAC";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraDirectoryRoles.csv";

            var identity = new AuditOptionGroup("identity", "Role", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("RoleName", true);
            identity.AddProp("Description", true);
            identity.AddProp("RoleKind", true);
            section.AddGroup(identity);

            var perms = new AuditOptionGroup("permissions", "Custom-role permissions", GroupMode.MultiCheck); perms.Columns = 1;
            perms.Hint = "rolePermissions/allowedResourceActions, populated for custom roles only (built-in sets are fixed by Microsoft). Requested inline with the role list - no extra query.";
            perms.AddProp("AllowedActions", true);
            section.AddGroup(perms);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "permissions");
                if (chosen.Count == 0) chosen.Add("RoleName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                // rolePermissions is only requested when its column is checked
                // (heavy payload on tenants with many custom roles).
                bool wantPerms = chosen.Contains("AllowedActions");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying directory roles (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                // NOTE: roleDefinitions does not support $select/$top
                // (Request_UnsupportedQuery) - fetch full objects via paging;
                // rolePermissions rides along for the custom-role column.
                sb.AppendLine("$defs = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'");
                sb.AppendLine("while ($uri -and ($maxUsers -lt 0 -or $defs.Count -lt $maxUsers)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $defs += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $defs.Count -gt $maxUsers) { $defs = $defs[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} role definition(s).\" -f $defs.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($d in $defs) {");
                sb.AppendLine("    $kind = 'Custom'; if ([bool]$d.isBuiltIn) { $kind = 'Built-in' }");
                if (wantPerms)
                {
                    sb.AppendLine("    $pa = ''");
                    sb.AppendLine("    if ($kind -eq 'Custom') {");
                    sb.AppendLine("        $al = New-Object System.Collections.Generic.List[string]");
                    sb.AppendLine("        foreach ($rp in @($d.rolePermissions)) { foreach ($a in @($rp.allowedResourceActions)) { if ($a -and $al -notcontains [string]$a) { $al.Add([string]$a) } } }");
                    sb.AppendLine("        $pa = ($al -join ',')");
                    sb.AppendLine("    }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        RoleName = $d.displayName; Description = $d.description; RoleKind = $kind;");
                sb.AppendLine("        AllowedActions = " + (wantPerms ? "$pa" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 5. ROLE ASSIGNMENTS
        // One row per assignment across the three feeds (permanent active, PIM
        // eligible, PIM scheduled-active). Principals are resolved to portable
        // names (UPN / display name / app name), scopes to 'Tenant-wide' or the
        // AU display name. Needs RoleManagement.Read.Directory (+
        // Directory.Read.All for service-principal names,
        // AdministrativeUnit.Read.All for AU names).
        private static AuditSection BuildRoleAssignmentsSection()
        {
            var section = new AuditSection(
                "entra-role-assignments",
                "Role assignments",
                "Role assignments export",
                "Audit directory role assignments via Graph (active, PIM eligible and PIM active): portable principal names, principal type, assignment type, scope display name and schedule dates (slow principal lookups).",
                "key",
                AuditScope.Graph);
            section.Category = "RBAC";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraRoleAssignments.csv";

            var assignment = new AuditOptionGroup("assignment", "Assignment", GroupMode.MultiCheck); assignment.Columns = 2;
            assignment.Hint = "Principals are resolved per assignment (user UPN, group display name, app name) - slower on tenants with many assignments. Object IDs alone are tenant-specific and not exported.";
            assignment.Add(AuditOption.Prop("RoleName", true));
            assignment.Add(AuditOption.Prop("PrincipalName", true).MarkSlow());
            assignment.Add(AuditOption.Prop("PrincipalType", true).MarkSlow());
            assignment.AddProp("AssignmentType", true);
            assignment.AddProp("IsPermanent", true);
            assignment.AddProp("Scope", true);
            section.AddGroup(assignment);

            var schedule = new AuditOptionGroup("schedule", "Schedule", GroupMode.MultiCheck); schedule.Columns = 2;
            schedule.Hint = "From the PIM scheduleInfo; empty for permanent active assignments.";
            schedule.AddProp("StartDateTime", true);
            schedule.AddProp("EndDateTime", true);
            section.AddGroup(schedule);

            var request = new AuditOptionGroup("request", "Justification & ticket (slow per-assignment lookup)", GroupMode.MultiCheck); request.Columns = 1;
            request.Hint = "Best effort from the PIM schedule requests (one query per assignment) - only populated when your org tracks justification/ticket info. Slower on large tenants.";
            request.Add(AuditOption.Prop("Justification", false).MarkSlow());
            request.Add(AuditOption.Prop("TicketInfo", false).MarkSlow());
            section.AddGroup(request);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "assignment", "schedule", "request");
                if (chosen.Count == 0) chosen.Add("RoleName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantReq = chosen.Contains("Justification") || chosen.Contains("TicketInfo");
                bool wantJust = chosen.Contains("Justification");
                bool wantTick = chosen.Contains("TicketInfo");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying directory roles, AUs and assignments (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$roleMap = @{}");
                sb.AppendLine("$ruri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'");
                sb.AppendLine("while ($ruri) { $rr = Invoke-RestMethod -Uri $ruri -Headers $headers -Method Get -ErrorAction Stop; foreach ($d in @($rr.value)) { $roleMap[[string]$d.id] = [string]$d.displayName }; $ruri = $rr.'@odata.nextLink' }");
                sb.AppendLine("$auMap = @{}");
                sb.AppendLine("try {");
                sb.AppendLine("    $auri = 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName&$top=999'");
                sb.AppendLine("    while ($auri) { $ar = Invoke-RestMethod -Uri $auri -Headers $headers -Method Get -ErrorAction Stop; foreach ($a in @($ar.value)) { $auMap[[string]$a.id] = [string]$a.displayName }; $auri = $ar.'@odata.nextLink' }");
                sb.AppendLine("} catch { Write-Host 'WARNING: administrativeUnits query failed (consent for AdministrativeUnit.Read.All?) - AU scopes will show raw IDs.' }");
                sb.AppendLine("$pcache = @{}");
                sb.AppendLine("$script:resFail = 0");
                sb.AppendLine("function Resolve-Principal {");
                sb.AppendLine("    param($prId)");
                sb.AppendLine("    if ($pcache.ContainsKey($prId)) { return $pcache[$prId] }");
                sb.AppendLine("    $nm = $prId; $tp = 'Unknown'");
                sb.AppendLine("    try {");
                sb.AppendLine("        $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $prId + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("        $nm = [string]$o.userPrincipalName; if (-not $nm) { $nm = [string]$o.displayName }; $tp = 'User'");
                sb.AppendLine("    } catch {");
                sb.AppendLine("        try {");
                sb.AppendLine("            $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $prId + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("            $nm = [string]$o.displayName; $tp = 'Group'");
                sb.AppendLine("        } catch {");
                sb.AppendLine("            try {");
                sb.AppendLine("                $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $prId + \"?`$select=displayName,appId\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("                $nm = [string]$o.displayName; if ($o.appId) { $nm = $nm + ' (' + [string]$o.appId + ')' }; $tp = 'ServicePrincipal'");
                sb.AppendLine("            } catch { $script:resFail++ }");
                sb.AppendLine("        }");
                sb.AppendLine("    }");
                sb.AppendLine("    $pp = [pscustomobject]@{ Name = $nm; Type = $tp }");
                sb.AppendLine("    $pcache[$prId] = $pp");
                sb.AppendLine("    return $pp");
                sb.AppendLine("}");
                sb.AppendLine("$items = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$puri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'");
                sb.AppendLine("while ($puri) { $pr = Invoke-RestMethod -Uri $puri -Headers $headers -Method Get -ErrorAction Stop; foreach ($a in @($pr.value)) { $items.Add([pscustomobject]@{ RD = [string]$a.roleDefinitionId; PR = [string]$a.principalId; SC = [string]$a.directoryScopeId; AT = 'Active'; ST = ''; EN = ''; ET = '' }) }; $puri = $pr.'@odata.nextLink' }");
                sb.AppendLine("Write-Host (\"Retrieved {0} active assignment(s).\" -f $items.Count)");
                sb.AppendLine("$euri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules'");
                sb.AppendLine("$elig = 0");
                sb.AppendLine("while ($euri) { $er = Invoke-RestMethod -Uri $euri -Headers $headers -Method Get -ErrorAction Stop; foreach ($a in @($er.value)) { if ([string]$a.status -eq 'Revoked') { continue }; $st = ''; $en = ''; $et = ''; try { $st = [string]$a.scheduleInfo.startDateTime } catch { }; try { $en = [string]$a.scheduleInfo.expiration.endDateTime } catch { }; try { $et = [string]$a.scheduleInfo.expiration.type } catch { }; $items.Add([pscustomobject]@{ RD = [string]$a.roleDefinitionId; PR = [string]$a.principalId; SC = [string]$a.directoryScopeId; AT = 'Eligible (PIM)'; ST = $st; EN = $en; ET = $et }); $elig++ }; $euri = $er.'@odata.nextLink' }");
                sb.AppendLine("Write-Host (\"Retrieved {0} PIM eligible schedule(s).\" -f $elig)");
                sb.AppendLine("$suri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules'");
                sb.AppendLine("$act = 0");
                sb.AppendLine("while ($suri) { $sr = Invoke-RestMethod -Uri $suri -Headers $headers -Method Get -ErrorAction Stop; foreach ($a in @($sr.value)) { if ([string]$a.status -eq 'Revoked') { continue }; $st = ''; $en = ''; $et = ''; try { $st = [string]$a.scheduleInfo.startDateTime } catch { }; try { $en = [string]$a.scheduleInfo.expiration.endDateTime } catch { }; try { $et = [string]$a.scheduleInfo.expiration.type } catch { }; $items.Add([pscustomobject]@{ RD = [string]$a.roleDefinitionId; PR = [string]$a.principalId; SC = [string]$a.directoryScopeId; AT = 'Active (PIM)'; ST = $st; EN = $en; ET = $et }); $act++ }; $suri = $sr.'@odata.nextLink' }");
                sb.AppendLine("Write-Host (\"Retrieved {0} PIM active schedule(s).\" -f $act)");
                sb.AppendLine("if ($maxUsers -ge 0 -and $items.Count -gt $maxUsers) { $items = $items[0..($maxUsers - 1)] }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantReq) sb.AppendLine("$reqFail = 0");
                sb.AppendLine("foreach ($it in $items) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $items.Count) }");
                sb.AppendLine("    $rn = $it.RD; if ($roleMap.ContainsKey($it.RD)) { $rn = $roleMap[$it.RD] }");
                sb.AppendLine("    $pp = Resolve-Principal $it.PR");
                sb.AppendLine("    $scope = $it.SC");
                sb.AppendLine("    if ($scope -eq '/') { $scope = 'Tenant-wide (/)' }");
                sb.AppendLine("    elseif ($scope -match '^/administrativeUnits/([^/]+)$') { $aid = $matches[1]; if ($auMap.ContainsKey($aid)) { $scope = 'AU: ' + $auMap[$aid] } else { $scope = 'AU: ' + $aid } }");
                sb.AppendLine("    $perm = 'Yes'; if ($it.AT -ne 'Active') { $perm = 'No'; if ($it.ET -eq 'noExpiration' -or $it.ET -eq '') { $perm = 'Yes' } }");
                if (wantReq)
                {
                    sb.AppendLine("    $just = ''; $tick = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $fq = [uri]::EscapeDataString(\"principalId eq '\" + $it.PR + \"'\")");
                    sb.AppendLine("        $cands = @()");
                    sb.AppendLine("        foreach ($feed in @('roleAssignmentScheduleRequests', 'roleEligibilityScheduleRequests')) {");
                    sb.AppendLine("            $quri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/' + $feed + '?$filter=' + $fq");
                    sb.AppendLine("            $qr = Invoke-RestMethod -Uri $quri -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("            $cands += @($qr.value)");
                    sb.AppendLine("        }");
                    sb.AppendLine("        $best = @($cands | Where-Object { [string]$_.roleDefinitionId -eq $it.RD } | Sort-Object { [string]$_.createdDateTime } -Descending)[0]");
                    sb.AppendLine("        if ($best) { $just = [string]$best.justification; $tn = [string]$best.ticketInfo.ticketNumber; $ts = [string]$best.ticketInfo.ticketSystem; $tick = $tn; if ($ts) { $tick = $tick + ' (' + $ts + ')' } }");
                    sb.AppendLine("    } catch { $reqFail++ }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        RoleName = $rn; PrincipalName = $pp.Name; PrincipalType = $pp.Type; AssignmentType = $it.AT; IsPermanent = $perm; Scope = $scope;");
                sb.AppendLine("        StartDateTime = $it.ST; EndDateTime = $it.EN;");
                sb.AppendLine("        Justification = " + (wantJust ? "$just" : "''") + "; TicketInfo = " + (wantTick ? "$tick" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($script:resFail -gt 0) { Write-Host (\"WARNING: {0} principal(s) could not be resolved (consent for Directory.Read.All?).\" -f $script:resFail) }");
                if (wantReq) sb.AppendLine("if ($reqFail -gt 0) { Write-Host (\"WARNING: {0} justification querie(s) failed (consent for RoleManagement.Read.Directory?).\" -f $reqFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 6. PIM ROLE SETTINGS
        // One row per directory-role PIM policy: activation duration, approval
        // + approvers, justification/ticket/MFA gates and notification summary.
        // Needs RoleManagement.Read.Directory.
        private static AuditSection BuildPimSettingsSection()
        {
            var section = new AuditSection(
                "entra-pim-settings",
                "PIM settings",
                "PIM settings export",
                "Audit PIM policies for directory roles via Graph: activation duration, approval and approvers, justification/ticket/MFA requirements and notification settings (one rules query per policy).",
                "key",
                AuditScope.Graph);
            section.Category = "Identity Governance";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraPimSettings.csv";

            var role = new AuditOptionGroup("role", "Role", GroupMode.MultiCheck); role.Columns = 1;
            role.AddProp("RoleName", true);
            section.AddGroup(role);

            var activation = new AuditOptionGroup("activation", "Activation", GroupMode.MultiCheck); activation.Columns = 2;
            activation.Hint = "From the EndUser rules of each role policy. Approvers are resolved to UPNs (users) or display names (groups) - slower on tenants with many policies.";
            activation.AddProp("ActivationDuration", true);
            activation.AddProp("ApprovalRequired", true);
            activation.Add(AuditOption.Prop("Approvers", true).MarkSlow());
            section.AddGroup(activation);

            var requirements = new AuditOptionGroup("requirements", "Activation requirements", GroupMode.MultiCheck); requirements.Columns = 2;
            requirements.Hint = "From the EndUser enablement rule (MultiFactorAuthentication / Justification / Ticketing).";
            requirements.AddProp("RequireJustification", true);
            requirements.AddProp("RequireTicket", true);
            requirements.AddProp("RequireMFA", true);
            section.AddGroup(requirements);

            var notifications = new AuditOptionGroup("notifications", "Notifications", GroupMode.MultiCheck); notifications.Columns = 1;
            notifications.Hint = "RecipientType/NotificationType per rule ('/default' when default recipients are used, '+names' for additionally configured recipients, resolved to UPNs). Identical entries across rules are deduped.";
            notifications.AddProp("NotificationSummary", true);
            section.AddGroup(notifications);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "role", "activation", "requirements", "notifications");
                if (chosen.Count == 0) chosen.Add("RoleName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantApprovers = chosen.Contains("Approvers");
                bool wantNotifs = chosen.Contains("NotificationSummary");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying PIM role policies (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$roleMap = @{}");
                sb.AppendLine("$ruri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'");
                sb.AppendLine("while ($ruri) { $rr = Invoke-RestMethod -Uri $ruri -Headers $headers -Method Get -ErrorAction Stop; foreach ($d in @($rr.value)) { $roleMap[[string]$d.id] = [string]$d.displayName }; $ruri = $rr.'@odata.nextLink' }");
                sb.AppendLine("$pols = @()");
                sb.AppendLine("$puri = 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole'''");
                sb.AppendLine("while ($puri) { $pr2 = Invoke-RestMethod -Uri $puri -Headers $headers -Method Get -ErrorAction Stop; $pols += @($pr2.value); $puri = $pr2.'@odata.nextLink' }");
                sb.AppendLine("$asgMap = @{}");
                sb.AppendLine("try {");
                sb.AppendLine("    $quri = 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole'''");
                sb.AppendLine("    while ($quri) { $qa = Invoke-RestMethod -Uri $quri -Headers $headers -Method Get -ErrorAction Stop; foreach ($a in @($qa.value)) { $asgMap[[string]$a.policyId] = [string]$a.roleDefinitionId }; $quri = $qa.'@odata.nextLink' }");
                sb.AppendLine("} catch { Write-Host 'WARNING: policyAssignments query failed (consent for RoleManagement.Read.Directory?) - roles will show policy IDs.' }");
                sb.AppendLine("if ($maxUsers -ge 0 -and $pols.Count -gt $maxUsers) { $pols = $pols[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} directory-role policies.\" -f $pols.Count)");
                sb.AppendLine("$ncache = @{}");
                sb.AppendLine("$script:nameFail = 0");
                sb.AppendLine("function Resolve-PolicyName {");
                sb.AppendLine("    param($aid)");
                sb.AppendLine("    if ($ncache.ContainsKey($aid)) { return $ncache[$aid] }");
                sb.AppendLine("    $nm = $aid");
                sb.AppendLine("    if ($aid -like 'group:*') {");
                sb.AppendLine("        try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $aid.Substring(6) + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; $nm = [string]$o.displayName + ' (group)' } catch { $script:nameFail++ }");
                sb.AppendLine("    } else {");
                sb.AppendLine("        try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $aid + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop; $nm = [string]$o.userPrincipalName; if (-not $nm) { $nm = [string]$o.displayName } } catch { try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $aid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; $nm = [string]$o.displayName + ' (group)' } catch { $script:nameFail++ } }");
                sb.AppendLine("    }");
                sb.AppendLine("    $ncache[$aid] = $nm");
                sb.AppendLine("    return $nm");
                sb.AppendLine("}");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                sb.AppendLine("$ruleFail = 0");
                sb.AppendLine("foreach ($p in $pols) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $pols.Count) }");
                sb.AppendLine("    $pid2 = [string]$p.id");
                sb.AppendLine("    $rd = ''; if ($asgMap.ContainsKey($pid2)) { $rd = $asgMap[$pid2] }");
                sb.AppendLine("    $rn = $pid2; if ($rd -ne '') { $rn = $rd; if ($roleMap.ContainsKey($rd)) { $rn = $roleMap[$rd] } }");
                sb.AppendLine("    $actDur = ''; $appr = 'No'; $apprs = @(); $just = 'No'; $tick = 'No'; $mfa = 'No'; $notifs = @()");
                sb.AppendLine("    try {");
                sb.AppendLine("        $rules = @()");
                sb.AppendLine("        $ruri2 = \"https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/\" + $pid2 + \"/rules\"");
                sb.AppendLine("        while ($ruri2) { $rx = Invoke-RestMethod -Uri $ruri2 -Headers $headers -Method Get -ErrorAction Stop; $rules += @($rx.value); $ruri2 = $rx.'@odata.nextLink' }");
                sb.AppendLine("        foreach ($rule in $rules) {");
                sb.AppendLine("            $rt = [string]$rule.'@odata.type'");
                sb.AppendLine("            $caller = ''; try { $caller = [string]$rule.target.caller } catch { }");
                sb.AppendLine("            if ($rt -match 'ExpirationRule' -and $caller -eq 'EndUser') { if ($rule.maximumDuration) { $actDur = [string]$rule.maximumDuration } }");
                sb.AppendLine("            elseif ($rt -match 'ApprovalRule' -and $caller -eq 'EndUser') {");
                sb.AppendLine("                try { if ($rule.setting.isApprovalRequired) { $appr = 'Yes' } } catch { }");
                if (wantApprovers)
                {
                    sb.AppendLine("                try { foreach ($st in @($rule.setting.approvalStages)) { foreach ($a in @($st.primaryApprovers)) { $aid = ''; if ($a.userId) { $aid = [string]$a.userId } elseif ($a.groupId) { $aid = 'group:' + [string]$a.groupId }; if ($aid -ne '') { $apprs += Resolve-PolicyName $aid } } } } catch { }");
                }
                sb.AppendLine("            }");
                sb.AppendLine("            elseif ($rt -match 'EnablementRule' -and $caller -eq 'EndUser') {");
                sb.AppendLine("                $er = @($rule.enabledRules); if ($er -contains 'Justification') { $just = 'Yes' }; if ($er -contains 'Ticketing') { $tick = 'Yes' }; if ($er -contains 'MultiFactorAuthentication') { $mfa = 'Yes' }");
                sb.AppendLine("            }");
                sb.AppendLine("            elseif ($rt -match 'NotificationRule') {");
                if (wantNotifs)
                {
                    sb.AppendLine("                try { $nt = [string]$rule.recipientType + '/' + [string]$rule.notificationType; if ($rule.isDefaultRecipientsEnabled) { $nt = $nt + '/default' }; $rn2 = @(); foreach ($nid in @($rule.notificationRecipients)) { if ($nid) { $rn2 += Resolve-PolicyName ([string]$nid) } }; if ($rn2.Count -gt 0) { $nt = $nt + ' (+' + (($rn2 | Sort-Object -Unique) -join ', ') + ')' }; $notifs += $nt } catch { }");
                }
                else
                {
                    sb.AppendLine("                try { $nt = [string]$rule.recipientType + '/' + [string]$rule.notificationType; if ($rule.isDefaultRecipientsEnabled) { $nt = $nt + '/default' }; $notifs += $nt } catch { }");
                }
                sb.AppendLine("            }");
                sb.AppendLine("        }");
                sb.AppendLine("    } catch { $ruleFail++ }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        RoleName = $rn; ActivationDuration = $actDur; ApprovalRequired = $appr; Approvers = " + (wantApprovers ? "($apprs -join ',')" : "''") + ";");
                sb.AppendLine("        RequireJustification = $just; RequireTicket = $tick; RequireMFA = $mfa; NotificationSummary = (($notifs | Sort-Object -Unique) -join ',')");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($ruleFail -gt 0) { Write-Host (\"WARNING: {0} policie(s) without readable rules (consent for RoleManagement.Read.Directory?).\" -f $ruleFail) }");
                sb.AppendLine("if ($script:nameFail -gt 0) { Write-Host (\"WARNING: {0} approver(s) could not be resolved.\" -f $script:nameFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 7. ADMINISTRATIVE UNITS
        // AU inventory with membership rules + the active role assignments scoped
        // to each AU (resolved locally from a single roleAssignments fetch).
        // Needs AdministrativeUnit.Read.All (+ RoleManagement.Read.Directory for
        // the scoped assignments).
        private static AuditSection BuildAdminUnitsSection()
        {
            var section = new AuditSection(
                "entra-admin-units",
                "Administrative units",
                "Administrative units export",
                "Audit Entra ID administrative units via Graph: members by type, AU-scoped role assignments (active + PIM) and access-review cross-reference.",
                "group",
                AuditScope.Graph);
            section.Category = "RBAC";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraAdminUnits.csv";

            var identity = new AuditOptionGroup("identity", "Unit", GroupMode.MultiCheck); identity.Columns = 2;
            identity.Hint = "Graph returns null Visibility/MembershipType when the defaults apply - the export shows the effective values (Public, Assigned). Graph v1.0 exposes no creation date or provisioning source on AUs: automation-created units must be re-established by that automation.";
            identity.AddProp("Id", true);
            identity.AddProp("DisplayName", true);
            identity.AddProp("Description", true);
            identity.AddProp("Visibility", true);
            section.AddGroup(identity);

            var rule = new AuditOptionGroup("rule", "Dynamic membership", GroupMode.MultiCheck); rule.Columns = 2;
            rule.Hint = "Dynamic AU rules target users; the raw rule string is exported precisely. MembershipRule is only set on dynamic units.";
            rule.AddProp("MembershipType", true);
            rule.AddProp("MembershipRule", true);
            rule.AddProp("RuleProcessingState", true);
            section.AddGroup(rule);

            var restricted = new AuditOptionGroup("restricted", "Restricted management", GroupMode.MultiCheck); restricted.Columns = 1;
            restricted.Hint = "Restricted AUs limit even Global Admins to role holders scoped to the unit. Immutable once set.";
            restricted.AddProp("RestrictedManagement", true);
            section.AddGroup(restricted);

            var auMembers = new AuditOptionGroup("auMembers", "Members by type (slow per-unit lookup)", GroupMode.MultiCheck); auMembers.Columns = 1;
            auMembers.Hint = "One members query per unit, split by object type. Note: a group listed here means the group object is in scope - its members are NOT implicitly covered by AU-scoped role assignments.";
            auMembers.Add(AuditOption.Prop("UserMembers", true).MarkSlow());
            auMembers.Add(AuditOption.Prop("GroupMembers", true).MarkSlow());
            auMembers.Add(AuditOption.Prop("DeviceMembers", true).MarkSlow());
            section.AddGroup(auMembers);

            var roles = new AuditOptionGroup("roles", "Scoped role assignments (slow per-unit lookup)", GroupMode.MultiCheck); roles.Columns = 1;
            roles.Hint = "The real payload: every assignment scoped to this unit (active via scopedRoleMembers plus PIM eligible/active from the shared schedules). An AU with none is nearly pointless to migrate.";
            roles.Add(AuditOption.Prop("AssignedRoles", true).MarkSlow());
            roles.Add(AuditOption.Prop("AssignmentCount", true).MarkSlow());
            roles.Add(AuditOption.Prop("AssignmentDetails", true).MarkSlow());
            section.AddGroup(roles);

            var reviews = new AuditOptionGroup("reviews", "Access reviews", GroupMode.MultiCheck); reviews.Columns = 1;
            reviews.Hint = "One shared access-reviews fetch matched locally per unit (needs AccessReview.Read.All). CA policies cannot scope to AUs.";
            reviews.AddProp("AccessReviews", true);
            section.AddGroup(reviews);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "rule", "restricted", "auMembers", "roles", "reviews");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantMembers = chosen.Contains("UserMembers") || chosen.Contains("GroupMembers") || chosen.Contains("DeviceMembers");
                bool wantAsg = chosen.Contains("AssignedRoles") || chosen.Contains("AssignmentCount") || chosen.Contains("AssignmentDetails");
                bool wantSched = chosen.Contains("AssignmentDetails");
                bool wantReviews = chosen.Contains("AccessReviews");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying administrative units (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$aus = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName,description,visibility,membershipType,membershipRule,membershipRuleProcessingState,isMemberManagementRestricted&$top=999'");
                sb.AppendLine("while ($uri -and ($maxUsers -lt 0 -or $aus.Count -lt $maxUsers)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $aus += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $aus.Count -gt $maxUsers) { $aus = $aus[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} administrative unit(s).\" -f $aus.Count)");
                if (wantAsg)
                {
                    sb.AppendLine("$roleMap = @{}");
                    sb.AppendLine("try {");
                    sb.AppendLine("    $ruri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'");
                    sb.AppendLine("    while ($ruri) { $rr = Invoke-RestMethod -Uri $ruri -Headers $headers -Method Get -ErrorAction Stop; foreach ($d in @($rr.value)) { $roleMap[[string]$d.id] = [string]$d.displayName }; $ruri = $rr.'@odata.nextLink' }");
                    sb.AppendLine("} catch { Write-Host 'WARNING: roleDefinitions query failed (consent for RoleManagement.Read.Directory?) - scoped roles will show raw IDs.' }");
                    sb.AppendLine("$pcache = @{}");
                    sb.AppendLine("$script:resFail = 0");
                    sb.AppendLine("function Resolve-AuPrincipal {");
                    sb.AppendLine("    param($prId)");
                    sb.AppendLine("    if ($pcache.ContainsKey($prId)) { return $pcache[$prId] }");
                    sb.AppendLine("    $nm = $prId; $tp = 'Other'");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $prId + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        $nm = [string]$o.userPrincipalName; if (-not $nm) { $nm = [string]$o.displayName }; $tp = 'User'");
                    sb.AppendLine("    } catch {");
                    sb.AppendLine("        try {");
                    sb.AppendLine("            $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $prId + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("            $nm = [string]$o.displayName; $tp = 'Group'");
                    sb.AppendLine("        } catch {");
                    sb.AppendLine("            try {");
                    sb.AppendLine("                $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $prId + \"?`$select=displayName,appId\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("                $nm = [string]$o.displayName; if ($o.appId) { $nm = $nm + ' (' + [string]$o.appId + ')' }; $tp = 'ServicePrincipal'");
                    sb.AppendLine("            } catch { $script:resFail++ }");
                    sb.AppendLine("        }");
                    sb.AppendLine("    }");
                    sb.AppendLine("    $pp = [pscustomobject]@{ Name = $nm; Type = $tp }");
                    sb.AppendLine("    $pcache[$prId] = $pp");
                    sb.AppendLine("    return $pp");
                    sb.AppendLine("}");
                }
                if (wantSched)
                {
                    sb.AppendLine("$auElig = @(); $auAct = @()");
                    sb.AppendLine("try {");
                    sb.AppendLine("    $euri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules'");
                    sb.AppendLine("    while ($euri) { $er = Invoke-RestMethod -Uri $euri -Headers $headers -Method Get -ErrorAction Stop; $auElig += @($er.value); $euri = $er.'@odata.nextLink' }");
                    sb.AppendLine("    $suri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules'");
                    sb.AppendLine("    while ($suri) { $sr = Invoke-RestMethod -Uri $suri -Headers $headers -Method Get -ErrorAction Stop; $auAct += @($sr.value); $suri = $sr.'@odata.nextLink' }");
                    sb.AppendLine("} catch { Write-Host 'WARNING: PIM schedules query failed (consent for RoleManagement.Read.Directory?) - eligible/active detail will be missing.' }");
                }
                if (wantReviews)
                {
                    sb.AppendLine("$defs = @()");
                    sb.AppendLine("try {");
                    sb.AppendLine("    $duri = 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions'");
                    sb.AppendLine("    while ($duri) { $dr = Invoke-RestMethod -Uri $duri -Headers $headers -Method Get -ErrorAction Stop; $defs += @($dr.value); $duri = $dr.'@odata.nextLink' }");
                    sb.AppendLine("    Write-Host (\"Retrieved {0} access review definition(s) for cross-reference.\" -f $defs.Count)");
                    sb.AppendLine("} catch { Write-Host 'WARNING: accessReviews query failed (consent for AccessReview.Read.All?) - review cross-reference will be empty.' }");
                }
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantMembers) sb.AppendLine("$memFail = 0");
                if (wantAsg) sb.AppendLine("$scFail = 0");
                sb.AppendLine("foreach ($u in $aus) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $aus.Count) }");
                sb.AppendLine("    $auid = [string]$u.id");
                sb.AppendLine("    $mrule = ''; try { $mrule = [string]$u.membershipRule } catch { }");
                sb.AppendLine("    $rps = ''; try { $rps = [string]$u.membershipRuleProcessingState } catch { }");
                sb.AppendLine("    $vis = [string]$u.visibility; if (-not $vis) { $vis = 'Public (default)' }");
                sb.AppendLine("    $mt = [string]$u.membershipType; if (-not $mt) { if ($mrule -ne '') { $mt = 'dynamic' } else { $mt = 'assigned' } }; if ($mt.Length -gt 0) { $mt = $mt.Substring(0, 1).ToUpper() + $mt.Substring(1) }");
                sb.AppendLine("    $rm = 'No'; try { if ([bool]$u.isMemberManagementRestricted) { $rm = 'Yes' } } catch { }");
                if (wantMembers)
                {
                    sb.AppendLine("    $um = ''; $gm = ''; $dm = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $ml = @(); $muri = \"https://graph.microsoft.com/v1.0/directory/administrativeUnits/\" + $auid + \"/members?`$select=id,displayName,userPrincipalName&`$top=999\"");
                    sb.AppendLine("        while ($muri) { $mr = Invoke-RestMethod -Uri $muri -Headers $headers -Method Get -ErrorAction Stop; $ml += @($mr.value); $muri = $mr.'@odata.nextLink' }");
                    sb.AppendLine("        $um = ((@($ml | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.user' } | ForEach-Object { $s = [string]$_.userPrincipalName; if (-not $s) { $s = [string]$_.displayName }; $s } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                    sb.AppendLine("        $gm = ((@($ml | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { [string]$_.displayName } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                    sb.AppendLine("        $dm = ((@($ml | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.device' } | ForEach-Object { $s = [string]$_.displayName; if (-not $s) { $s = [string]$_.id }; $s } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                    sb.AppendLine("    } catch { $memFail++ }");
                }
                if (wantAsg)
                {
                    sb.AppendLine("    $rnames = @(); $det = New-Object System.Collections.Generic.List[string]");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $sm = @(); $smuri = \"https://graph.microsoft.com/v1.0/directory/administrativeUnits/\" + $auid + \"/scopedRoleMembers\"");
                    sb.AppendLine("        while ($smuri) { $smr = Invoke-RestMethod -Uri $smuri -Headers $headers -Method Get -ErrorAction Stop; $sm += @($smr.value); $smuri = $smr.'@odata.nextLink' }");
                    sb.AppendLine("        foreach ($s in $sm) {");
                    sb.AppendLine("            $rid = [string]$s.roleId; $rn = $rid; if ($roleMap.ContainsKey($rid)) { $rn = $roleMap[$rid] }; if ($rn -ne '' -and $rnames -notcontains $rn) { $rnames += $rn }");
                    sb.AppendLine("            $pn = [string]$s.roleMemberInfo.userPrincipalName; $pt = 'User'; if (-not $pn) { $pp2 = Resolve-AuPrincipal ([string]$s.roleMemberInfo.id); $pn = $pp2.Name; $pt = $pp2.Type }");
                    sb.AppendLine("            $det.Add($rn + ' | ' + $pn + ' (' + $pt + ') | Active')");
                    sb.AppendLine("        }");
                    sb.AppendLine("    } catch { $scFail++ }");
                    if (wantSched)
                    {
                        sb.AppendLine("    $apath = '/administrativeUnits/' + $auid");
                        sb.AppendLine("    foreach ($s in @($auElig | Where-Object { [string]$_.directoryScopeId -eq $apath })) { if ([string]$s.status -eq 'Revoked') { continue }; $rid = [string]$s.roleDefinitionId; $rn = $rid; if ($roleMap.ContainsKey($rid)) { $rn = $roleMap[$rid] }; if ($rn -ne '' -and $rnames -notcontains $rn) { $rnames += $rn }; $pp2 = Resolve-AuPrincipal ([string]$s.principalId); $st = ''; try { $st = [string]$s.scheduleInfo.startDateTime } catch { }; $en = ''; try { $en = [string]$s.scheduleInfo.expiration.endDateTime } catch { }; $det.Add($rn + ' | ' + $pp2.Name + ' (' + $pp2.Type + ') | Eligible (PIM) | ' + $st + ' -> ' + $en) }");
                        sb.AppendLine("    foreach ($s in @($auAct | Where-Object { [string]$_.directoryScopeId -eq $apath })) { if ([string]$s.status -eq 'Revoked') { continue }; $rid = [string]$s.roleDefinitionId; $rn = $rid; if ($roleMap.ContainsKey($rid)) { $rn = $roleMap[$rid] }; if ($rn -ne '' -and $rnames -notcontains $rn) { $rnames += $rn }; $pp2 = Resolve-AuPrincipal ([string]$s.principalId); $st = ''; try { $st = [string]$s.scheduleInfo.startDateTime } catch { }; $en = ''; try { $en = [string]$s.scheduleInfo.expiration.endDateTime } catch { }; $det.Add($rn + ' | ' + $pp2.Name + ' (' + $pp2.Type + ') | Active (PIM) | ' + $st + ' -> ' + $en) }");
                    }
                    sb.AppendLine("    $ar = ($rnames -join ','); $acount = $det.Count; $ad = ($det -join '; ')");
                }
                if (wantReviews)
                {
                    sb.AppendLine("    $rw = ((@($defs | Where-Object { $q = ''; try { $q = [string]$_.scope.query } catch { }; $q2 = ''; try { $q2 = [string]$_.instanceEnumerationScope.query } catch { }; ($q -like ('*' + $auid + '*')) -or ($q2 -like ('*' + $auid + '*')) } | ForEach-Object { $dn = [string]$_.displayName; try { if ([string]$_.status -ne 'Completed') { $dn = $dn + ' (' + [string]$_.status + ')' } } catch { }; $dn } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        Id = $auid; DisplayName = $u.displayName; Description = $u.description; Visibility = $vis;");
                sb.AppendLine("        MembershipType = $mt; MembershipRule = $mrule; RuleProcessingState = $rps; RestrictedManagement = $rm;");
                sb.AppendLine("        UserMembers = " + (chosen.Contains("UserMembers") ? "$um" : "''") + "; GroupMembers = " + (chosen.Contains("GroupMembers") ? "$gm" : "''") + "; DeviceMembers = " + (chosen.Contains("DeviceMembers") ? "$dm" : "''") + ";");
                sb.AppendLine("        AssignedRoles = " + (chosen.Contains("AssignedRoles") ? "$ar" : "''") + "; AssignmentCount = " + (chosen.Contains("AssignmentCount") ? "$acount" : "''") + "; AssignmentDetails = " + (chosen.Contains("AssignmentDetails") ? "$ad" : "''") + ";");
                sb.AppendLine("        AccessReviews = " + (wantReviews ? "$rw" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantMembers) sb.AppendLine("if ($memFail -gt 0) { Write-Host (\"WARNING: {0} member querie(s) failed (consent for AdministrativeUnit.Read.All?).\" -f $memFail) }");
                if (wantAsg) sb.AppendLine("if ($scFail -gt 0) { Write-Host (\"WARNING: {0} scoped-role querie(s) failed (consent for RoleManagement.Read.Directory?).\" -f $scFail) }");
                if (wantAsg) sb.AppendLine("if ($script:resFail -gt 0) { Write-Host (\"WARNING: {0} principal(s) could not be resolved (consent for Directory.Read.All?).\" -f $script:resFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 8. GUEST USERS
        // B2B guest inventory: state, source IdP, derived home tenant plus
        // optional slow per-guest sponsors / memberships / app roles. Needs
        // User.Read.All (+ AuditLog.Read.All for sign-in,
        // RoleManagement.Read.Directory for memberships, Directory.Read.All
        // for app roles).
        private static AuditSection BuildGuestUsersSection()
        {
            var section = new AuditSection(
                "entra-guest-users",
                "Guest users",
                "Guest users export",
                "Audit B2B guest accounts via Graph: state, source identity provider, home tenant and stale-guest sign-in activity plus optional sponsors, group/role/app access (slow per-guest lookups).",
                "user",
                AuditScope.Graph);
            section.Category = "Standard Objects";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraGuestUsers.csv";

            var identity = new AuditOptionGroup("identity", "Identity", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("UserPrincipalName", true);
            identity.AddProp("DisplayName", true);
            identity.AddProp("Mail", true);
            identity.AddProp("OtherMails", true);
            section.AddGroup(identity);

            var state = new AuditOptionGroup("state", "Guest state & origin", GroupMode.MultiCheck); state.Columns = 2;
            state.Hint = "IdP comes from the identities collection (issuer/signInType); HomeTenant is derived from the #EXT# UPN (invited-address domain).";
            state.AddProp("UserType", true);
            state.AddProp("ExternalUserState", true);
            state.AddProp("CreationType", true);
            state.AddProp("IdP", true);
            state.AddProp("HomeTenant", true);
            section.AddGroup(state);

            var signin = new AuditOptionGroup("signin", "Sign-in activity", GroupMode.MultiCheck); signin.Columns = 1;
            signin.Hint = "Needs the AuditLog.Read.All consent; without it the whole query is rejected - uncheck the column instead. Use it to flag stale guests.";
            signin.AddProp("LastSignInDateTime", true);
            section.AddGroup(signin);

            var sponsors = new AuditOptionGroup("sponsors", "Sponsors (slow per-guest lookup)", GroupMode.MultiCheck); sponsors.Columns = 1;
            sponsors.Hint = "One sponsors query per guest - slower on large tenants. Empty when no sponsor is tracked.";
            sponsors.Add(AuditOption.Prop("Sponsors", false).MarkSlow());
            section.AddGroup(sponsors);

            var access = new AuditOptionGroup("access", "Access (slow per-guest lookup)", GroupMode.MultiCheck); access.Columns = 1;
            access.Hint = "Groups + directory roles come from one transitiveMemberOf query per guest (needs RoleManagement.Read.Directory); app roles from appRoleAssignments (needs Directory.Read.All).";
            access.Add(AuditOption.Prop("Groups", false).MarkSlow());
            access.Add(AuditOption.Prop("AssignedRoles", false).MarkSlow());
            access.Add(AuditOption.Prop("AppRoles", false).MarkSlow());
            section.AddGroup(access);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "state", "signin", "sponsors", "access");
                if (chosen.Count == 0) chosen.Add("UserPrincipalName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantSignIn = chosen.Contains("LastSignInDateTime");
                bool wantSponsors = chosen.Contains("Sponsors");
                bool wantGroups = chosen.Contains("Groups");
                bool wantRoles = chosen.Contains("AssignedRoles");
                bool wantMembers = wantGroups || wantRoles;
                bool wantApps = chosen.Contains("AppRoles");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying guest users (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$sel = 'id,displayName,userPrincipalName,mail,otherMails,userType,externalUserState,creationType,identities'");
                if (wantSignIn)
                    sb.AppendLine("$sel += ',signInActivity'");
                sb.AppendLine("$guests = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/users?$filter=userType eq ''Guest''&$select=' + $sel + '&$top=999'");
                sb.AppendLine("while ($uri -and ($maxUsers -lt 0 -or $guests.Count -lt $maxUsers)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $guests += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $guests.Count -gt $maxUsers) { $guests = $guests[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} guest(s).\" -f $guests.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantSponsors) sb.AppendLine("$sponFail = 0");
                if (wantMembers) sb.AppendLine("$memFail = 0");
                if (wantApps) sb.AppendLine("$appFail = 0");
                sb.AppendLine("foreach ($u in $guests) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $guests.Count) }");
                sb.AppendLine("    $uid = [string]$u.id");
                sb.AppendLine("    $om = ((@($u.otherMails) | ForEach-Object { [string]$_ }) -join ',')");
                sb.AppendLine("    $idp = ((@($u.identities) | ForEach-Object { [string]$_.issuer + '/' + [string]$_.signInType } | Where-Object { $_ -ne '/' } | Sort-Object -Unique) -join ',')");
                sb.AppendLine("    $ht = ''; $upn = [string]$u.userPrincipalName; if ($upn -match '^(.+)#EXT#') { $h = $matches[1]; $k = $h.LastIndexOf('_'); if ($k -gt 0) { $ht = $h.Substring(0, $k) + '@' + $h.Substring($k + 1) } else { $ht = $h } }");
                if (wantSignIn)
                    sb.AppendLine("    $ls = ''; try { if ($u.signInActivity) { $ls = [string]$u.signInActivity.lastSignInDateTime } } catch { }");
                if (wantSponsors)
                {
                    sb.AppendLine("    $sp = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $sr = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"/sponsors?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        $sp = ((@($sr.value) | ForEach-Object { $s = [string]$_.userPrincipalName; if (-not $s) { $s = [string]$_.displayName }; $s } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')");
                    sb.AppendLine("    } catch { $sponFail++ }");
                }
                if (wantMembers)
                {
                    sb.AppendLine("    $gr = ''; $rl = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $tmo = @()");
                    sb.AppendLine("        $turi = \"https://graph.microsoft.com/v1.0/users/\" + $uid + \"/transitiveMemberOf?`$select=id,displayName\"");
                    sb.AppendLine("        while ($turi) { $tr = Invoke-RestMethod -Uri $turi -Headers $headers -Method Get -ErrorAction Stop; $tmo += @($tr.value); $turi = $tr.'@odata.nextLink' }");
                    sb.AppendLine("        $gr = ((@($tmo | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { [string]$_.displayName } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                    sb.AppendLine("        $rl = ((@($tmo | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | ForEach-Object { [string]$_.displayName } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ',')");
                    sb.AppendLine("    } catch { $memFail++ }");
                }
                if (wantApps)
                {
                    sb.AppendLine("    $ap = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $aa = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"/appRoleAssignments?`$select=resourceDisplayName\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        $ap = ((@($aa.value) | ForEach-Object { [string]$_.resourceDisplayName } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')");
                    sb.AppendLine("    } catch { $appFail++ }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        UserPrincipalName = $upn; DisplayName = $u.displayName; Mail = $u.mail; OtherMails = $om;");
                sb.AppendLine("        UserType = $u.userType; ExternalUserState = $u.externalUserState; CreationType = $u.creationType; IdP = $idp; HomeTenant = $ht;");
                sb.AppendLine("        LastSignInDateTime = " + (wantSignIn ? "$ls" : "''") + "; Sponsors = " + (wantSponsors ? "$sp" : "''") + ";");
                sb.AppendLine("        Groups = " + (wantGroups ? "$gr" : "''") + "; AssignedRoles = " + (wantRoles ? "$rl" : "''") + "; AppRoles = " + (wantApps ? "$ap" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantSponsors) sb.AppendLine("if ($sponFail -gt 0) { Write-Host (\"WARNING: {0} sponsor querie(s) failed.\" -f $sponFail) }");
                if (wantMembers) sb.AppendLine("if ($memFail -gt 0) { Write-Host (\"WARNING: {0} membership querie(s) failed (consent for RoleManagement.Read.Directory?).\" -f $memFail) }");
                if (wantApps) sb.AppendLine("if ($appFail -gt 0) { Write-Host (\"WARNING: {0} app-role querie(s) failed (consent for Directory.Read.All?).\" -f $appFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 8b. RISKY USERS
        // Identity Protection risk STATE (not policy config - no endpoint
        // exists, even beta): one row per at-risk user with level, state,
        // detail and last update. Risk-driven enforcement itself is captured
        // per CA policy in the RiskLevels column of ca-policies. Needs
        // IdentityRiskyUser.Read.All.
        private static AuditSection BuildRiskyUsersSection()
        {
            var section = new AuditSection(
                "entra-risky-users",
                "Risky users",
                "Risky users export",
                "Audit Identity Protection risk state via Graph: risk level, state and detail per at-risk user (one row per user).",
                "risk",
                AuditScope.Graph);
            section.Category = "Standard Objects";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraRiskyUsers.csv";

            var identity = new AuditOptionGroup("identity", "User", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("UserPrincipalName", true);
            identity.AddProp("DisplayName", true);
            section.AddGroup(identity);

            var risk = new AuditOptionGroup("risk", "Risk state", GroupMode.MultiCheck); risk.Columns = 2;
            risk.AddProp("RiskLevel", true);
            risk.AddProp("RiskState", true);
            risk.AddProp("RiskDetail", true);
            risk.AddProp("RiskLastUpdated", true);
            section.AddGroup(risk);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "risk");
                if (chosen.Count == 0) chosen.Add("UserPrincipalName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying risky users (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$rus = @()");
                sb.AppendLine("try {");
                sb.AppendLine("    $ruri = 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$select=id,userPrincipalName,userDisplayName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime'");
                sb.AppendLine("    while ($ruri -and ($maxUsers -lt 0 -or $rus.Count -lt $maxUsers)) {");
                sb.AppendLine("        $rr = Invoke-RestMethod -Uri $ruri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("        $rus += @($rr.value)");
                sb.AppendLine("        $ruri = $rr.'@odata.nextLink'");
                sb.AppendLine("    }");
                sb.AppendLine("    if ($maxUsers -ge 0 -and $rus.Count -gt $maxUsers) { $rus = $rus[0..($maxUsers - 1)] }");
                sb.AppendLine("    Write-Host (\"Retrieved {0} risky user(s).\" -f $rus.Count)");
                sb.AppendLine("} catch { Write-Host ('WARNING: riskyUsers query failed (' + $_.Exception.Message + ' - consent for IdentityRiskyUser.Read.All?)'); $rus = @() }");
                sb.AppendLine("if ($rus.Count -eq 0) { Write-Host 'No risky users returned - clean tenant, or consent missing.' }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($u in $rus) {");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        UserPrincipalName = $u.userPrincipalName; DisplayName = $u.userDisplayName;");
                sb.AppendLine("        RiskLevel = $u.riskLevel; RiskState = $u.riskState; RiskDetail = $u.riskDetail; RiskLastUpdated = $u.riskLastUpdatedDateTime");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ UserPrincipalName = ''; DisplayName = ''; RiskLevel = ''; RiskState = ''; RiskDetail = ''; RiskLastUpdated = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 9. EXTERNAL SETTINGS
        // Tenant-wide External ID collaboration policies, one row. Domain
        // allow/block lists are NOT exposed by Graph v1.0 (beta
        // b2bManagementPolicy only) - review them in the Entra portal. Needs
        // Policy.Read.All (+ IdentityUserFlow.Read.All for user flows).
        private static AuditSection BuildExternalSettingsSection()
        {
            var section = new AuditSection(
                "entra-external-settings",
                "External settings",
                "External collaboration settings export",
                "Audit tenant-wide External ID policies via Graph (one row): guest invite rights, guest access level, sign-up and user flows. Domain allow/block lists are portal-only.",
                "key",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraExternalSettings.csv";

            var invite = new AuditOptionGroup("invite", "Guest invitations", GroupMode.MultiCheck); invite.Columns = 1;
            invite.Hint = "From the authorization policy (who can invite guests).";
            invite.AddProp("GuestInviteAllowed", true);
            section.AddGroup(invite);

            var access = new AuditOptionGroup("access", "Guest access", GroupMode.MultiCheck); access.Columns = 2;
            access.Hint = "Guest access level maps the guestUserRoleId (Same as members / Guest User / Restricted Guest User).";
            access.AddProp("GuestAccessLevel", true);
            access.AddProp("EmailSignUpAllowed", true);
            access.AddProp("AllowEmailVerifiedJoin", true);
            section.AddGroup(access);

            var signup = new AuditOptionGroup("signup", "Self-service sign-up", GroupMode.MultiCheck); signup.Columns = 1;
            signup.Hint = "Authentication flows policy + B2B user flows (needs IdentityUserFlow.Read.All; warning when unavailable).";
            signup.AddProp("SelfServiceSignUp", true);
            signup.AddProp("UserFlows", true);
            section.AddGroup(signup);

            var domains = new AuditOptionGroup("domains", "Collaboration restrictions", GroupMode.MultiCheck); domains.Columns = 1;
            domains.Hint = "Domain allow/block lists are not exposed by Graph v1.0 - review External collaboration settings in the Entra portal.";
            domains.AddProp("DomainRestrictions", true);
            section.AddGroup(domains);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "invite", "access", "signup", "domains");
                if (chosen.Count == 0) chosen.Add("GuestInviteAllowed");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying external collaboration settings (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$auth = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy?$select=allowInvitesFrom,guestUserRoleId,allowedToSignUpEmailBasedSubscriptions,allowEmailVerifiedUsersToJoinOrganization' -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("$gal = [string]$auth.guestUserRoleId");
                sb.AppendLine("if ($gal -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') { $gal = 'Same as members (User)' }");
                sb.AppendLine("elseif ($gal -eq '10dae51f-b6af-4016-8d66-8c2a99b929b3') { $gal = 'Guest User (default)' }");
                sb.AppendLine("elseif ($gal -eq '2af84b1e-32c8-42b7-82bc-daa82404023b') { $gal = 'Restricted Guest User' }");
                sb.AppendLine("$sss = ''");
                sb.AppendLine("try {");
                sb.AppendLine("    $fl = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationFlowsPolicy' -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    if ($fl.selfServiceSignUp.isEnabled) { $sss = 'Enabled' } else { $sss = 'Disabled' }");
                sb.AppendLine("} catch { Write-Host 'WARNING: authenticationFlowsPolicy query failed (consent for Policy.Read.All?).' }");
                sb.AppendLine("$flows = ''");
                sb.AppendLine("try {");
                sb.AppendLine("    $fv = @()");
                sb.AppendLine("    $fu = 'https://graph.microsoft.com/v1.0/identity/b2xUserFlows'");
                sb.AppendLine("    while ($fu) { $fx = Invoke-RestMethod -Uri $fu -Headers $headers -Method Get -ErrorAction Stop; $fv += @($fx.value); $fu = $fx.'@odata.nextLink' }");
                sb.AppendLine("    if ($fv.Count -eq 0) { $flows = 'None configured' }");
                sb.AppendLine("    else { $flows = ((@($fv) | ForEach-Object { $pn = ((@($_.identityProviders) | ForEach-Object { $t = [string]$_.displayName; if (-not $t) { $t = [string]$_.id }; $t } | Where-Object { $_ -ne '' }) -join ','); [string]$_.id + ' (' + [string]$_.userFlowType + ': ' + $pn + ')' } | Sort-Object -Unique) -join ';') }");
                sb.AppendLine("} catch { Write-Host 'WARNING: b2xUserFlows query failed (consent for IdentityUserFlow.Read.All?).' }");
                sb.AppendLine("$rows = @([pscustomobject]@{");
                sb.AppendLine("    GuestInviteAllowed = $auth.allowInvitesFrom; GuestAccessLevel = $gal;");
                sb.AppendLine("    EmailSignUpAllowed = $auth.allowedToSignUpEmailBasedSubscriptions; AllowEmailVerifiedJoin = $auth.allowEmailVerifiedUsersToJoinOrganization;");
                sb.AppendLine("    SelfServiceSignUp = $sss; UserFlows = $flows;");
                sb.AppendLine("    DomainRestrictions = 'Not exposed by Graph v1.0 - review Collaboration restrictions in the Entra portal'");
                sb.AppendLine("})");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 10. CROSS-TENANT ACCESS
        // Default + per-partner B2B collaboration / direct-connect settings,
        // inbound trust claims, redemption/consent and optional cross-tenant
        // sync scope. Needs Policy.Read.All.
        private static AuditSection BuildCrossTenantSection()
        {
            var section = new AuditSection(
                "entra-cross-tenant",
                "Cross-tenant access",
                "Cross-tenant access export",
                "Audit B2B collaboration, direct-connect trust and tenant restrictions with other Entra orgs via Graph: default settings plus one row per partner tenant (slow per-partner sync lookup).",
                "key",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraCrossTenant.csv";

            var scope = new AuditOptionGroup("scope", "Scope", GroupMode.MultiCheck); scope.Columns = 2;
            scope.AddProp("Scope", true);
            scope.AddProp("TenantId", true);
            section.AddGroup(scope);

            var collab = new AuditOptionGroup("collab", "B2B collaboration & direct connect", GroupMode.MultiCheck); collab.Columns = 2;
            collab.Hint = "Inbound/outbound summaries (Allowed all / Blocked / Allowed with named targets, incl. apps). Selectively-targeted users/groups are resolved to names via cached lookups.";
            collab.Add(AuditOption.Prop("CollabInbound", true).MarkSlow());
            collab.Add(AuditOption.Prop("CollabOutbound", true).MarkSlow());
            collab.Add(AuditOption.Prop("DirectConnectInbound", true).MarkSlow());
            collab.Add(AuditOption.Prop("DirectConnectOutbound", true).MarkSlow());
            section.AddGroup(collab);

            var trust = new AuditOptionGroup("trust", "Inbound trust claims", GroupMode.MultiCheck); trust.Columns = 2;
            trust.Hint = "Whether MFA, compliant-device and hybrid-joined-device claims from the partner are trusted.";
            trust.AddProp("TrustMFA", true);
            trust.AddProp("TrustCompliantDevice", true);
            trust.AddProp("TrustHybridJoinedDevice", true);
            section.AddGroup(trust);

            var restrictions = new AuditOptionGroup("restrictions", "Tenant restrictions", GroupMode.MultiCheck); restrictions.Columns = 1;
            restrictions.Hint = "Tenant-restriction stance (who may use external accounts on your network/devices) from the same policy object - no extra query. All-disabled is the Microsoft default.";
            restrictions.AddProp("TenantRestrictionsUsers", true);
            restrictions.AddProp("TenantRestrictionsApps", true);
            restrictions.AddProp("TenantRestrictionsDevices", true);
            section.AddGroup(restrictions);

            var redemption = new AuditOptionGroup("redemption", "Redemption & sync", GroupMode.MultiCheck); redemption.Columns = 1;
            redemption.Hint = "Automatic redemption order / user-consent settings; cross-tenant sync scope is one extra query per partner (slow, off by default).";
            redemption.AddProp("AutoRedemption", true);
            redemption.Add(AuditOption.Prop("SyncConfig", false).MarkSlow());
            section.AddGroup(redemption);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "scope", "collab", "trust", "restrictions", "redemption");
                if (chosen.Count == 0) chosen.Add("TenantId");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantSync = chosen.Contains("SyncConfig");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying cross-tenant access policy (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$tnameCache = @{}");
                sb.AppendLine("$script:tnameFail = 0");
                sb.AppendLine("function Resolve-TargetName {");
                sb.AppendLine("    param($tid)");
                sb.AppendLine("    if ($tnameCache.ContainsKey($tid)) { return $tnameCache[$tid] }");
                sb.AppendLine("    $nm = $tid");
                sb.AppendLine("    try {");
                sb.AppendLine("        $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $tid + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("        $nm = [string]$o.userPrincipalName; if (-not $nm) { $nm = [string]$o.displayName }");
                sb.AppendLine("    } catch {");
                sb.AppendLine("        try {");
                sb.AppendLine("            $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $tid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("            $nm = [string]$o.displayName");
                sb.AppendLine("        } catch { $script:tnameFail++ }");
                sb.AppendLine("    }");
                sb.AppendLine("    $tnameCache[$tid] = $nm");
                sb.AppendLine("    return $nm");
                sb.AppendLine("}");
                sb.AppendLine("function Format-Target {");
                sb.AppendLine("    param($c)");
                sb.AppendLine("    if (-not $c) { return '' }");
                sb.AppendLine("    $o = ''");
                sb.AppendLine("    try {");
                sb.AppendLine("        $ua = [string]$c.usersAndGroups.accessType");
                sb.AppendLine("        if ($ua -eq 'blocked') { $u = 'Blocked' }");
                sb.AppendLine("        else { $all = $false; try { $all = [bool]$c.usersAndGroups.targetAllUsers } catch { }; if ($all) { $u = 'Allowed (all)' }");
                sb.AppendLine("        else { $names = @(); foreach ($t in @($c.usersAndGroups.targets)) { $tv = [string]$t.target; if ($tv) { $names += [string]$t.targetType + ':' + (Resolve-TargetName $tv) } }; if ($names.Count -eq 0) { $u = 'Allowed (all)' } else { $u = 'Allowed (' + ($names -join ', ') + ')' } } }");
                sb.AppendLine("        $aa = [string]$c.applications.accessType");
                sb.AppendLine("        if ($aa -eq 'blocked') { $a = 'Blocked' }");
                sb.AppendLine("        else { $alla = $false; try { $alla = [bool]$c.applications.targetAllApplications } catch { }; if ($alla) { $a = 'Allowed (all)' }");
                sb.AppendLine("        else { $anames = @(); foreach ($t in @($c.applications.targets)) { $tv = [string]$t.target; if ($tv) { $anames += 'application:' + $tv } }; if ($anames.Count -eq 0) { $a = 'Allowed (all)' } else { $a = 'Allowed (' + ($anames -join ', ') + ')' } } }");
                sb.AppendLine("        $o = $u + ' / apps: ' + $a");
                sb.AppendLine("    } catch { }");
                sb.AppendLine("    return $o");
                sb.AppendLine("}");
                sb.AppendLine("function Format-Trust {");
                sb.AppendLine("    param($t, $prop)");
                sb.AppendLine("    $v = 'No'; try { if ([bool]$t.$prop) { $v = 'Yes' } } catch { }; return $v");
                sb.AppendLine("}");
                sb.AppendLine("function Format-TrAccess {");
                sb.AppendLine("    param($n)");
                sb.AppendLine("    $a = ''");
                sb.AppendLine("    try {");
                sb.AppendLine("        $t = [string]$n.accessType");
                sb.AppendLine("        if ($t -eq 'blocked') { $a = 'Blocked' }");
                sb.AppendLine("        elseif ($t) {");
                sb.AppendLine("            $all = $false");
                sb.AppendLine("            try { $all = [bool]$n.targetAllUsers } catch { }");
                sb.AppendLine("            try { if (-not $all) { $all = [bool]$n.targetAllApplications } } catch { }");
                sb.AppendLine("            try { if (-not $all) { $all = [bool]$n.targetAllDevices } } catch { }");
                sb.AppendLine("            if ($all) { $a = 'Allowed (all)' }");
                sb.AppendLine("            else { $cnt = @($n.targets).Count; if ($cnt -gt 0) { $a = 'Allowed (' + $cnt + ' targets)' } else { $a = 'Allowed (all)' } }");
                sb.AppendLine("        }");
                sb.AppendLine("    } catch { }");
                sb.AppendLine("    return $a");
                sb.AppendLine("}");
                sb.AppendLine("$def = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("$parts = @()");
                sb.AppendLine("$puri = 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners'");
                sb.AppendLine("while ($puri -and ($maxUsers -lt 0 -or $parts.Count -lt $maxUsers)) {");
                sb.AppendLine("    $pr = Invoke-RestMethod -Uri $puri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $parts += @($pr.value)");
                sb.AppendLine("    $puri = $pr.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $parts.Count -gt $maxUsers) { $parts = $parts[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} partner configuration(s).\" -f $parts.Count)");
                sb.AppendLine("$dRed = ''");
                sb.AppendLine("try { $o = @($def.invitationRedemptionIdentityProviderConfiguration.primaryIdentityProviderPrecedenceOrder); if ($o.Count -gt 0) { $dRed = ($o -join ' > ') }; if ($def.invitationRedemptionIdentityProviderConfiguration.fallbackIdentityProvider) { $dRed = $dRed + ' (fallback: ' + [string]$def.invitationRedemptionIdentityProviderConfiguration.fallbackIdentityProvider + ')' } } catch { }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$rows.Add([pscustomobject]@{");
                sb.AppendLine("    Scope = 'Default (all tenants)'; TenantId = ''; CollabInbound = (Format-Target $def.b2bCollaborationInbound); CollabOutbound = (Format-Target $def.b2bCollaborationOutbound);");
                sb.AppendLine("    DirectConnectInbound = (Format-Target $def.b2bDirectConnectInbound); DirectConnectOutbound = (Format-Target $def.b2bDirectConnectOutbound);");
                sb.AppendLine("    TrustMFA = (Format-Trust $def.inboundTrust 'isMfaAccepted'); TrustCompliantDevice = (Format-Trust $def.inboundTrust 'isCompliantDeviceAccepted'); TrustHybridJoinedDevice = (Format-Trust $def.inboundTrust 'isHybridAzureADJoinedDeviceAccepted');");
                sb.AppendLine("    TenantRestrictionsUsers = (Format-TrAccess $def.tenantRestrictions.usersAndGroups); TenantRestrictionsApps = (Format-TrAccess $def.tenantRestrictions.applications); TenantRestrictionsDevices = (Format-TrAccess $def.tenantRestrictions.devices);");
                sb.AppendLine("    AutoRedemption = $dRed; SyncConfig = ''");
                sb.AppendLine("})");
                sb.AppendLine("$i = 0");
                if (wantSync) sb.AppendLine("$syncFail = 0");
                sb.AppendLine("foreach ($p in $parts) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $parts.Count) }");
                sb.AppendLine("    $tid = [string]$p.tenantId");
                sb.AppendLine("    $cons = ''; try { $ci = 'No'; $co = 'No'; if ([bool]$p.automaticUserConsentSettings.inboundIsConsentAccepted) { $ci = 'Yes' }; if ([bool]$p.automaticUserConsentSettings.outboundIsConsentAccepted) { $co = 'Yes' }; $cons = 'Inbound consent: ' + $ci + ', Outbound consent: ' + $co } catch { }");
                if (wantSync)
                {
                    sb.AppendLine("    $sy = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $sq = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners/\" + $tid + \"/identitySynchronization\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        $en = 'Disabled'; try { if ([bool]$sq.userSyncInbound.isSyncEnabled) { $en = 'Enabled' } } catch { }; $sc = ''; try { $sc = [string]$sq.userSyncInbound.scopeType } catch { }; $sy = $en; if ($sc) { $sy = $sy + ' (' + $sc + ')' }");
                    sb.AppendLine("    } catch { $syncFail++ }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        Scope = 'Partner'; TenantId = $tid; CollabInbound = (Format-Target $p.b2bCollaborationInbound); CollabOutbound = (Format-Target $p.b2bCollaborationOutbound);");
                sb.AppendLine("        DirectConnectInbound = (Format-Target $p.b2bDirectConnectInbound); DirectConnectOutbound = (Format-Target $p.b2bDirectConnectOutbound);");
                sb.AppendLine("        TrustMFA = (Format-Trust $p.inboundTrust 'isMfaAccepted'); TrustCompliantDevice = (Format-Trust $p.inboundTrust 'isCompliantDeviceAccepted'); TrustHybridJoinedDevice = (Format-Trust $p.inboundTrust 'isHybridAzureADJoinedDeviceAccepted');");
                sb.AppendLine("        TenantRestrictionsUsers = (Format-TrAccess $p.tenantRestrictions.usersAndGroups); TenantRestrictionsApps = (Format-TrAccess $p.tenantRestrictions.applications); TenantRestrictionsDevices = (Format-TrAccess $p.tenantRestrictions.devices);");
                sb.AppendLine("        AutoRedemption = $cons; SyncConfig = " + (wantSync ? "$sy" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantSync) sb.AppendLine("if ($syncFail -gt 0) { Write-Host (\"WARNING: {0} sync querie(s) failed (consent for Policy.Read.All?).\" -f $syncFail) }");
                sb.AppendLine("if ($script:tnameFail -gt 0) { Write-Host (\"WARNING: {0} cross-tenant target(s) could not be resolved to names.\" -f $script:tnameFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 11. EXTERNAL IDPS
        // Configured external identity providers + redemption order from the
        // cross-tenant default. SAML/WS-Fed custom IdPs are portal-only
        // (beta API). Needs IdentityProvider.Read.All (+ Policy.Read.All for
        // the redemption order).
        private static AuditSection BuildExternalIdpsSection()
        {
            var section = new AuditSection(
                "entra-external-idps",
                "External IdPs",
                "External identity providers export",
                "Audit configured external identity providers via Graph (Google/Facebook) plus the invitation redemption order. SAML/WS-Fed custom IdPs are portal-only.",
                "key",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraExternalIdps.csv";

            var idp = new AuditOptionGroup("idp", "Identity provider", GroupMode.MultiCheck); idp.Columns = 2;
            idp.Hint = "From /identity/identityProviders (secrets are never requested). SAML/WS-Fed custom IdPs are not exposed by Graph v1.0.";
            idp.AddProp("IdPName", true);
            idp.AddProp("IdPType", true);
            idp.AddProp("ClientId", true);
            section.AddGroup(idp);

            var redemption = new AuditOptionGroup("redemption", "Redemption", GroupMode.MultiCheck); redemption.Columns = 1;
            redemption.Hint = "Invitation redemption order from the cross-tenant default configuration (needs Policy.Read.All).";
            redemption.AddProp("RedemptionOrder", true);
            section.AddGroup(redemption);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "idp", "redemption");
                if (chosen.Count == 0) chosen.Add("IdPName");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying external identity providers (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$red = ''");
                sb.AppendLine("try {");
                sb.AppendLine("    $def = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default?$select=invitationRedemptionIdentityProviderConfiguration' -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $o = @($def.invitationRedemptionIdentityProviderConfiguration.primaryIdentityProviderPrecedenceOrder); if ($o.Count -gt 0) { $red = ($o -join ' > ') }");
                sb.AppendLine("} catch { Write-Host 'WARNING: redemption order query failed (consent for Policy.Read.All?).' }");
                sb.AppendLine("$provs = @()");
                sb.AppendLine("try {");
                sb.AppendLine("    $puri = 'https://graph.microsoft.com/v1.0/identity/identityProviders?$select=id,displayName,clientId&$top=999'");
                sb.AppendLine("    while ($puri) { $pr = Invoke-RestMethod -Uri $puri -Headers $headers -Method Get -ErrorAction Stop; $provs += @($pr.value); $puri = $pr.'@odata.nextLink' }");
                sb.AppendLine("} catch { Write-Host 'WARNING: identityProviders query failed (needs IdentityProvider.Read.All consent AND the External Identity Provider Administrator role for the auditor).' }");
                sb.AppendLine("Write-Host (\"Retrieved {0} identity provider(s).\" -f $provs.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($v in $provs) {");
                sb.AppendLine("    $tp = ([string]$v.'@odata.type' -replace '^#microsoft.graph.', ''); if ($v.identityProviderType) { $tp = $tp + '/' + [string]$v.identityProviderType }");
                sb.AppendLine("    $nm = [string]$v.displayName; if (-not $nm) { $nm = [string]$v.id }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{ IdPName = $nm; IdPType = $tp; ClientId = $v.clientId; RedemptionOrder = $red })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ IdPName = ''; IdPType = ''; ClientId = ''; RedemptionOrder = $red }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 12. APP REGISTRATIONS
        // Migration checklist per app registration: API permissions (resolved to
        // names + delegated/application split) and secret/cert expiries (values
        // never transfer - regenerate pre-cutover). Needs Application.Read.All.
        private static AuditSection BuildAppRegistrationsSection()
        {
            var section = new AuditSection(
                "entra-app-registrations",
                "App registrations",
                "App registrations export",
                "Audit app registrations via Graph: redirect URIs, API permissions and secret/certificate expiries (values never transfer - regenerate before cutover).",
                "key",
                AuditScope.Graph);
            section.Category = "Applications";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraAppRegistrations.csv";

            var identity = new AuditOptionGroup("identity", "Application", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("DisplayName", true);
            identity.AddProp("AppId", true);
            identity.AddProp("SignInAudience", true);
            section.AddGroup(identity);

            var config = new AuditOptionGroup("config", "Redirects & permissions", GroupMode.MultiCheck); config.Columns = 1;
            config.Hint = "API permission names are resolved via the resource service principals (cached, one lookup per API).";
            config.AddProp("RedirectUris", true);
            config.AddProp("ApiPermissions", true);
            section.AddGroup(config);

            var secrets = new AuditOptionGroup("secrets", "Secrets & certificates", GroupMode.MultiCheck); secrets.Columns = 1;
            secrets.Hint = "Metadata only (Graph never returns secret values). Expired credentials are flagged EXPIRED - regenerate them in the target tenant before cutover.";
            secrets.AddProp("Secrets", true);
            secrets.AddProp("Certificates", true);
            section.AddGroup(secrets);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "config", "secrets");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantPerms = chosen.Contains("ApiPermissions");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying app registrations (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$apps = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,signInAudience,web,spa,publicClient,requiredResourceAccess,passwordCredentials,keyCredentials&$top=999'");
                sb.AppendLine("while ($uri -and ($maxUsers -lt 0 -or $apps.Count -lt $maxUsers)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $apps += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $apps.Count -gt $maxUsers) { $apps = $apps[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} app registration(s).\" -f $apps.Count)");
                if (wantPerms)
                {
                    sb.AppendLine("$resCache = @{}");
                    sb.AppendLine("$script:resFail = 0");
                    sb.AppendLine("function Resolve-ResourceApi {");
                    sb.AppendLine("    param($appid)");
                    sb.AppendLine("    if ($resCache.ContainsKey($appid)) { return $resCache[$appid] }");
                    sb.AppendLine("    $ro = [pscustomobject]@{ Name = $appid; Scopes = @{}; Roles = @{} }");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals(appId='\" + $appid + \"')?`$select=displayName,oauth2PermissionScopes,appRoles\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        if ($o.displayName) { $ro.Name = [string]$o.displayName }");
                    sb.AppendLine("        foreach ($s in @($o.oauth2PermissionScopes)) { $ro.Scopes[[string]$s.id] = [string]$s.value }");
                    sb.AppendLine("        foreach ($a in @($o.appRoles)) { $rn = [string]$a.displayName; if (-not $rn) { $rn = [string]$a.value }; $ro.Roles[[string]$a.id] = $rn }");
                    sb.AppendLine("    } catch { $script:resFail++ }");
                    sb.AppendLine("    $resCache[$appid] = $ro");
                    sb.AppendLine("    return $ro");
                    sb.AppendLine("}");
                }
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                sb.AppendLine("foreach ($a in $apps) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $apps.Count) }");
                sb.AppendLine("    $ru = ((@(@($a.web.redirectUris) + @($a.spa.redirectUris) + @($a.publicClient.redirectUris) | ForEach-Object { [string]$_ }) | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',')");
                if (wantPerms)
                {
                    sb.AppendLine("    $pl = New-Object System.Collections.Generic.List[string]");
                    sb.AppendLine("    foreach ($rr in @($a.requiredResourceAccess)) {");
                    sb.AppendLine("        $ro = Resolve-ResourceApi ([string]$rr.resourceAppId)");
                    sb.AppendLine("        foreach ($ra in @($rr.resourceAccess)) {");
                    sb.AppendLine("            $aid = [string]$ra.id; $nm = $aid");
                    sb.AppendLine("            if ([string]$ra.type -eq 'Scope') { if ($ro.Scopes.ContainsKey($aid)) { $nm = $ro.Scopes[$aid] }; $pl.Add($ro.Name + ': ' + $nm + ' (delegated)') }");
                    sb.AppendLine("            else { if ($ro.Roles.ContainsKey($aid)) { $nm = $ro.Roles[$aid] }; $pl.Add($ro.Name + ': ' + $nm + ' (application)') }");
                    sb.AppendLine("        }");
                    sb.AppendLine("    }");
                    sb.AppendLine("    $perms = (($pl | Sort-Object -Unique) -join ',')");
                }
                sb.AppendLine("    $sec = ((@($a.passwordCredentials) | ForEach-Object { $n = [string]$_.displayName; $e = [string]$_.endDateTime; $x = ''; try { if ($e -ne '' -and ([datetime]$e) -lt (Get-Date)) { $x = ' EXPIRED' } } catch { }; $n + ' (expires ' + $e + ')' + $x } | Where-Object { $_ -ne ' (expires )' } | Sort-Object -Unique) -join ',')");
                sb.AppendLine("    $crt = ((@($a.keyCredentials) | ForEach-Object { $n = [string]$_.displayName; if (-not $n) { $n = [string]$_.keyId }; $e = [string]$_.endDateTime; $x = ''; try { if ($e -ne '' -and ([datetime]$e) -lt (Get-Date)) { $x = ' EXPIRED' } } catch { }; $n + ' (expires ' + $e + ')' + $x } | Where-Object { $_ -ne ' (expires )' } | Sort-Object -Unique) -join ',')");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        DisplayName = $a.displayName; AppId = $a.appId; SignInAudience = $a.signInAudience;");
                sb.AppendLine("        RedirectUris = $ru; ApiPermissions = " + (wantPerms ? "$perms" : "''") + ";");
                sb.AppendLine("        Secrets = $sec; Certificates = $crt");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantPerms) sb.AppendLine("if ($script:resFail -gt 0) { Write-Host (\"WARNING: {0} API(s) could not be resolved to names (consent for Application.Read.All?).\" -f $script:resFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 13. ENTERPRISE APPS
        // Service principals (Application type): SSO mode, assignments with app
        // role names, provisioning jobs. Needs Application.Read.All (+
        // Synchronization.Read.All for provisioning).
        private static AuditSection BuildEnterpriseAppsSection()
        {
            var section = new AuditSection(
                "entra-enterprise-apps",
                "Enterprise apps",
                "Enterprise applications export",
                "Audit enterprise apps (service principals) via Graph: SSO config, assigned users/groups with app roles, provisioning state (slow per-app lookups).",
                "key",
                AuditScope.Graph);
            section.Category = "Applications";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraEnterpriseApps.csv";

            var identity = new AuditOptionGroup("identity", "Application", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("DisplayName", true);
            identity.AddProp("AppId", true);
            identity.AddProp("SpType", true);
            identity.AddProp("Enabled", true);
            section.AddGroup(identity);

            var sso = new AuditOptionGroup("sso", "SSO config", GroupMode.MultiCheck); sso.Columns = 2;
            sso.AddProp("SsoMode", true);
            sso.AddProp("Homepage", true);
            sso.AddProp("LoginUrl", true);
            section.AddGroup(sso);

            var scope = new AuditOptionGroup("scope", "Scope", GroupMode.SingleChoice); scope.Columns = 1;
            scope.Hint = "Microsoft-owned apps (owner org = Microsoft tenant) are first-party noise in a migration audit - hide them to focus on third-party integrations.";
            scope.Add(new AuditOption("all", "All apps", "all", true));
            scope.Add(new AuditOption("nonms", "Hide Microsoft apps", "nonms", false));
            section.AddGroup(scope);

            var assignments = new AuditOptionGroup("assignments", "Assignments (slow per-app lookup)", GroupMode.MultiCheck); assignments.Columns = 1;
            assignments.Hint = "One appRoleAssignedTo query per app (users/groups + app role name). Rebuild these in the target tenant or SaaS access breaks silently.";
            assignments.Add(AuditOption.Prop("AssignedUsers", false).MarkSlow());
            section.AddGroup(assignments);

            var provisioning = new AuditOptionGroup("provisioning", "Provisioning (slow per-app lookup)", GroupMode.MultiCheck); provisioning.Columns = 1;
            provisioning.Hint = "Automated user provisioning jobs per app (needs Synchronization.Read.All plus an Application/Cloud Application Administrator role for the auditor).";
            provisioning.Add(AuditOption.Prop("Provisioning", false).MarkSlow());
            section.AddGroup(provisioning);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "sso", "assignments", "provisioning");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantAssign = chosen.Contains("AssignedUsers");
                bool wantProv = chosen.Contains("Provisioning");
                // Microsoft tenant (owner org of first-party apps).
                bool hideMsft = sel.First("scope", "all") == "nonms";

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying enterprise apps (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$sps = @()");
                sb.AppendLine("$uri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=servicePrincipalType eq ''Application''&$select=id,appId,displayName,servicePrincipalType,accountEnabled,preferredSingleSignOnMode,homepage,loginUrl,appRoles,appOwnerOrganizationId&$top=999'");
                sb.AppendLine("while ($uri -and ($maxUsers -lt 0 -or $sps.Count -lt $maxUsers)) {");
                sb.AppendLine("    $r = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $sps += @($r.value)");
                sb.AppendLine("    $uri = $r.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $sps.Count -gt $maxUsers) { $sps = $sps[0..($maxUsers - 1)] }");
                if (hideMsft)
                {
                    sb.AppendLine("$before = $sps.Count");
                    sb.AppendLine("$sps = @($sps | Where-Object { [string]$_.appOwnerOrganizationId -ne '72f988bf-86f1-41af-91ab-2d7cd012db47' })");
                    sb.AppendLine("Write-Host (\"Retrieved {0} service principal(s) ({1} Microsoft-owned hidden).\" -f $sps.Count, ($before - $sps.Count))");
                }
                else
                {
                    sb.AppendLine("Write-Host (\"Retrieved {0} service principal(s).\" -f $sps.Count)");
                }
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("$i = 0");
                if (wantAssign) sb.AppendLine("$asFail = 0");
                if (wantProv) sb.AppendLine("$pjFail = 0");
                sb.AppendLine("foreach ($s in $sps) {");
                sb.AppendLine("    $i++; if (($i % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $i, $sps.Count) }");
                sb.AppendLine("    $sid = [string]$s.id");
                if (wantAssign)
                {
                    sb.AppendLine("    $au = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $al = @(); $auri = \"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $sid + \"/appRoleAssignedTo?`$top=999\"");
                    sb.AppendLine("        while ($auri) { $ax = Invoke-RestMethod -Uri $auri -Headers $headers -Method Get -ErrorAction Stop; $al += @($ax.value); $auri = $ax.'@odata.nextLink' }");
                    sb.AppendLine("        $au = ((@($al) | ForEach-Object { $pn = [string]$_.principalDisplayName; if (-not $pn) { $pn = [string]$_.principalId }; $rn = [string]$_.appRoleId; $m = @($s.appRoles | Where-Object { [string]$_.id -eq $rn })[0]; if ($m) { $rn = [string]$m.displayName; if (-not $rn) { $rn = [string]$m.value } }; $pn + ' (' + [string]$_.principalType + '): ' + $rn } | Sort-Object -Unique) -join ',')");
                    sb.AppendLine("    } catch { $asFail++ }");
                }
                if (wantProv)
                {
                    sb.AppendLine("    $pj = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $jl = @(); $juri = \"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $sid + \"/synchronization/jobs\"");
                    sb.AppendLine("        while ($juri) { $jx = Invoke-RestMethod -Uri $juri -Headers $headers -Method Get -ErrorAction Stop; $jl += @($jx.value); $juri = $jx.'@odata.nextLink' }");
                    sb.AppendLine("        if ($jl.Count -eq 0) { $pj = 'None' }");
                    sb.AppendLine("        else { $pj = ((@($jl) | ForEach-Object { $st = ''; try { $st = [string]$_.schedule.state } catch { }; $iv = ''; try { $iv = [string]$_.schedule.interval } catch { }; $st + ' (' + $iv + ')' } | Sort-Object -Unique) -join ',') }");
                    sb.AppendLine("    } catch { $pjFail++ }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        DisplayName = $s.displayName; AppId = $s.appId; SpType = $s.servicePrincipalType; Enabled = $s.accountEnabled;");
                sb.AppendLine("        SsoMode = $s.preferredSingleSignOnMode; Homepage = $s.homepage; LoginUrl = $s.loginUrl;");
                sb.AppendLine("        AssignedUsers = " + (wantAssign ? "$au" : "''") + "; Provisioning = " + (wantProv ? "$pj" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantAssign) sb.AppendLine("if ($asFail -gt 0) { Write-Host (\"WARNING: {0} assignment querie(s) failed (consent for Application.Read.All?).\" -f $asFail) }");
                if (wantProv) sb.AppendLine("if ($pjFail -gt 0) { Write-Host (\"WARNING: {0} provisioning querie(s) failed (needs Synchronization.Read.All + Application/Cloud Application Administrator role?).\" -f $pjFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 14. CONSENT GRANTS
        // Delegated consent records (admin tenant-wide vs user + who) plus
        // optional application-permission grants per client. Needs
        // Directory.Read.All (+ Application.Read.All for role names; the auditor
        // needs a supported Entra role for the grants API).
        private static AuditSection BuildConsentGrantsSection()
        {
            var section = new AuditSection(
                "entra-consent-grants",
                "Consent grants",
                "Consent grants export",
                "Audit OAuth2 permission grants via Graph: who consented to what, admin tenant-wide vs user consent, plus optional application-permission grants.",
                "key",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraConsentGrants.csv";

            var grant = new AuditOptionGroup("grant", "Grant", GroupMode.MultiCheck); grant.Columns = 2;
            grant.Hint = "Delegated grants come from one oauth2PermissionGrants fetch. The auditor needs a supported Entra role for that API on top of Directory.Read.All.";
            grant.AddProp("ClientApp", true);
            grant.AddProp("ResourceApp", true);
            grant.AddProp("PermissionType", true);
            grant.AddProp("Permissions", true);
            section.AddGroup(grant);

            var consent = new AuditOptionGroup("consent", "Consent", GroupMode.MultiCheck); consent.Columns = 2;
            consent.AddProp("ConsentType", true);
            consent.AddProp("ConsentedBy", true);
            consent.AddProp("ExpiryTime", true);
            section.AddGroup(consent);

            var scope = new AuditOptionGroup("scope", "Scope", GroupMode.SingleChoice); scope.Columns = 1;
            scope.Hint = "Hides rows whose client app is Microsoft-owned (owner org = Microsoft tenant) - first-party noise in a migration audit.";
            scope.Add(new AuditOption("all", "All clients", "all", true));
            scope.Add(new AuditOption("nonms", "Hide Microsoft clients", "nonms", false));
            section.AddGroup(scope);

            var approles = new AuditOptionGroup("approles", "Application permissions (slow lookup)", GroupMode.MultiCheck); approles.Columns = 1;
            approles.Hint = "Application (app-role) grants are read per client service principal - slower on tenants with many apps. Records show the grant, not which admin clicked consent.";
            approles.Add(AuditOption.Prop("AppRoleGrants", false).MarkSlow());
            section.AddGroup(approles);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "grant", "consent", "approles");
                if (chosen.Count == 0) chosen.Add("ClientApp");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantAppRoles = chosen.Contains("AppRoleGrants");
                bool hideMsClients = sel.First("scope", "all") == "nonms";

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying consent grants (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$spCache = @{}");
                sb.AppendLine("$script:spFail = 0");
                sb.AppendLine("function Resolve-SpName {");
                sb.AppendLine("    param($spid)");
                sb.AppendLine("    if ($spCache.ContainsKey($spid)) { return $spCache[$spid] }");
                sb.AppendLine("    $nm = $spid");
                sb.AppendLine("    try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $spid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $nm = [string]$o.displayName } } catch { $script:spFail++ }");
                sb.AppendLine("    $spCache[$spid] = $nm");
                sb.AppendLine("    return $nm");
                sb.AppendLine("}");
                sb.AppendLine("$userCache = @{}");
                sb.AppendLine("function Resolve-GrantUpn {");
                sb.AppendLine("    param($uid)");
                sb.AppendLine("    if ($userCache.ContainsKey($uid)) { return $userCache[$uid] }");
                sb.AppendLine("    $nm = $uid");
                sb.AppendLine("    try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"?`$select=userPrincipalName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.userPrincipalName) { $nm = [string]$o.userPrincipalName } } catch { }");
                sb.AppendLine("    $userCache[$uid] = $nm");
                sb.AppendLine("    return $nm");
                sb.AppendLine("}");
                if (hideMsClients)
                {
                    sb.AppendLine("$ownCache = @{}");
                    sb.AppendLine("function Resolve-SpOwner {");
                    sb.AppendLine("    param($spid)");
                    sb.AppendLine("    if ($ownCache.ContainsKey($spid)) { return $ownCache[$spid] }");
                    sb.AppendLine("    $ow = ''");
                    sb.AppendLine("    try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $spid + \"?`$select=appOwnerOrganizationId\") -Headers $headers -Method Get -ErrorAction Stop; $ow = [string]$o.appOwnerOrganizationId } catch { }");
                    sb.AppendLine("    $ownCache[$spid] = $ow");
                    sb.AppendLine("    return $ow");
                    sb.AppendLine("}");
                    sb.AppendLine("$skipped = 0");
                }
                sb.AppendLine("$grants = @()");
                sb.AppendLine("$guri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants'");
                sb.AppendLine("while ($guri -and ($maxUsers -lt 0 -or $grants.Count -lt $maxUsers)) {");
                sb.AppendLine("    $gr = Invoke-RestMethod -Uri $guri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $grants += @($gr.value)");
                sb.AppendLine("    $guri = $gr.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $grants.Count -gt $maxUsers) { $grants = $grants[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} delegated grant(s).\" -f $grants.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($g in $grants) {");
                if (hideMsClients)
                {
                    sb.AppendLine("    if ((Resolve-SpOwner ([string]$g.clientId)) -eq '72f988bf-86f1-41af-91ab-2d7cd012db47') { $skipped++; continue }");
                }
                sb.AppendLine("    $ct = 'User'; $by = ''; if ([string]$g.consentType -eq 'AllPrincipals') { $ct = 'Admin (tenant-wide)' } else { $by = Resolve-GrantUpn ([string]$g.principalId) }");
                sb.AppendLine("    $sc = [string]$g.scope; if ($sc) { $sc = ($sc -split '\\s+' | Where-Object { $_ -ne '' }) -join ',' }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        ClientApp = (Resolve-SpName ([string]$g.clientId)); ResourceApp = (Resolve-SpName ([string]$g.resourceId)); PermissionType = 'Delegated'; Permissions = $sc;");
                sb.AppendLine("        ConsentType = $ct; ConsentedBy = $by; ExpiryTime = $g.expiryTime");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                if (wantAppRoles)
                {
                    sb.AppendLine("$cls = @()");
                    sb.AppendLine("$curi = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=servicePrincipalType eq ''Application''&$select=id,appId,displayName'");
                    sb.AppendLine("while ($curi) { $cr = Invoke-RestMethod -Uri $curi -Headers $headers -Method Get -ErrorAction Stop; $cls += @($cr.value); $curi = $cr.'@odata.nextLink' }");
                    sb.AppendLine("$resCache = @{}");
                    sb.AppendLine("$arFail = 0");
                    sb.AppendLine("$ci = 0");
                    sb.AppendLine("foreach ($c in $cls) {");
                    sb.AppendLine("    $ci++; if (($ci % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $ci, $cls.Count) }");
                    sb.AppendLine("    $cid = [string]$c.id; $cnm = [string]$c.displayName; if (-not $cnm) { $cnm = $cid }");
                    if (hideMsClients)
                    {
                        sb.AppendLine("    if ((Resolve-SpOwner $cid) -eq '72f988bf-86f1-41af-91ab-2d7cd012db47') { $skipped++; continue }");
                    }
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $al = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $cid + \"/appRoleAssignments\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        foreach ($ar in @($al.value)) {");
                    sb.AppendLine("            $rid = [string]$ar.resourceId; $rnm = [string]$ar.resourceDisplayName; if (-not $rnm) { $rnm = Resolve-SpName $rid }");
                    sb.AppendLine("            $rln = [string]$ar.appRoleId");
                    sb.AppendLine("            try {");
                    sb.AppendLine("                if (-not $resCache.ContainsKey($rid)) { $so = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals/\" + $rid + \"?`$select=appRoles\") -Headers $headers -Method Get -ErrorAction Stop; $resCache[$rid] = $so }");
                    sb.AppendLine("                $m = @($resCache[$rid].appRoles | Where-Object { [string]$_.id -eq $rln })[0]; if ($m) { $rln = [string]$m.displayName; if (-not $rln) { $rln = [string]$m.value } }");
                    sb.AppendLine("            } catch { }");
                    sb.AppendLine("            $rows.Add([pscustomobject]@{");
                    sb.AppendLine("                ClientApp = $cnm; ResourceApp = $rnm; PermissionType = 'Application'; Permissions = $rln;");
                    sb.AppendLine("                ConsentType = 'Admin (app role)'; ConsentedBy = ''; ExpiryTime = ''");
                    sb.AppendLine("            })");
                    sb.AppendLine("        }");
                    sb.AppendLine("    } catch { $arFail++ }");
                    sb.AppendLine("}");
                    sb.AppendLine("if ($arFail -gt 0) { Write-Host (\"WARNING: {0} client(s) without readable app-role grants (consent for Application.Read.All?).\" -f $arFail) }");
                }
                if (hideMsClients) sb.AppendLine("if ($skipped -gt 0) { Write-Host (\"Excluded {0} Microsoft-owned client grant(s).\" -f $skipped) }");
                sb.AppendLine("if ($script:spFail -gt 0) { Write-Host (\"WARNING: {0} service principal(s) could not be resolved to names.\" -f $script:spFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 16. ACCESS PACKAGES
        // Entitlement management: one row per access package with catalog,
        // assignment policies (requestors incl. connected organizations,
        // approval stages, duration - matched locally from one shared fetch)
        // and granted resources (slow per-package lookup). Needs
        // EntitlementManagement.Read.All + the auditor holding Catalog reader
        // (least) or Global/Security/Identity-Governance reader. Placeholder
        // row keeps the CSV headers when governance is not in use.
        private static AuditSection BuildAccessPackagesSection()
        {
            var section = new AuditSection(
                "entra-access-packages",
                "Access packages",
                "Access packages export",
                "Audit entitlement management via Graph: access packages with catalog, assignment policies (requestors, approval, connected organizations) and granted resources (slow per-package lookup).",
                "package",
                AuditScope.Graph);
            section.Category = "Identity Governance";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraAccessPackages.csv";

            var package = new AuditOptionGroup("package", "Package", GroupMode.MultiCheck); package.Columns = 2;
            package.AddProp("PackageName", true);
            package.AddProp("Description", true);
            package.AddProp("IsHidden", true);
            package.AddProp("CreatedDateTime", true);
            package.AddProp("ModifiedDateTime", true);
            section.AddGroup(package);

            var catalog = new AuditOptionGroup("catalog", "Catalog", GroupMode.MultiCheck); catalog.Columns = 2;
            catalog.Hint = "Catalog expanded inline from the packages query - no extra lookup.";
            catalog.AddProp("CatalogName", true);
            catalog.AddProp("CatalogType", true);
            catalog.AddProp("CatalogExternallyVisible", true);
            section.AddGroup(catalog);

            var policies = new AuditOptionGroup("policies", "Assignment policies", GroupMode.MultiCheck); policies.Columns = 1;
            policies.Hint = "Policies matched locally by accessPackageId from one shared fetch. Connected organizations resolved from one shared fetch; user/group approvers via cached lookups.";
            policies.AddProp("PolicyCount", true);
            policies.AddProp("PolicyDetails", true);
            section.AddGroup(policies);

            var resources = new AuditOptionGroup("resources", "Granted resources (slow per-package lookup)", GroupMode.MultiCheck); resources.Columns = 1;
            resources.Hint = "One accessPackageResourceRoleScopes query per package - slower on tenants with many packages. Needs the EntitlementManagement.Read.All consent.";
            resources.Add(AuditOption.Prop("GrantedResources", false).MarkSlow());
            section.AddGroup(resources);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "package", "catalog", "policies", "resources");
                if (chosen.Count == 0) chosen.Add("PackageName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantPols = chosen.Contains("PolicyCount") || chosen.Contains("PolicyDetails");
                bool wantRes = chosen.Contains("GrantedResources");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying entitlement management (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$pkgs = @()");
                sb.AppendLine("$puri = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages?$expand=catalog($select=id,displayName,catalogType,isExternallyVisible)&$select=id,displayName,description,isHidden,createdDateTime,modifiedDateTime'");
                sb.AppendLine("while ($puri -and ($maxUsers -lt 0 -or $pkgs.Count -lt $maxUsers)) {");
                sb.AppendLine("    $pr = Invoke-RestMethod -Uri $puri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $pkgs += @($pr.value)");
                sb.AppendLine("    $puri = $pr.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $pkgs.Count -gt $maxUsers) { $pkgs = $pkgs[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} access package(s).\" -f $pkgs.Count)");
                sb.AppendLine("if ($pkgs.Count -eq 0) { Write-Host 'No access packages found - entitlement management not in use, or consent for EntitlementManagement.Read.All / a Catalog reader role is missing.' }");
                sb.AppendLine("$pols = @()");
                sb.AppendLine("try {");
                sb.AppendLine("    $pouri = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignmentPolicies'");
                sb.AppendLine("    while ($pouri) { $por = Invoke-RestMethod -Uri $pouri -Headers $headers -Method Get -ErrorAction Stop; $pols += @($por.value); $pouri = $por.'@odata.nextLink' }");
                sb.AppendLine("    Write-Host (\"Retrieved {0} assignment policie(s).\" -f $pols.Count)");
                sb.AppendLine("} catch { Write-Host ('WARNING: assignmentPolicies query failed (' + $_.Exception.Message + ' - consent for EntitlementManagement.Read.All?) - policy detail will be empty.') }");
                sb.AppendLine("$orgs = @{}");
                sb.AppendLine("try {");
                sb.AppendLine("    $ouri = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/connectedOrganizations?$select=id,displayName'");
                sb.AppendLine("    while ($ouri) { $orr = Invoke-RestMethod -Uri $ouri -Headers $headers -Method Get -ErrorAction Stop; foreach ($o in @($orr.value)) { $orgs[[string]$o.id] = [string]$o.displayName }; $ouri = $orr.'@odata.nextLink' }");
                sb.AppendLine("} catch { Write-Host 'WARNING: connectedOrganizations query failed (consent for EntitlementManagement.Read.All?) - connected orgs will show raw IDs.' }");
                if (wantPols)
                {
                    sb.AppendLine("$uCache2 = @{}; $gCache3 = @{}");
                    sb.AppendLine("$script:govResFail = 0");
                    sb.AppendLine("function Resolve-GovUser { param($uid) if (-not $uid) { return '' }; if ($uCache2.ContainsKey($uid)) { return $uCache2[$uid] }; $nm = $uid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop; $nm = [string]$o.userPrincipalName; if (-not $nm) { $nm = [string]$o.displayName } } catch { $script:govResFail++ }; $uCache2[$uid] = $nm; return $nm }");
                    sb.AppendLine("function Resolve-GovGroup { param($gid) if (-not $gid) { return '' }; if ($gCache3.ContainsKey($gid)) { return $gCache3[$gid] }; $nm = $gid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $nm = [string]$o.displayName } } catch { $script:govResFail++ }; $gCache3[$gid] = $nm; return $nm }");
                }
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                if (wantRes) sb.AppendLine("$resFail = 0");
                sb.AppendLine("foreach ($p in $pkgs) {");
                sb.AppendLine("    $pkgId = [string]$p.id");
                sb.AppendLine("    $cat = ''; try { $cat = [string]$p.catalog.displayName } catch { }; if (-not $cat) { try { $cat = [string]$p.catalog.id } catch { } }");
                sb.AppendLine("    $cty = ''; try { $cty = [string]$p.catalog.catalogType } catch { }");
                sb.AppendLine("    $cexv = ''; try { $cexv = [string]$p.catalog.isExternallyVisible } catch { }");
                if (wantPols)
                {
                    sb.AppendLine("    $pd = @()");
                    sb.AppendLine("    foreach ($po in @($pols | Where-Object { [string]$_.accessPackageId -eq $pkgId })) {");
                    sb.AppendLine("        $pn = [string]$po.displayName; if (-not $pn) { $pn = [string]$po.id }");
                    sb.AppendLine("        $rq = ''; $tg = ''; $ap = ''; $du = ''");
                    sb.AppendLine("        try {");
                    sb.AppendLine("            $st = [string]$po.requestorSettings.scopeType; if (-not $st) { $st = 'default' }");
                    sb.AppendLine("            $who = @()");
                    sb.AppendLine("            foreach ($r in @($po.requestorSettings.allowedRequestors)) {");
                    sb.AppendLine("                $rt = [string]$r.'@odata.type'; $rv = ''");
                    sb.AppendLine("                if ($rt -match 'singleUser') { $rid2 = [string]$r.id; if (-not $rid2) { $rid2 = [string]$r.userId }; if ($rid2) { $rv = Resolve-GovUser $rid2 } }");
                    sb.AppendLine("                elseif ($rt -match 'groupMembers') { $gid2 = [string]$r.groupId; if ($gid2) { $rv = 'group:' + (Resolve-GovGroup $gid2) } }");
                    sb.AppendLine("                elseif ($rt -match 'connectedOrganizationMembers') { $oid = [string]$r.connectedOrganizationId; $on = $oid; if ($oid -and $orgs.ContainsKey($oid)) { $on = $orgs[$oid] }; if ($oid) { $rv = 'org:' + $on } }");
                    sb.AppendLine("                elseif ($rt -match 'requestorManager') { $rv = 'manager' }");
                    sb.AppendLine("                elseif ($rt -match 'internalSponsors') { $rv = 'internalSponsors' }");
                    sb.AppendLine("                elseif ($rt -match 'externalSponsors') { $rv = 'externalSponsors' }");
                    sb.AppendLine("                elseif ($rt -ne '') { $rv = ($rt -split '\\.')[-1] }");
                    sb.AppendLine("                if ($rv -ne '') { $who += $rv }");
                    sb.AppendLine("            }");
                    sb.AppendLine("            $who = @($who | Sort-Object -Unique)");
                    sb.AppendLine("            $rq = $st; if ($who.Count -gt 0) { $rq = $st + ' (' + ($who -join ', ') + ')' }");
                    sb.AppendLine("        } catch { }");
                    sb.AppendLine("        try { $tg = [string]$po.allowedTargetScope } catch { }");
                    sb.AppendLine("        try {");
                    sb.AppendLine("            $am = [string]$po.approvalSettings.approvalMode");
                    sb.AppendLine("            $stgs = @(); $si = 0");
                    sb.AppendLine("            foreach ($sg in @($po.approvalSettings.approvalStages)) {");
                    sb.AppendLine("                $si++");
                    sb.AppendLine("                $td = ''; try { $td = [string]$sg.approvalStageTimeOutInDays; if ($td) { $td = $td + 'd' } } catch { }");
                    sb.AppendLine("                $avs = @()");
                    sb.AppendLine("                foreach ($av in @($sg.primaryApprovers)) {");
                    sb.AppendLine("                    $at2 = [string]$av.'@odata.type'; $an = ''");
                    sb.AppendLine("                    if ($at2 -match 'singleUser') { $aid = [string]$av.id; if (-not $aid) { $aid = [string]$av.userId }; if ($aid) { $an = Resolve-GovUser $aid } }");
                    sb.AppendLine("                    elseif ($at2 -match 'groupMembers') { $agd = [string]$av.groupId; if ($agd) { $an = 'group:' + (Resolve-GovGroup $agd) } }");
                    sb.AppendLine("                    elseif ($at2 -ne '') { $an = ($at2 -split '\\.')[-1] }");
                    sb.AppendLine("                    if ($an -ne '') { $avs += $an }");
                    sb.AppendLine("                }");
                    sb.AppendLine("                $avs = @($avs | Sort-Object -Unique)");
                    sb.AppendLine("                $sl = 'stage' + $si; if ($td) { $sl = $sl + ' ' + $td }; if ($avs.Count -gt 0) { $sl = $sl + ': ' + ($avs -join ', ') }");
                    sb.AppendLine("                $stgs += $sl");
                    sb.AppendLine("            }");
                    sb.AppendLine("            $ap = $am; if ($stgs.Count -gt 0) { if ($ap) { $ap = $ap + ' [' + ($stgs -join ' | ') + ']' } else { $ap = ($stgs -join ' | ') } }");
                    sb.AppendLine("        } catch { }");
                    sb.AppendLine("        try { $dd = $po.durationInDays; if (($null -ne $dd) -and (([string]$dd) -ne '')) { $du = [string]$dd + 'd' }; try { if ([bool]$po.canExtend) { if ($du) { $du = $du + ' (extendable)' } else { $du = 'extendable' } } } catch { } } catch { }");
                    sb.AppendLine("        $pd += ($pn + ' | requestors: ' + $rq + ' | target: ' + $tg + ' | approval: ' + $ap + ' | duration: ' + $du)");
                    sb.AppendLine("    }");
                    sb.AppendLine("    $pc = $pd.Count");
                    sb.AppendLine("    $pdet = ($pd -join '; ')");
                }
                if (wantRes)
                {
                    sb.AppendLine("    $gr = ''");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $gl = @(); $guri = \"https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/\" + $pkgId + \"/accessPackageResourceRoleScopes?`$expand=accessPackageResourceRole,accessPackageResourceScope\"");
                    sb.AppendLine("        while ($guri) { $grr = Invoke-RestMethod -Uri $guri -Headers $headers -Method Get -ErrorAction Stop; $gl += @($grr.value); $guri = $grr.'@odata.nextLink' }");
                    sb.AppendLine("        $gr = ((@($gl | ForEach-Object { $rn = ''; try { $rn = [string]$_.accessPackageResourceRole.displayName } catch { }; $sn = ''; try { $sn = [string]$_.accessPackageResourceScope.displayName } catch { }; if (-not $sn) { try { $sn = [string]$_.accessPackageResourceScope.originId } catch { } }; $pair = ''; if ($rn -and $sn) { $pair = $rn + ' on ' + $sn } elseif ($sn) { $pair = $sn } elseif ($rn) { $pair = $rn }; $pair } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join '; ')");
                    sb.AppendLine("    } catch { $resFail++ }");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        PackageName = $p.displayName; Description = $p.description; IsHidden = $p.isHidden; CreatedDateTime = $p.createdDateTime; ModifiedDateTime = $p.modifiedDateTime;");
                sb.AppendLine("        CatalogName = $cat; CatalogType = $cty; CatalogExternallyVisible = $cexv;");
                sb.AppendLine("        PolicyCount = " + (wantPols ? "$pc" : "''") + "; PolicyDetails = " + (wantPols ? "$pdet" : "''") + "; GrantedResources = " + (wantRes ? "$gr" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ PackageName = ''; Description = ''; IsHidden = ''; CreatedDateTime = ''; ModifiedDateTime = ''; CatalogName = ''; CatalogType = ''; CatalogExternallyVisible = ''; PolicyCount = ''; PolicyDetails = ''; GrantedResources = '' }) }");
                if (wantPols) sb.AppendLine("if ($script:govResFail -gt 0) { Write-Host (\"WARNING: {0} user/group reference(s) could not be resolved to names.\" -f $script:govResFail) }");
                if (wantRes) sb.AppendLine("if ($resFail -gt 0) { Write-Host (\"WARNING: {0} resource-scope querie(s) failed (consent for EntitlementManagement.Read.All?).\" -f $resFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 17. ACCESS REVIEWS
        // Recurring reviews on groups, apps and PIM roles: one row per review
        // definition with resolved scope, schedule, reviewers/fallback and
        // decision settings. Multi-stage reviews (StageCount > 0) use per-stage
        // reviewers/settings - the top-level columns then show the definition
        // defaults. Needs AccessReview.Read.All (already required).
        private static AuditSection BuildAccessReviewsSection()
        {
            var section = new AuditSection(
                "entra-access-reviews",
                "Access reviews",
                "Access reviews export",
                "Audit recurring access reviews via Graph: scope (groups, apps, PIM roles), schedule, reviewers and decision settings (one row per review definition).",
                "review",
                AuditScope.Graph);
            section.Category = "Identity Governance";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraAccessReviews.csv";

            var identity = new AuditOptionGroup("identity", "Review", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("DefinitionName", true);
            identity.AddProp("Description", true);
            identity.AddProp("Status", true);
            section.AddGroup(identity);

            var scope = new AuditOptionGroup("scope", "Scope", GroupMode.MultiCheck); scope.Columns = 1;
            scope.Hint = "ScopeQuery is the raw Graph query; ReviewScope resolves embedded user/group IDs to names via cached lookups (instanceEnumerationScope appended for guest-across-groups reviews).";
            scope.AddProp("ReviewScope", true);
            scope.AddProp("ScopeQuery", true);
            section.AddGroup(scope);

            var schedule = new AuditOptionGroup("schedule", "Schedule", GroupMode.MultiCheck); schedule.Columns = 2;
            schedule.AddProp("Schedule", true);
            schedule.AddProp("StartDate", true);
            schedule.AddProp("StageCount", true);
            section.AddGroup(schedule);

            var reviewers = new AuditOptionGroup("reviewers", "Reviewers", GroupMode.MultiCheck); reviewers.Columns = 1;
            reviewers.Hint = "Specific users/groups resolved to names via cached lookups; well-known reviewer scopes (managers, group owners) kept literal.";
            reviewers.AddProp("Reviewers", true);
            reviewers.AddProp("FallbackReviewers", true);
            section.AddGroup(reviewers);

            var settings = new AuditOptionGroup("settings", "Decision settings", GroupMode.MultiCheck); settings.Columns = 2;
            settings.AddProp("AutoApplyDecisions", true);
            settings.AddProp("DefaultDecision", true);
            settings.AddProp("MailNotifications", true);
            settings.AddProp("JustificationRequired", true);
            section.AddGroup(settings);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "scope", "schedule", "reviewers", "settings");
                if (chosen.Count == 0) chosen.Add("DefinitionName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying access reviews (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$defs = @()");
                sb.AppendLine("$duri = 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions'");
                sb.AppendLine("while ($duri -and ($maxUsers -lt 0 -or $defs.Count -lt $maxUsers)) {");
                sb.AppendLine("    $dr = Invoke-RestMethod -Uri $duri -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("    $defs += @($dr.value)");
                sb.AppendLine("    $duri = $dr.'@odata.nextLink'");
                sb.AppendLine("}");
                sb.AppendLine("if ($maxUsers -ge 0 -and $defs.Count -gt $maxUsers) { $defs = $defs[0..($maxUsers - 1)] }");
                sb.AppendLine("Write-Host (\"Retrieved {0} access review definition(s).\" -f $defs.Count)");
                sb.AppendLine("if ($defs.Count -eq 0) { Write-Host 'No access review definitions found - reviews not in use, or consent for AccessReview.Read.All is missing.' }");
                sb.AppendLine("$pkgMap = @{}; $polMap = @{}");
                sb.AppendLine("try {");
                sb.AppendLine("    $puri2 = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages?$select=id,displayName'");
                sb.AppendLine("    while ($puri2) { $pr2 = Invoke-RestMethod -Uri $puri2 -Headers $headers -Method Get -ErrorAction Stop; foreach ($x in @($pr2.value)) { $pkgMap[[string]$x.id] = [string]$x.displayName }; $puri2 = $pr2.'@odata.nextLink' }");
                sb.AppendLine("    $pouri2 = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignmentPolicies?$select=id,displayName'");
                sb.AppendLine("    while ($pouri2) { $por2 = Invoke-RestMethod -Uri $pouri2 -Headers $headers -Method Get -ErrorAction Stop; foreach ($x in @($por2.value)) { $polMap[[string]$x.id] = [string]$x.displayName }; $pouri2 = $por2.'@odata.nextLink' }");
                sb.AppendLine("} catch { }");
                sb.AppendLine("$uCache3 = @{}; $gCache4 = @{}");
                sb.AppendLine("$script:revResFail = 0");
                sb.AppendLine("function Resolve-RevName {");
                sb.AppendLine("    param($q)");
                sb.AppendLine("    $out = [string]$q");
                sb.AppendLine("    $out = $out -replace '^/(v1\\.0|beta)(?=/|$)', ''");
                sb.AppendLine("    try {");
                sb.AppendLine("        foreach ($m in @([regex]::Matches($out, '/users/([0-9a-fA-F\\-]{36})'))) {");
                sb.AppendLine("            $uid = $m.Groups[1].Value");
                sb.AppendLine("            if (-not $uCache3.ContainsKey($uid)) { $un = $uid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop; $un = [string]$o.userPrincipalName; if (-not $un) { $un = [string]$o.displayName } } catch { $script:revResFail++ }; $uCache3[$uid] = $un }");
                sb.AppendLine("            $out = $out.Replace($m.Value, $uCache3[$uid])");
                sb.AppendLine("        }");
                sb.AppendLine("        foreach ($m in @([regex]::Matches($out, '/groups/([0-9a-fA-F\\-]{36})'))) {");
                sb.AppendLine("            $gid = $m.Groups[1].Value");
                sb.AppendLine("            if (-not $gCache4.ContainsKey($gid)) { $gn = $gid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $gn = [string]$o.displayName } } catch { $script:revResFail++ }; $gCache4[$gid] = $gn }");
                sb.AppendLine("            $out = $out.Replace($m.Value, $gCache4[$gid])");
                sb.AppendLine("        }");
                sb.AppendLine("        foreach ($m in @([regex]::Matches($out, \"accessPackage/id eq '([0-9a-fA-F\\\\-]{36})'\"))) {");
                sb.AppendLine("            $ak = $m.Groups[1].Value; $an2 = $ak; if ($pkgMap.ContainsKey($ak)) { $an2 = $pkgMap[$ak] }");
                sb.AppendLine("            $out = $out.Replace($m.Value, 'package:' + $an2)");
                sb.AppendLine("        }");
                sb.AppendLine("        foreach ($m in @([regex]::Matches($out, \"assignmentPolicy/id eq '([0-9a-fA-F\\\\-]{36})'\"))) {");
                sb.AppendLine("            $lk = $m.Groups[1].Value; $ln2 = $lk; if ($polMap.ContainsKey($lk)) { $ln2 = $polMap[$lk] }");
                sb.AppendLine("            $out = $out.Replace($m.Value, 'policy:' + $ln2)");
                sb.AppendLine("        }");
                sb.AppendLine("        foreach ($m in @([regex]::Matches($out, \"/accessPackageAssignmentPolicies/([0-9a-fA-F\\\\-]{36})\"))) {");
                sb.AppendLine("            $jk = $m.Groups[1].Value; $jn2 = $jk; if ($polMap.ContainsKey($jk)) { $jn2 = $polMap[$jk] }");
                sb.AppendLine("            $out = $out.Replace($m.Value, 'policy:' + $jn2)");
                sb.AppendLine("        }");
                sb.AppendLine("    } catch { }");
                sb.AppendLine("    return $out");
                sb.AppendLine("}");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($d in $defs) {");
                sb.AppendLine("    $sq = ''; try { $sq = [string]$d.scope.query } catch { }");
                sb.AppendLine("    $sqr = $sq -replace '^/(v1\\.0|beta)(?=/|$)', ''");
                sb.AppendLine("    $sqt = ''; try { $sqt = [string]$d.scope.queryType } catch { }");
                sb.AppendLine("    $scope2 = $sq; if (-not $scope2) { $scope2 = $sqt } else { $scope2 = Resolve-RevName $sq }");
                sb.AppendLine("    try { $iq = [string]$d.instanceEnumerationScope.query; if ($iq) { $ies = 'instances: ' + (Resolve-RevName $iq); if ($scope2) { $scope2 = $scope2 + '; ' + $ies } else { $scope2 = $ies } } } catch { }");
                sb.AppendLine("    $rv = ((@($d.reviewers | ForEach-Object { $q = ''; try { $q = [string]$_.query } catch { }; if (-not $q) { try { $q = [string]$_.queryType } catch { } }; if ($q) { Resolve-RevName $q } else { '' } } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ')");
                sb.AppendLine("    $fr = ((@($d.fallbackReviewers | ForEach-Object { $q = ''; try { $q = [string]$_.query } catch { }; if (-not $q) { try { $q = [string]$_.queryType } catch { } }; if ($q) { Resolve-RevName $q } else { '' } } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ')");
                sb.AppendLine("    $rec = ''; $rng = ''; $sdt = ''");
                sb.AppendLine("    try { $rp = $d.settings.recurrence.pattern; if ([string]$rp.type) { $rec = [string]$rp.type + ' every ' + [string]$rp.interval } } catch { }");
                sb.AppendLine("    try { $rr = $d.settings.recurrence.range; if ([string]$rr.type) { $rng = [string]$rr.type }; try { if ([string]$rr.startDate) { $sdt = [string]$rr.startDate } } catch { } } catch { }");
                sb.AppendLine("    $sch = $rec; if ($rng) { if ($sch) { $sch = $sch + ' (' + $rng + ')' } else { $sch = $rng } }");
                sb.AppendLine("    $stg = 0; try { $stg = @($d.stageSettings).Count } catch { }");
                sb.AppendLine("    $aa = ''; try { $aa = [string]$d.settings.autoApplyDecisionsEnabled } catch { }");
                sb.AppendLine("    $dd2 = ''; try { if ([bool]$d.settings.defaultDecisionEnabled) { $dd2 = [string]$d.settings.defaultDecision } } catch { }");
                sb.AppendLine("    $mn = ''; try { $mn = [string]$d.settings.mailNotificationsEnabled } catch { }");
                sb.AppendLine("    $jr = ''; try { $jr = [string]$d.settings.justificationRequiredOnApproval } catch { }");
                sb.AppendLine("    $desc = ''; try { $desc = [string]$d.descriptionForAdmins } catch { }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        DefinitionName = $d.displayName; Description = $desc; Status = $d.status;");
                sb.AppendLine("        ReviewScope = $scope2; ScopeQuery = $sqr;");
                sb.AppendLine("        Schedule = $sch; StartDate = $sdt; StageCount = $stg;");
                sb.AppendLine("        Reviewers = $rv; FallbackReviewers = $fr;");
                sb.AppendLine("        AutoApplyDecisions = $aa; DefaultDecision = $dd2; MailNotifications = $mn; JustificationRequired = $jr");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ DefinitionName = ''; Description = ''; Status = ''; ReviewScope = ''; ScopeQuery = ''; Schedule = ''; StartDate = ''; StageCount = ''; Reviewers = ''; FallbackReviewers = ''; AutoApplyDecisions = ''; DefaultDecision = ''; MailNotifications = ''; JustificationRequired = '' }) }");
                sb.AppendLine("if ($script:revResFail -gt 0) { Write-Host (\"WARNING: {0} reviewer/scope reference(s) could not be resolved to names.\" -f $script:revResFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 18. CUSTOM ATTRIBUTES
        // Custom security attributes: one row per attribute definition
        // (attribute set + name/type/status/flags/allowed values) plus
        // user assignments aggregated from slow per-user
        // customSecurityAttributes lookups. Needs
        // CustomSecAttributeDefinition.Read.All (+
        // CustomSecAttributeAssignment.Read.All for the assignments) AND the
        // auditor holding Attribute Definition Reader (least), Attribute
        // Assignment/Definition Administrator - Global Admin alone 403s.
        // Service-principal assignments are out of scope (users only).
        private static AuditSection BuildCustomAttributesSection()
        {
            var section = new AuditSection(
                "entra-custom-attributes",
                "Custom attributes",
                "Custom attributes export",
                "Audit Entra custom security attributes via Graph: attribute definitions (set, type, status, allowed values) plus user assignments (slow per-user lookup).",
                "tag",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraCustomAttributes.csv";

            var definition = new AuditOptionGroup("definition", "Definition", GroupMode.MultiCheck); definition.Columns = 2;
            definition.AddProp("AttributeSet", true);
            definition.AddProp("AttributeName", true);
            definition.AddProp("Description", true);
            definition.AddProp("Type", true);
            definition.AddProp("Status", true);
            definition.AddProp("IsCollection", true);
            definition.AddProp("IsSearchable", true);
            definition.AddProp("PredefinedValuesOnly", true);
            definition.AddProp("AllowedValues", true);
            section.AddGroup(definition);

            var assignments = new AuditOptionGroup("assignments", "User assignments (slow per-user lookup)", GroupMode.MultiCheck); assignments.Columns = 1;
            assignments.Hint = "One customSecurityAttributes query per user - slower on large tenants (Result size caps it). Needs the CustomSecAttributeAssignment.Read.All consent. Values themselves are not exported, only who carries them; service-principal assignments are out of scope.";
            assignments.Add(AuditOption.Prop("AssignedCount", true).MarkSlow());
            assignments.Add(AuditOption.Prop("AssignedTo", true).MarkSlow());
            section.AddGroup(assignments);

            PsScriptHelpers.AddSizeGroup(section);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "definition", "assignments");
                if (chosen.Count == 0) chosen.Add("AttributeName");
                string selectList = string.Join(", ", chosen.ToArray());
                string size = sel.First("size", "Unlimited");
                bool wantAssign = chosen.Contains("AssignedCount") || chosen.Contains("AssignedTo");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying custom security attributes (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine(SizePrelude(size));
                sb.AppendLine("$defs = @()");
                sb.AppendLine("$duri = 'https://graph.microsoft.com/v1.0/directory/customSecurityAttributeDefinitions?$expand=allowedValues'");
                sb.AppendLine("while ($duri) { $dr = Invoke-RestMethod -Uri $duri -Headers $headers -Method Get -ErrorAction Stop; $defs += @($dr.value); $duri = $dr.'@odata.nextLink' }");
                sb.AppendLine("Write-Host (\"Retrieved {0} attribute definition(s).\" -f $defs.Count)");
                sb.AppendLine("if ($defs.Count -eq 0) { Write-Host 'No custom security attribute definitions found - none defined, or consent for CustomSecAttributeDefinition.Read.All / an Attribute Definition Reader role is missing (Global Admin alone is not enough).' }");
                if (wantAssign)
                {
                    sb.AppendLine("$asgMap = @{}");
                    sb.AppendLine("$users = @()");
                    sb.AppendLine("$uuri = 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName&$top=999'");
                    sb.AppendLine("while ($uuri -and ($maxUsers -lt 0 -or $users.Count -lt $maxUsers)) {");
                    sb.AppendLine("    $ur = Invoke-RestMethod -Uri $uuri -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("    $users += @($ur.value)");
                    sb.AppendLine("    $uuri = $ur.'@odata.nextLink'");
                    sb.AppendLine("}");
                    sb.AppendLine("if ($maxUsers -ge 0 -and $users.Count -gt $maxUsers) { $users = $users[0..($maxUsers - 1)] }");
                    sb.AppendLine("Write-Host (\"Scanning customSecurityAttributes of {0} user(s)...\" -f $users.Count)");
                    sb.AppendLine("$ui = 0; $asgFail = 0");
                    sb.AppendLine("foreach ($u in $users) {");
                    sb.AppendLine("    $ui++; if (($ui % 20) -eq 0) { Write-Host (\"  ... {0}/{1}\" -f $ui, $users.Count) }");
                    sb.AppendLine("    $uid = [string]$u.id; $upn = [string]$u.userPrincipalName; if (-not $upn) { $upn = $uid }");
                    sb.AppendLine("    try {");
                    sb.AppendLine("        $cu = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $uid + \"?`$select=customSecurityAttributes\") -Headers $headers -Method Get -ErrorAction Stop");
                    sb.AppendLine("        foreach ($sp in @($cu.customSecurityAttributes.PSObject.Properties)) {");
                    sb.AppendLine("            $set = [string]$sp.Name; if (-not $set -or $set -eq '@odata.type') { continue }");
                    sb.AppendLine("            foreach ($ap in @($sp.Value.PSObject.Properties)) {");
                    sb.AppendLine("                $ak = $set + '_' + [string]$ap.Name");
                    sb.AppendLine("                if (-not $asgMap.ContainsKey($ak)) { $asgMap[$ak] = New-Object System.Collections.Generic.List[string] }");
                    sb.AppendLine("                if ($asgMap[$ak] -notcontains $upn) { $asgMap[$ak].Add($upn) }");
                    sb.AppendLine("            }");
                    sb.AppendLine("        }");
                    sb.AppendLine("    } catch { $asgFail++ }");
                    sb.AppendLine("}");
                }
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($d in $defs) {");
                sb.AppendLine("    $av = ((@($d.allowedValues | ForEach-Object { $v = [string]$_.id; try { if ([bool]$_.isActive -eq $false) { $v = $v + ' (inactive)' } } catch { }; $v } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ')");
                if (wantAssign)
                {
                    sb.AppendLine("    $akey = [string]$d.id; $alist = @(); if ($asgMap.ContainsKey($akey)) { $alist = @($asgMap[$akey] | Sort-Object -Unique) }");
                    sb.AppendLine("    $acount = $alist.Count; $ato = ($alist -join ', ')");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        AttributeSet = $d.attributeSet; AttributeName = $d.name; Description = $d.description; Type = $d.type; Status = $d.status;");
                sb.AppendLine("        IsCollection = $d.isCollection; IsSearchable = $d.isSearchable; PredefinedValuesOnly = $d.usePreDefinedValuesOnly; AllowedValues = $av;");
                sb.AppendLine("        AssignedCount = " + (chosen.Contains("AssignedCount") ? "$acount" : "''") + "; AssignedTo = " + (chosen.Contains("AssignedTo") ? "$ato" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ AttributeSet = ''; AttributeName = ''; Description = ''; Type = ''; Status = ''; IsCollection = ''; IsSearchable = ''; PredefinedValuesOnly = ''; AllowedValues = ''; AssignedCount = ''; AssignedTo = '' }) }");
                if (wantAssign) sb.AppendLine("if ($asgFail -gt 0) { Write-Host (\"WARNING: {0} assignment querie(s) failed (consent for CustomSecAttributeAssignment.Read.All?).\" -f $asgFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 19. ORGANIZATION PROFILE
        // Tenant-wide identity settings: one row from GET /organization
        // (technical/privacy contacts, tenant type, locale). Needs
        // Organization.Read.All (already required).
        private static AuditSection BuildOrgProfileSection()
        {
            var section = new AuditSection(
                "entra-org-profile",
                "Organization profile",
                "Organization profile export",
                "Audit tenant-wide organization settings via Graph: technical and privacy contacts, tenant type and locale (one row).",
                "tenant",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraOrgProfile.csv";

            var identity = new AuditOptionGroup("identity", "Tenant", GroupMode.MultiCheck); identity.Columns = 2;
            identity.AddProp("DisplayName", true);
            identity.AddProp("TenantId", true);
            identity.AddProp("TenantType", true);
            identity.AddProp("CreatedDateTime", true);
            section.AddGroup(identity);

            var contact = new AuditOptionGroup("contact", "Technical & privacy contacts", GroupMode.MultiCheck); contact.Columns = 1;
            contact.AddProp("TechnicalNotificationMails", true);
            contact.AddProp("MarketingNotificationEmails", true);
            contact.AddProp("PrivacyContactEmail", true);
            contact.AddProp("PrivacyStatementUrl", true);
            contact.AddProp("SecurityComplianceNotificationMails", true);
            contact.AddProp("SecurityComplianceNotificationPhones", true);
            section.AddGroup(contact);

            var locale = new AuditOptionGroup("locale", "Locale", GroupMode.MultiCheck); locale.Columns = 2;
            locale.AddProp("CountryLetterCode", true);
            locale.AddProp("PreferredLanguage", true);
            section.AddGroup(locale);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "identity", "contact", "locale");
                if (chosen.Count == 0) chosen.Add("DisplayName");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying organization profile (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$orgs = @()");
                sb.AppendLine("try { $or = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/organization' -Headers $headers -Method Get -ErrorAction Stop; $orgs = @($or.value) } catch { Write-Host ('WARNING: organization query failed (' + $_.Exception.Message + ' - consent for Organization.Read.All?)') }");
                sb.AppendLine("Write-Host (\"Retrieved {0} organization record(s).\" -f $orgs.Count)");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($o in $orgs) {");
                sb.AppendLine("    $tn = ((@($o.technicalNotificationMails) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("    $mn = ((@($o.marketingNotificationEmails) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("    $pc = ''; try { $pc = [string]$o.privacyProfile.contactEmail } catch { }");
                sb.AppendLine("    $ps = ''; try { $ps = [string]$o.privacyProfile.statementUrl } catch { }");
                sb.AppendLine("    $sm = ((@($o.securityComplianceNotificationMails) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("    $sp2 = ((@($o.securityComplianceNotificationPhones) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        DisplayName = $o.displayName; TenantId = $o.id; TenantType = $o.tenantType; CreatedDateTime = $o.createdDateTime;");
                sb.AppendLine("        TechnicalNotificationMails = $tn; MarketingNotificationEmails = $mn; PrivacyContactEmail = $pc; PrivacyStatementUrl = $ps;");
                sb.AppendLine("        SecurityComplianceNotificationMails = $sm; SecurityComplianceNotificationPhones = $sp2;");
                sb.AppendLine("        CountryLetterCode = $o.countryLetterCode; PreferredLanguage = $o.preferredLanguage");
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ DisplayName = ''; TenantId = ''; TenantType = ''; CreatedDateTime = ''; TechnicalNotificationMails = ''; MarketingNotificationEmails = ''; PrivacyContactEmail = ''; PrivacyStatementUrl = ''; SecurityComplianceNotificationMails = ''; SecurityComplianceNotificationPhones = ''; CountryLetterCode = ''; PreferredLanguage = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 20. COMPANY BRANDING
        // Sign-in customization: default branding text + which logos/images
        // are configured, plus locale overrides count. GET /organization
        // (for the id) then /organization/{id}/branding with
        // Accept-Language: 0 - 404 means unconfigured (placeholder row).
        // Needs Organization.Read.All (already required) + the auditor
        // holding Global Reader or Organizational Branding Administrator.
        private static AuditSection BuildBrandingSection()
        {
            var section = new AuditSection(
                "entra-branding",
                "Company branding",
                "Company branding export",
                "Audit sign-in customization via Graph: branding text and configured logos/images (default locale) plus locale overrides (one row).",
                "brand",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraBranding.csv";

            var text = new AuditOptionGroup("text", "Branding text", GroupMode.MultiCheck); text.Columns = 1;
            text.AddProp("SignInPageText", true);
            text.AddProp("UsernameHintText", true);
            text.AddProp("BackgroundColor", true);
            section.AddGroup(text);

            var images = new AuditOptionGroup("images", "Logos & images (configured?)", GroupMode.MultiCheck); images.Columns = 2;
            images.Hint = "Whether each image slot is set (image bytes are portal-only, never exported).";
            images.AddProp("BannerLogo", true);
            images.AddProp("SquareLogo", true);
            images.AddProp("BackgroundImage", true);
            images.AddProp("CustomCSS", true);
            section.AddGroup(images);

            var locales = new AuditOptionGroup("locales", "Locale overrides", GroupMode.MultiCheck); locales.Columns = 1;
            locales.Hint = "One extra query listing locale-specific branding overrides.";
            locales.AddProp("LocalizationCount", true);
            locales.AddProp("Localizations", true);
            section.AddGroup(locales);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "text", "images", "locales");
                if (chosen.Count == 0) chosen.Add("SignInPageText");
                string selectList = string.Join(", ", chosen.ToArray());
                bool wantLocales = chosen.Contains("LocalizationCount") || chosen.Contains("Localizations");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying company branding (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$bheaders = $headers.Clone(); $bheaders['Accept-Language'] = '0'");
                sb.AppendLine("$oid = ''");
                sb.AppendLine("try { $oo = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id' -Headers $headers -Method Get -ErrorAction Stop; $oid = [string](@($oo.value)[0].id) } catch { Write-Host ('WARNING: organization id query failed (' + $_.Exception.Message + ' - consent for Organization.Read.All?)') }");
                sb.AppendLine("$br = $null");
                sb.AppendLine("if ($oid) { try { $br = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/organization/\" + $oid + \"/branding\") -Headers $bheaders -Method Get -ErrorAction Stop } catch { if ([string]$_.Exception.Message -match '404') { Write-Host 'No company branding configured (404) - placeholder row exported.' } else { Write-Host ('WARNING: branding query failed (' + $_.Exception.Message + ' - consent for Organization.Read.All + a Global Reader or Organizational Branding Administrator role?)') } } }");
                if (wantLocales)
                {
                    sb.AppendLine("$locs = @()");
                    sb.AppendLine("if ($oid -and $br) { try { $lr = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/organization/\" + $oid + \"/branding/localizations\") -Headers $bheaders -Method Get -ErrorAction Stop; $locs = @($lr.value) } catch { Write-Host ('WARNING: branding localizations query failed (' + $_.Exception.Message + ')') } }");
                    sb.AppendLine("$lc = $locs.Count; $ln = ((@($locs | ForEach-Object { [string]$_.id } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ')");
                }
                sb.AppendLine("$yn = { param($u) if ($u) { 'Yes' } else { 'No' } }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("if ($br) {");
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        SignInPageText = $br.signInPageText; UsernameHintText = $br.usernameHintText; BackgroundColor = $br.backgroundColor;");
                sb.AppendLine("        BannerLogo = (& $yn $br.bannerLogoRelativeUrl); SquareLogo = (& $yn $br.squareLogoRelativeUrl); BackgroundImage = (& $yn $br.backgroundImageRelativeUrl); CustomCSS = (& $yn $br.customCSSRelativeUrl);");
                sb.AppendLine("        LocalizationCount = " + (chosen.Contains("LocalizationCount") ? "$lc" : "''") + "; Localizations = " + (chosen.Contains("Localizations") ? "$ln" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ SignInPageText = ''; UsernameHintText = ''; BackgroundColor = ''; BannerLogo = ''; SquareLogo = ''; BackgroundImage = ''; CustomCSS = ''; LocalizationCount = ''; Localizations = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 21. SECURITY DEFAULTS
        // One row from GET /policies/identitySecurityDefaultsEnforcementPolicy
        // (isEnabled). Mutually exclusive with Conditional Access - when any
        // CA policy is enabled, Security Defaults must be off (and vice
        // versa). Needs Policy.Read.All (already required).
        private static AuditSection BuildSecurityDefaultsSection()
        {
            var section = new AuditSection(
                "entra-security-defaults",
                "Security defaults",
                "Security defaults export",
                "Audit Security Defaults state via Graph (one row): enabled or not. Mutually exclusive with Conditional Access policies.",
                "toggle",
                AuditScope.Graph);
            section.Category = "Tenant Settings";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraSecurityDefaults.csv";

            var state = new AuditOptionGroup("state", "State", GroupMode.MultiCheck); state.Columns = 1;
            state.AddProp("IsEnabled", true);
            state.AddProp("DisplayName", true);
            state.AddProp("Description", true);
            section.AddGroup(state);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "state");
                if (chosen.Count == 0) chosen.Add("IsEnabled");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying Security Defaults policy (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$pol = $null");
                sb.AppendLine("try { $pol = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -Headers $headers -Method Get -ErrorAction Stop } catch { Write-Host ('WARNING: Security Defaults query failed (' + $_.Exception.Message + ' - consent for Policy.Read.All?)') }");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("if ($pol) {");
                sb.AppendLine("    $rows.Add([pscustomobject]@{ IsEnabled = $pol.isEnabled; DisplayName = $pol.displayName; Description = $pol.description })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ IsEnabled = ''; DisplayName = ''; Description = '' }) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 22. PIM GROUP ASSIGNMENTS
        // PIM for Groups (distinct from PIM for directory roles in
        // entra-pim-settings / entra-role-assignments): one row per eligible
        // or active schedule on role-assignable groups, with resolved group
        // and principal names plus schedule window. Skips revoked/cancelled/
        // denied/failed schedules. Needs PrivilegedEligibilitySchedule.
        // Read.AzureADGroup + PrivilegedAssignmentSchedule.Read.AzureADGroup
        // (already required).
        private static AuditSection BuildPimGroupsSection()
        {
            var section = new AuditSection(
                "entra-pim-groups",
                "PIM group assignments",
                "PIM group assignments export",
                "Audit PIM for Groups via Graph: eligible vs active member/owner schedules on role-assignable groups (one row per schedule).",
                "pim",
                AuditScope.Graph);
            section.Category = "Identity Governance";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraPimGroups.csv";

            var group = new AuditOptionGroup("group", "Group", GroupMode.MultiCheck); group.Columns = 1;
            group.AddProp("GroupName", true);
            section.AddGroup(group);

            var assignment = new AuditOptionGroup("assignment", "Assignment", GroupMode.MultiCheck); assignment.Columns = 2;
            assignment.Hint = "Principals resolved to UPNs (users) or display names (groups) via cached lookups.";
            assignment.AddProp("PrincipalName", true);
            assignment.AddProp("PrincipalType", true);
            assignment.AddProp("MemberType", true);
            assignment.AddProp("AssignmentType", true);
            section.AddGroup(assignment);

            var schedule = new AuditOptionGroup("schedule", "Schedule", GroupMode.MultiCheck); schedule.Columns = 2;
            schedule.Hint = "From the PIM scheduleInfo; empty end means no expiration.";
            schedule.AddProp("StartDateTime", true);
            schedule.AddProp("EndDateTime", true);
            section.AddGroup(schedule);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "group", "assignment", "schedule");
                if (chosen.Count == 0) chosen.Add("GroupName");
                string selectList = string.Join(", ", chosen.ToArray());

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying PIM for Groups schedules (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$elig = @(); $act = @()");
                sb.AppendLine("try {");
                sb.AppendLine("    $peuri = 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules'");
                sb.AppendLine("    while ($peuri) { $pe = Invoke-RestMethod -Uri $peuri -Headers $headers -Method Get -ErrorAction Stop; $elig += @($pe.value); $peuri = $pe.'@odata.nextLink' }");
                sb.AppendLine("    $pauri = 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules'");
                sb.AppendLine("    while ($pauri) { $paa = Invoke-RestMethod -Uri $pauri -Headers $headers -Method Get -ErrorAction Stop; $act += @($paa.value); $pauri = $paa.'@odata.nextLink' }");
                sb.AppendLine("    Write-Host (\"Retrieved {0} eligible + {1} active group schedule(s).\" -f $elig.Count, $act.Count)");
                sb.AppendLine("} catch { Write-Host 'WARNING: PIM group schedules query failed (needs PrivilegedEligibilitySchedule.Read.AzureADGroup + PrivilegedAssignmentSchedule.Read.AzureADGroup) - export will be empty.' }");
                sb.AppendLine("if (($elig.Count + $act.Count) -eq 0) { Write-Host 'No PIM for Groups schedules found - PIM for Groups not in use, or consent is missing.' }");
                sb.AppendLine("$gCache5 = @{}; $pgCache = @{}");
                sb.AppendLine("$script:pgResFail = 0");
                sb.AppendLine("function Resolve-PgGroup { param($gid) if (-not $gid) { return '' }; if ($gCache5.ContainsKey($gid)) { return $gCache5[$gid] }; $nm = $gid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $gid + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $nm = [string]$o.displayName } } catch { $script:pgResFail++ }; $gCache5[$gid] = $nm; return $nm }");
                sb.AppendLine("function Resolve-PgPrincipal {");
                sb.AppendLine("    param($prId)");
                sb.AppendLine("    if (-not $prId) { return @{ Name = ''; Type = '' } }");
                sb.AppendLine("    if ($pgCache.ContainsKey($prId)) { return $pgCache[$prId] }");
                sb.AppendLine("    $nm = $prId; $tp = 'Unknown'");
                sb.AppendLine("    try {");
                sb.AppendLine("        $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/users/\" + $prId + \"?`$select=userPrincipalName,displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("        $nm = [string]$o.userPrincipalName; if (-not $nm) { $nm = [string]$o.displayName }; $tp = 'User'");
                sb.AppendLine("    } catch {");
                sb.AppendLine("        try {");
                sb.AppendLine("            $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/groups/\" + $prId + \"?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop");
                sb.AppendLine("            $nm = [string]$o.displayName; $tp = 'Group'");
                sb.AppendLine("        } catch { $script:pgResFail++ }");
                sb.AppendLine("    }");
                sb.AppendLine("    $pgCache[$prId] = @{ Name = $nm; Type = $tp }");
                sb.AppendLine("    return $pgCache[$prId]");
                sb.AppendLine("}");
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($s in @($elig)) {");
                sb.AppendLine("    if ([string]$s.status -match 'Revoked|Canceled|Denied|Failed') { continue }");
                sb.AppendLine("    $pp = Resolve-PgPrincipal ([string]$s.principalId); $st = ''; $en = ''");
                sb.AppendLine("    try { $st = [string]$s.scheduleInfo.startDateTime } catch { }; try { $en = [string]$s.scheduleInfo.expiration.endDateTime } catch { }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{ GroupName = (Resolve-PgGroup ([string]$s.groupId)); PrincipalName = [string]$pp.Name; PrincipalType = [string]$pp.Type; MemberType = $s.memberType; AssignmentType = 'Eligible (PIM)'; StartDateTime = $st; EndDateTime = $en })");
                sb.AppendLine("}");
                sb.AppendLine("foreach ($s in @($act)) {");
                sb.AppendLine("    if ([string]$s.status -match 'Revoked|Canceled|Denied|Failed') { continue }");
                sb.AppendLine("    $pp = Resolve-PgPrincipal ([string]$s.principalId); $st = ''; $en = ''");
                sb.AppendLine("    try { $st = [string]$s.scheduleInfo.startDateTime } catch { }; try { $en = [string]$s.scheduleInfo.expiration.endDateTime } catch { }");
                sb.AppendLine("    $rows.Add([pscustomobject]@{ GroupName = (Resolve-PgGroup ([string]$s.groupId)); PrincipalName = [string]$pp.Name; PrincipalType = [string]$pp.Type; MemberType = $s.memberType; AssignmentType = 'Active (PIM)'; StartDateTime = $st; EndDateTime = $en })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ GroupName = ''; PrincipalName = ''; PrincipalType = ''; MemberType = ''; AssignmentType = ''; StartDateTime = ''; EndDateTime = '' }) }");
                sb.AppendLine("if ($script:pgResFail -gt 0) { Write-Host (\"WARNING: {0} group/principal(s) could not be resolved to names.\" -f $script:pgResFail) }");
                sb.AppendLine("$rows = $rows | Select-Object " + selectList);
                sb.AppendLine();
                sb.Append(ctx.ExportCsv("$rows"));
                sb.AppendLine("Write-Host 'Export complete.'");
                return sb.ToString();
            };

            return section;
        }

        // ============================================================ 23. SCHEMA EXTENSIONS
        // Third-party (and first-party) schema extensions: one row per
        // extension with target types, property set, status and owning app
        // (resolved). Missing extensions break apps silently after migration
        // when the owning app is not re-registered. Needs Application.Read.All
        // (already required).
        private static AuditSection BuildSchemaExtensionsSection()
        {
            var section = new AuditSection(
                "entra-schema-extensions",
                "Schema extensions",
                "Schema extensions export",
                "Audit schema extensions via Graph: target types, properties, status and owning app (one row per extension).",
                "ext",
                AuditScope.Graph);
            section.Category = "Applications";
            section.Product = "Entra ID";
            section.DefaultFileName = "EntraSchemaExtensions.csv";

            var extension = new AuditOptionGroup("extension", "Extension", GroupMode.MultiCheck); extension.Columns = 2;
            extension.AddProp("ExtensionId", true);
            extension.AddProp("Description", true);
            extension.AddProp("TargetTypes", true);
            extension.AddProp("Status", true);
            extension.AddProp("Properties", true);
            section.AddGroup(extension);

            var owner = new AuditOptionGroup("owner", "Owning app", GroupMode.MultiCheck); owner.Columns = 1;
            owner.Hint = "Owner appId resolved to display name via cached service-principal lookup.";
            owner.AddProp("OwnerApp", true);
            section.AddGroup(owner);

            section.BuildScript = delegate (AuditSelection sel, ScriptContext ctx)
            {
                var chosen = Collect(sel, "extension", "owner");
                if (chosen.Count == 0) chosen.Add("ExtensionId");
                string selectList = string.Join(", ", chosen.ToArray());
                bool wantOwner = chosen.Contains("OwnerApp");

                var sb = new StringBuilder();
                sb.AppendLine("Write-Host 'Querying schema extensions (Graph)...'");
                sb.AppendLine(GraphHeaders);
                sb.AppendLine("$exts = @()");
                sb.AppendLine("try {");
                sb.AppendLine("    $euri = 'https://graph.microsoft.com/v1.0/schemaExtensions'");
                sb.AppendLine("    while ($euri) { $er = Invoke-RestMethod -Uri $euri -Headers $headers -Method Get -ErrorAction Stop; $exts += @($er.value); $euri = $er.'@odata.nextLink' }");
                sb.AppendLine("    Write-Host (\"Retrieved {0} schema extension(s).\" -f $exts.Count)");
                sb.AppendLine("} catch { Write-Host ('WARNING: schemaExtensions query failed (' + $_.Exception.Message + ' - consent for Application.Read.All?)'); $exts = @() }");
                sb.AppendLine("if ($exts.Count -eq 0) { Write-Host 'No schema extensions found - none defined, or consent is missing.' }");
                if (wantOwner)
                {
                    sb.AppendLine("$spCache2 = @{}");
                    sb.AppendLine("$script:sp2Fail = 0");
                    sb.AppendLine("function Resolve-ExtOwner { param($appid) if (-not $appid) { return '' }; if ($spCache2.ContainsKey($appid)) { return $spCache2[$appid] }; $nm = $appid; try { $o = Invoke-RestMethod -Uri (\"https://graph.microsoft.com/v1.0/servicePrincipals(appId='\" + $appid + \"')?`$select=displayName\") -Headers $headers -Method Get -ErrorAction Stop; if ($o.displayName) { $nm = [string]$o.displayName } } catch { $script:sp2Fail++ }; $spCache2[$appid] = $nm; return $nm }");
                }
                sb.AppendLine("$rows = New-Object System.Collections.Generic.List[object]");
                sb.AppendLine("foreach ($x in $exts) {");
                sb.AppendLine("    $tt = ((@($x.targetTypes) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ', ')");
                sb.AppendLine("    $pr = ((@($x.properties | ForEach-Object { $pn = [string]$_.name; $pt = [string]$_.type; if ($pn) { if ($pt) { $pn + ' (' + $pt + ')' } else { $pn } } else { '' } } | Where-Object { $_ -ne '' } | Sort-Object -Unique)) -join ', ')");
                if (wantOwner)
                {
                    sb.AppendLine("    $ow = Resolve-ExtOwner ([string]$x.owner)");
                }
                sb.AppendLine("    $rows.Add([pscustomobject]@{");
                sb.AppendLine("        ExtensionId = $x.id; Description = $x.description; TargetTypes = $tt; Status = $x.status; Properties = $pr;");
                sb.AppendLine("        OwnerApp = " + (wantOwner ? "$ow" : "''"));
                sb.AppendLine("    })");
                sb.AppendLine("}");
                sb.AppendLine("if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ ExtensionId = ''; Description = ''; TargetTypes = ''; Status = ''; Properties = ''; OwnerApp = '' }) }");
                if (wantOwner) sb.AppendLine("if ($script:sp2Fail -gt 0) { Write-Host (\"WARNING: {0} owner app(s) could not be resolved to names.\" -f $script:sp2Fail) }");
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
