// IT Simply Ltd: tier policy for the CIPP MCP server (new file, not derived from upstream).
//
// Every CIPP endpoint is assigned one of four tiers by `computeTier` (tier.ts)
// using ONLY the data in this file plus the endpoint's name and x-cipp-role.
// To change what the server will do, edit this file and nothing else.

/**
 * Endpoint names that are never callable, by anyone, through any route (meta
 * tool or named tool). Compared case-insensitively: CIPP resolves names
 * case-sensitively, but a spelling variant must not slip past the list.
 *
 * Decision 4 (sensitive reads the public CIPP MCP exposes), decision 6
 * (dangerous triggers Grant named), and the three endpoints CIPP's own
 * catalogue also excludes.
 */
export const BLOCKED_NAMES: readonly string[] = [
  // Decision 4: sensitive reads
  'ExecGetLocalAdminPassword', // LAPS passwords
  'ExecGetRecoveryKey', // BitLocker recovery keys
  // RULING (beyond the design's list, conservative): same exposure as the two above.
  'ExecBitlockerSearch', // searches BitLocker recovery keys
  // RULING (security review): Graph is reachable ONLY through cipp_graph_request,
  // which builds its own call from an allowlist (src/itsl/graph.ts). These four
  // are arbitrary-Graph or Graph-state relays and are never callable via cipp_exec_read / cipp_exec_write.
  'ListGraphRequest',
  'ListGraphBulkRequest',
  'ExecGraphExplorerPreset', // saves/deletes CIPP presets
  'ExecGraphRequestProfile', // arbitrary Graph GETs without a blocklist; Reset clears counters
  // RULING (security review): stored CIPP backups contain integration config, API clients, etc.
  'ExecListBackup',
  'ListApiTest', // echoes the request, including the caller's Authorization header
  'ListExoRequest', // arbitrary Exchange Online cmdlet proxy
  'ExecSendPush', // sends a live MFA push to a user
  'ExecMailTest',
  'ExecBreachSearch',
  'ListExtensionsConfig', // extension (integration) configuration
  // Decision 6: called dangerous by Grant
  'ExecCPVRefresh',
  'ExecStandardsRun',
  'ExecCIPPDBCacheAdmin',
  // Never exposed: the MCP transport itself, the spec dump, and the docs
  // search that CIPP serves as SearchDocs/GetDoc (this server has neither).
  'ExecMcp',
  'ListOpenApiSpec',
  'ListCippDocs',
];

/**
 * Role patterns that block every endpoint carrying a matching x-cipp-role.
 *
 * RULING (decision 4 says "every CIPP.Extension.* config read"): only the
 * `.Read` roles of CIPP.Extension are blocked. Blocking the whole prefix would
 * also block ExecExtensionSync (CIPP.Extension.ReadWrite), which decision 6
 * puts in the launch write tier. A side effect: ListExtensionSync, a status
 * read, is blocked too (conservative; promote via a reviewer decision if wanted).
 */
export const BLOCKED_ROLE_PATTERNS: readonly RegExp[] = [
  /^CIPP\.Backup\./i,
  /^CIPP\.SuperAdmin\./i,
  /^CIPP\.AppSettings\./i,
  /^CIPP\.Extension\.Read$/i,
];

/** Any endpoint whose name contains one of these is blocked (RULING: every *Backup* endpoint). */
export const BLOCKED_NAME_PATTERNS: readonly RegExp[] = [/backup/i];

/** Decision 6: the write tier at launch is the sync triggers only. */
export const WRITE_ALLOWLIST: readonly string[] = [
  'ExecCIPPDBCache',
  'ExecSyncAPDevices',
  'ExecSyncDEP',
  'ExecSyncVPP',
  'ExecExtensionSync',
  'ExecTestRefresh',
  'ExecTestRun',
];

/**
 * CIPP's own read-only rule: a `.Read` role (never `.ReadWrite`) ... AND, RULING
 * (security review), the endpoint must have a GET operation and is only ever
 * invoked as GET. POST-only `.Read` endpoints (e.g. ExecBECCheck) compute to
 * `disabled` pending review: CIPP labels some POST handlers `.Read` that change state.
 */
export const READ_ROLE_PATTERN = /\.Read$/i;

/** ... on an endpoint whose name does not imply a mutation. */
export const MUTATION_NAME_PATTERN =
  /^(Add|Set|Remove|Delete|Edit|New|Update|Disable|Enable|Reset|Revoke|Push|Clear|Start|Stop|Rename|Move|Copy)/;

/**
 * Manual promotions of an otherwise-`disabled` endpoint to `read` or `write`
 * after review. `blocked` always wins over this map.
 *
 * Both entries exist because named WYRE tools call endpoints that CIPP's spec
 * gives no `.Read` role (so the rule cannot place them):
 *  - ListBPA: absent from CIPP's openapi.json entirely.
 *  - PublicPing: role is `Public`; a connectivity check with no tenant data.
 */
export const REVIEWED: Readonly<Record<string, 'read' | 'write'>> = {
  ListBPA: 'read',
  PublicPing: 'read',
};

/**
 * cipp_graph_request allowlist. THIS IS THE KNOB: to let the model read more of
 * Microsoft Graph, add a collection prefix here (lower-case, no leading slash,
 * no version). NOTE: devicemanagement/deviceconfigurations is deliberately NOT
 * listed: full GETs may return Wi-Fi/VPN preSharedKey values (unverified). Re-add
 * it after a live check. A request path must equal a prefix or sit beneath it
 * (prefix + '/...'). Anything not listed is refused. The denylist below is
 * applied on top of the allowlist and always wins.
 */
export const GRAPH_ALLOWED_PREFIXES: readonly string[] = [
  'users',
  'groups',
  'devices',
  'serviceprincipals',
  'applications',
  'domains',
  'organization',
  'subscribedskus',
  'directoryroles',
  'rolemanagement/directory',
  'identity/conditionalaccess',
  'policies',
  'auditlogs',
  'reports',
  'security/alerts_v2',
  'security/incidents',
  'devicemanagement/manageddevices',
  'devicemanagement/devicecompliancepolicies',
  'teams',
  'sites',
];

/** Terms that are refused anywhere in a Graph path or in $select/$filter/$expand values (lower-case, substring). */
export const GRAPH_DENY_TERMS: readonly string[] = [
  'informationprotection',
  'bitlocker',
  'devicelocalcredentials',
  'recoverykeys',
  'recoverykey',
  'getfilevaultkey',
  'filevault',
  'getomasettingplaintextvalue',
  'secretreference',
  'activationlockbypasscode',
  'presharedkey',
  'temporaryaccesspass',
  'passwordmethod',
];

/**
 * Endpoints that carry a `.Read` role but change state (RULING, security review):
 * forced to `disabled` regardless of the read rule or the reviewed map.
 *  - ListAuditLogSearches: its default branch creates a unified-audit-log search.
 *  - ExecBECCheck: starts a BEC investigation.
 * Blocked still wins over this list.
 */
export const FORCE_DISABLED: readonly string[] = ['ListAuditLogSearches', 'ExecBECCheck'];

/**
 * Graph path SEGMENTS that are customer content (mail, calendar, files, chats,
 * notes, contacts, photos, list items) and are refused anywhere in a path, under
 * every allowed collection (RULING, prompt-injection hardening). Compared
 * case-insensitively against whole segments, so e.g. users/x/messages,
 * sites/x/drive, sites/x/lists/y/items and teams/x/channels/y/messages are all refused.
 * The same words are refused as whole words in $select and $expand.
 */
export const GRAPH_CONTENT_SEGMENTS: readonly string[] = [
  'messages',
  'mailfolders',
  'events',
  'calendar',
  'calendars',
  'calendarview',
  'drive',
  'drives',
  'onenote',
  'chats',
  'contacts',
  'contactfolders',
  'teamwork',
  'joinedteams',
  'photo',
  'photos',
  'extensions',
  'items',
  'conversations',
  'threads',
  'posts',
  'pages',
  'canvaslayout',
  'webparts',
  'planner',
  'todo',
  'mailboxsettings',
  'insights',
  'onlinemeetings',
  'shifts',
  'schedule',
  'notes',
  'attachments',
];

/**
 * Argument keys whose VALUES may contain '/' (free-text and filter keys), and
 * also '&' and the guest marker #EXT#. Compared case-insensitively, TOP-LEVEL
 * string values only (never nested). Even here `..`, backslash, control
 * characters, '?' and '%' are refused.
 * Keys ending "url" (siteUrl, url, webUrl, ...) are NOT here: their value must be
 * an https SharePoint URL (see values.ts), so '/' needs no blanket allowance.
 * Add a key here only after reviewing what CIPP does with it.
 *
 * NOTE: the value rules assume a read-only tool set. They MUST be revisited
 * (passwords, out-of-office text, templates, free-text bodies) before Grant
 * enables any write tool; today those tools are disabled so it is moot.
 */
export const VALUE_FILTER_KEYS: readonly string[] = ['filter', '$filter', 'graphfilter', 'search', 'query', 'searchstring'];
export const VALUE_SLASH_ALLOWED_KEYS: readonly string[] = VALUE_FILTER_KEYS;

/**
 * cipp_disable_enterprise_app / cipp_enable_enterprise_app (app-toggle.ts) refuse any service
 * principal whose appOwnerOrganizationId is in one of these two lists (lower-case GUIDs,
 * compared case-insensitively). Add a tenant here to protect every app it owns.
 *
 * Microsoft's first-party apps: disabling one (Exchange Online, SharePoint, Graph, Teams...)
 * can break a whole tenant, and none of them is ours or the client's to switch off.
 *  - f8cdef31-a31e-4b4a-93e4-5f571e91255a: Microsoft Services, the owner of first-party apps.
 *  - 72f988bf-86f1-41af-91ab-2d7cd011db47: Microsoft's corporate tenant, which owns many more.
 */
export const MICROSOFT_FIRST_PARTY_TENANT_IDS: readonly string[] = [
  'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
  '72f988bf-86f1-41af-91ab-2d7cd011db47',
];

/**
 * IT Simply's own tenants. They own the apps our tooling runs on in client tenants. Disabling
 * one of them through this server would cut IT Simply (and this server) off from the client.
 *  - caaf597f-c70a-428d-8dae-312ff86d1e23: IT Simply (itsimply.co.nz). The MCP gateway, data
 *    gateway, CIPP SAM and Practice Intelligence app registrations.
 *  - d751f643-98f0-452b-beb9-adf331942ce5: Practice Intelligence (practiceintelligence.co.nz).
 *    Owns e.g. the "Sandbox" app found in a client tenant in the 2026-10-18 live test.
 */
export const ITSL_OWN_TENANT_IDS: readonly string[] = [
  'caaf597f-c70a-428d-8dae-312ff86d1e23',
  'd751f643-98f0-452b-beb9-adf331942ce5',
];

/**
 * ListDBCache (CIPP's cached tenant data, read tier) is runnable through cipp_exec_read ONLY for the
 * cache types listed here. A `type` that is missing, not a string, or not in this list is refused by
 * name. Matching is case-insensitive and the canonical spelling below is what is sent to CIPP.
 * Add a type only after reading what CIPP caches into it (Modules/CIPPDB/Public/DBCache/Set-CIPPDBCache<Type>.ps1).
 *
 * Every cache type CIPP defines (CIPP-API master 2026-10-18: the Set-CIPPDBCache*.ps1 names,
 * Config/CIPPDBCacheTypes.json, and the types seen live), allowed or refused:
 *
 *   ActiveUserDetail                           refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   ActivityBasedTimeoutPolicy                 refused: not reviewed for the read tier; add after review
 *   AdminConsentRequestPolicy                  allowed: Graph/Exchange policy configuration, no secrets or personal data
 *   AdministrativeUnits                        refused: not reviewed for the read tier; add after review
 *   AdminReportSettings                        refused: not reviewed for the read tier; add after review
 *   AppRoleAssignments                         allowed: Graph/Exchange policy configuration, no secrets or personal data
 *   Apps                                       refused: owner profiles are expanded into each row (PII); use cipp_list_app_registrations
 *   AppsAndServices                            refused: not reviewed for the read tier; add after review
 *   AuthenticationFlowsPolicy                  refused: not reviewed for the read tier; add after review
 *   AuthenticationMethodsPolicy                refused: not reviewed for the read tier; add after review
 *   AuthenticationStrengths                    refused: not reviewed for the read tier; add after review
 *   AuthorizationPolicy                        allowed: Graph/Exchange policy configuration, no secrets or personal data
 *   AutopilotDeploymentProfiles                refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   B2BManagementPolicy                        refused: not reviewed for the read tier; add after review
 *   BitlockerKeys                              refused: BitLocker recovery key records; the BitLocker endpoints are blocked by name, so this stays refused too
 *   CalendarPermissions                        refused: calendar sharing by person; use ListCalendarPermissions
 *   CASMailbox                                 refused: mailbox or contact data per person; use the live mailbox tools
 *   CASMailboxes                               refused: mailbox or contact data per person; use the live mailbox tools
 *   ComplianceRetentionPolicies                refused: not reviewed for the read tier; add after review
 *   ComplianceRetentionRules                   refused: not reviewed for the read tier; add after review
 *   ConditionalAccessPolicies                  refused: not reviewed for the read tier; add after review
 *   CopilotAdminSettings                       refused: not reviewed for the read tier; add after review
 *   CopilotPolicySettings                      refused: not reviewed for the read tier; add after review
 *   CopilotReadinessActivity                   refused: not reviewed for the read tier; add after review
 *   CopilotUsageUserDetail                     refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   CopilotUserCountSummary                    refused: not reviewed for the read tier; add after review
 *   CopilotUserCountTrend                      refused: not reviewed for the read tier; add after review
 *   CredentialUserRegistrationDetails          refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   CrossTenantAccessPolicy                    allowed: Graph/Exchange policy configuration, no secrets or personal data
 *   CsExternalAccessPolicy                     refused: not reviewed for the read tier; add after review
 *   CsTeamsAppPermissionPolicy                 refused: not reviewed for the read tier; add after review
 *   CsTeamsClientConfiguration                 refused: not reviewed for the read tier; add after review
 *   CsTeamsFilesPolicy                         refused: not reviewed for the read tier; add after review
 *   CsTeamsMeetingPolicy                       refused: not reviewed for the read tier; add after review
 *   CsTeamsMessagingConfiguration              refused: not reviewed for the read tier; add after review
 *   CsTeamsMessagingPolicy                     refused: not reviewed for the read tier; add after review
 *   CsTenantFederationConfiguration            refused: not reviewed for the read tier; add after review
 *   DefaultAppManagementPolicy                 refused: not reviewed for the read tier; add after review
 *   DefenderCVEs                               refused: not reviewed for the read tier
 *   DetectedApps                               refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   DeviceEnrollmentConfigurations             refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   DeviceRegistrationPolicy                   refused: not reviewed for the read tier; add after review
 *   Devices                                    refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   DeviceSettings                             refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   DirectoryRecommendations                   refused: not reviewed for the read tier
 *   DlpCompliancePolicies                      refused: not reviewed for the read tier; add after review
 *   DlpComplianceRules                         refused: not reviewed for the read tier; add after review
 *   DomainAnalyser                             refused: not reviewed for the read tier; add after review
 *   Domains                                    refused: not reviewed for the read tier; add after review
 *   ExoAcceptedDomains                         refused: not reviewed for the read tier; add after review
 *   ExoAdminAuditLogConfig                     refused: not reviewed for the read tier; add after review
 *   ExoAntiPhishPolicies                       refused: not reviewed for the read tier; add after review
 *   ExoAntiPhishRules                          refused: not reviewed for the read tier; add after review
 *   ExoAtpPolicyForO365                        refused: not reviewed for the read tier; add after review
 *   ExoCASMailboxSmtpAuth                      refused: mailbox or contact data per person; use the live mailbox tools
 *   ExoDkimSigningConfig                       refused: not reviewed for the read tier; add after review
 *   ExoDlpSensitiveInfoTypes                   refused: not reviewed for the read tier; add after review
 *   ExoDynamicDistributionGroup                refused: mailbox or contact data per person; use the live mailbox tools
 *   ExoExternalInOutlook                       refused: not reviewed for the read tier; add after review
 *   ExoGlobalQuarantinePolicy                  refused: not reviewed for the read tier; add after review
 *   ExoHostedConnectionFilterPolicy            refused: not reviewed for the read tier; add after review
 *   ExoHostedContentFilterPolicy               refused: not reviewed for the read tier; add after review
 *   ExoHostedContentFilterRule                 refused: not reviewed for the read tier; add after review
 *   ExoHostedOutboundSpamFilterPolicy          allowed: Graph/Exchange policy configuration, no secrets or personal data
 *   ExoInboundConnector                        refused: not reviewed for the read tier; add after review
 *   ExoIRMConfiguration                        refused: not reviewed for the read tier; add after review
 *   ExoLabelPolicies                           refused: not reviewed for the read tier; add after review
 *   ExoLabels                                  refused: not reviewed for the read tier; add after review
 *   ExoMailboxPlans                            refused: mailbox or contact data per person; use the live mailbox tools
 *   ExoMailContacts                            refused: mailbox or contact data per person; use the live mailbox tools
 *   ExoMalwareFilterPolicies                   refused: not reviewed for the read tier; add after review
 *   ExoMalwareFilterRules                      refused: not reviewed for the read tier; add after review
 *   ExoOMEConfiguration                        refused: not reviewed for the read tier; add after review
 *   ExoOrganizationConfig                      refused: not reviewed for the read tier; add after review
 *   ExoOutboundConnector                       refused: not reviewed for the read tier; add after review
 *   ExoPhishSimConfig                          refused: not reviewed for the read tier; add after review
 *   ExoPhishSimOverridePolicy                  refused: not reviewed for the read tier; add after review
 *   ExoPhishSimOverrideRule                    refused: not reviewed for the read tier; add after review
 *   ExoPhishSimUrlAllowItems                   refused: not reviewed for the read tier; add after review
 *   ExoPresetSecurityPolicy                    refused: not reviewed for the read tier; add after review
 *   ExoProtectionAlert                         refused: not reviewed for the read tier; add after review
 *   ExoQuarantinePolicy                        refused: not reviewed for the read tier; add after review
 *   ExoRemoteDomain                            refused: not reviewed for the read tier; add after review
 *   ExoRetentionPolicies                       refused: not reviewed for the read tier; add after review
 *   ExoRetentionPolicyTags                     refused: not reviewed for the read tier; add after review
 *   ExoRoleAssignmentPolicy                    refused: not reviewed for the read tier; add after review
 *   ExoSafeAttachmentPolicies                  refused: not reviewed for the read tier; add after review
 *   ExoSafeAttachmentRules                     refused: not reviewed for the read tier; add after review
 *   ExoSafeLinksPolicies                       refused: not reviewed for the read tier; add after review
 *   ExoSafeLinksRules                          refused: not reviewed for the read tier; add after review
 *   ExoSharingPolicy                           refused: not reviewed for the read tier; add after review
 *   ExoTeamsProtectionPolicy                   refused: not reviewed for the read tier; add after review
 *   ExoTenantAllowBlockList                    refused: not reviewed for the read tier; add after review
 *   ExoTenantAllowBlockListSpoofItems          refused: not reviewed for the read tier; add after review
 *   ExoTransportConfig                         refused: not reviewed for the read tier; add after review
 *   ExoTransportRules                          refused: not reviewed for the read tier; add after review
 *   Fido2Configuration                         refused: not reviewed for the read tier; add after review
 *   FormsSettings                              refused: not reviewed for the read tier; add after review
 *   Groups                                     refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   GroupUsage                                 refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   Guests                                     refused: per-user profile data; use ListUsers
 *   HomeRealmDiscoveryPolicy                   refused: not reviewed for the read tier; add after review
 *   HVEAccounts                                refused: mailbox or contact data per person; use the live mailbox tools
 *   IntuneAppInstallStatus                     refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneAppleUserInitiatedEnrollmentProfiles refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneApplications                         refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneAppProtectionPolicies                refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneAssignmentFilters                    refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneBrandingProfile                      refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneCompliancePolicies                   refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneConfigurationPolicies                refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneDataProcessorOnboarding              refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneDeviceEnrollmentConfigurations       refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneDeviceManagementSettings             refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneMobileApps                           refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneMobileAppsAll                        refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntunePolicies                             refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneReusableSettings                     refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneScripts                              refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   IntuneWindowsAutopilotDeploymentProfiles   refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   LicenseOverview                            refused: not reviewed for the read tier; add after review
 *   M365AppUserDetail                          refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   Mailboxes                                  refused: mailbox or contact data per person; use the live mailbox tools
 *   MailboxMessageConfiguration                refused: mailbox or contact data per person; use the live mailbox tools
 *   MailboxPermissions                         refused: mailbox access lists by person; use cipp_list_mailbox_permissions
 *   MailboxRules                               refused: inbox rule bodies can quote mail content; use the live endpoint
 *   MailboxUsage                               refused: mailbox or contact data per person; use the live mailbox tools
 *   MailTrafficSummary                         refused: not reviewed for the read tier
 *   ManagedDeviceCleanupRules                  refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   ManagedDeviceEncryptionStates              refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   ManagedDevices                             refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   MDEOnboarding                              refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   MessageCenterMessages                      refused: not reviewed for the read tier
 *   MFAState                                   refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   MobileDeviceManagementPolicies             refused: Intune and device configuration (can carry scripts and secrets); not reviewed
 *   MoeraDmarc                                 refused: not reviewed for the read tier; add after review
 *   NamedLocations                             refused: not reviewed for the read tier; add after review
 *   NamePronunciation                          refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   NetworkAccess                              refused: not reviewed for the read tier; add after review
 *   OAuth2PermissionGrants                     allowed: Graph/Exchange policy configuration, no secrets or personal data
 *   OfficeActivations                          refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   OneDriveLongPaths                          refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   OneDriveQuotas                             refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   OneDriveRootPermissions                    refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   OneDriveRootShortcuts                      refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   OneDriveSiteListing                        refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   OneDriveUsage                              refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   Organization                               refused: not reviewed for the read tier; add after review
 *   OrganizationBranding                       refused: not reviewed for the read tier; add after review
 *   OwaMailboxPolicy                           refused: not reviewed for the read tier; add after review
 *   PeopleInsights                             refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   PermissionGrantPolicies                    allowed: Graph/Exchange policy configuration, no secrets or personal data
 *   PhotoUpdateSettings                        refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   PIMAssignments                             refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   PIMRoleSettings                            refused: not reviewed for the read tier; add after review
 *   PIMSettings                                refused: not reviewed for the read tier; add after review
 *   PlannerUserPolicies                        refused: not reviewed for the read tier; add after review
 *   Pronouns                                   refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   ReportSubmissionPolicy                     refused: not reviewed for the read tier; add after review
 *   ReportSubmissionRule                       refused: not reviewed for the read tier; add after review
 *   RiskDetections                             refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   RiskyServicePrincipals                     refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   RiskyUsers                                 refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   RoleAssignments                            refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   RoleAssignmentScheduleInstances            refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   RoleDefinitions                            refused: not reviewed for the read tier; add after review
 *   RoleEligibilitySchedules                   refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   RoleManagementPolicies                     refused: not reviewed for the read tier; add after review
 *   Roles                                      refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   RolesAndAssignments                        refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   SecureScore                                refused: not reviewed for the read tier
 *   SecureScoreControlProfiles                 refused: not reviewed for the read tier
 *   SecurityDefaults                           refused: not reviewed for the read tier; add after review
 *   SelfServicePurchaseProducts                refused: not reviewed for the read tier; add after review
 *   SensitivityLabels                          refused: not reviewed for the read tier; add after review
 *   ServiceHealthIssues                        refused: not reviewed for the read tier
 *   ServiceHealthOverviews                     refused: not reviewed for the read tier
 *   ServicePrincipalRiskDetections             refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   ServicePrincipals                          refused: whole beta service principals (large); use cipp_list_enterprise_apps
 *   Settings                                   refused: not reviewed for the read tier; add after review
 *   SharePointAdminSettings                    refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   SharePointPermissions                      refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   SharePointSharingLinks                     refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   SharePointSiteListing                      refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   SharePointSiteUsage                        refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   SharePointUsageReport                      refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   SiteActivity                               refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   SPOSites                                   refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   SPOTenant                                  refused: not reviewed for the read tier; add after review
 *   SPOTenantSyncClientRestriction             refused: not reviewed for the read tier; add after review
 *   StorageCleanupScan                         refused: site, file or sharing names (customer content); use the live sharing and site tools
 *   Teams                                      refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   TeamsActivity                              refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   TeamsActivityTeamsUserActivityUser         refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   TeamsResourceAccounts                      refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   TeamsVoice                                 refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   UserRegistrationDetails                    refused: per-person or per-device records; not reviewed for the read tier (use the live endpoint)
 *   Users                                      refused: per-user profiles, licences and contact data; use ListUsers */
export const DBCACHE_ALLOWED_TYPES: readonly string[] = [
  'AuthorizationPolicy',
  'OAuth2PermissionGrants',
  'AppRoleAssignments',
  'PermissionGrantPolicies',
  'AdminConsentRequestPolicy',
  'CrossTenantAccessPolicy',
  'ExoHostedOutboundSpamFilterPolicy',
];
