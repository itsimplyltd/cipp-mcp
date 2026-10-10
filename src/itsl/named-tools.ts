// IT Simply Ltd: which CIPP endpoints each named WYRE tool calls (new file).
//
// Derived by reading the CippService method each handler case calls. The
// guard tests re-derive the endpoint list from the service source and fail if
// this table is missing an endpoint or a tool, so it cannot silently go stale.

import { computeTier, mostRestrictive, Tier } from './tier.js';

/** Tool name -> CIPP endpoints the tool calls (every endpoint of its service method). */
export const NAMED_TOOL_ENDPOINTS: Readonly<Record<string, readonly string[]>> = {
  cipp_list_tenants: ['ListTenants'],
  cipp_get_tenant_details: ['ListTenantDetails'],
  cipp_list_users: ['ListUsers'],
  cipp_create_user: ['AddUser'],
  cipp_edit_user: ['EditUser', 'ListUsers'], // editUser resolves the user first
  cipp_disable_user: ['ExecDisableUser'],
  cipp_reset_password: ['ExecResetPass'],
  cipp_reset_mfa: ['ExecResetMFA'],
  cipp_revoke_sessions: ['ExecRevokeSessions'],
  cipp_offboard_user: ['ExecOffboardUser', 'ListUsers'], // resolves the user first
  cipp_bec_check: ['ExecBECCheck'],
  cipp_list_mfa_users: ['ListMFAUsers'],
  cipp_list_user_devices: ['ListUserDevices'],
  cipp_list_user_groups: ['ListUserGroups'],
  cipp_list_user_signin_logs: ['ListUserSigninLogs'],
  cipp_list_groups: ['ListGroups'],
  cipp_create_group: ['AddGroup'],
  cipp_list_mailboxes: ['ListMailboxes'],
  cipp_list_mailbox_permissions: ['ListmailboxPermissions'],
  cipp_list_trusted_blocked_senders: ['ListUserTrustedBlockedSenders'],
  cipp_list_mailbox_usage: ['ListMailboxes'],
  cipp_get_mailbox_usage: ['ListUserMailboxDetails', 'ListUsers'], // resolves the Entra id first
  cipp_set_out_of_office: ['ExecSetOoO'],
  cipp_set_email_forwarding: ['ExecEmailForward'],
  cipp_list_conditional_access_policies: ['ListConditionalAccessPolicies'],
  cipp_list_named_locations: ['ListNamedLocations'],
  // Fixed GET of /servicePrincipals built inside CippService. 'ListGraphRequest' itself is BLOCKED
  // for the catalogue; this virtual key (text after '#' is ignored when matching service calls)
  // lets the one hard-coded named use keep its read tier.
  cipp_list_enterprise_apps: ['ListGraphRequest#servicePrincipals'],
  cipp_list_standards: ['ListStandards'],
  cipp_run_standards_check: ['ExecStandardsRun'],
  cipp_list_standard_templates: ['listStandardTemplates'],
  cipp_get_tenant_drift: ['ListTenantDrift'],
  cipp_get_tenant_alignment: ['ListTenantAlignment'],
  cipp_create_standard_template: ['AddStandardsTemplate'],
  cipp_delete_standard_template: ['RemoveStandardTemplate'],
  cipp_list_bpa: ['ListBPA'],
  cipp_list_domain_health: ['ListDomains', 'ListDomainHealth'],
  cipp_list_licenses: ['ListLicenses'],
  cipp_list_csp_licenses: ['ListCSPLicenses'],
  cipp_list_audit_logs: ['ListAuditLogs'],
  cipp_list_alert_queue: ['ListAlertsQueue'],
  cipp_list_gdap_roles: ['ListGDAPRoles'],
  cipp_list_gdap_invites: ['ListGDAPInvite'],
  cipp_list_scheduled_items: ['ListScheduledItems'],
  cipp_add_scheduled_item: ['AddScheduledItem'],
  cipp_ping: ['PublicPing'],
  cipp_get_version: ['GetVersion'],
  cipp_list_logs: ['ListLogs'],
};

/**
 * x-cipp-role of each endpoint above, as published in CIPP's openapi.json
 * (CIPP-API master, 2026-10-10). Used when the live spec has not been loaded
 * (so `tools/list` and named tools never depend on the catalogue), and always
 * combined with the live spec by taking the MORE restrictive answer.
 * `undefined` means the spec carries no role for the endpoint.
 */
export const KNOWN_ENDPOINT_ROLES: Readonly<Record<string, string | undefined>> = {
  ListTenants: 'CIPP.Core.Read',
  ListTenantDetails: 'CIPP.Core.Read',
  ListUsers: 'Identity.User.Read',
  AddUser: 'Identity.User.ReadWrite',
  EditUser: 'Identity.User.ReadWrite',
  ExecDisableUser: 'Identity.User.ReadWrite',
  ExecResetPass: 'Identity.User.ReadWrite',
  ExecResetMFA: 'Identity.User.ReadWrite',
  ExecRevokeSessions: 'Identity.User.ReadWrite',
  ExecOffboardUser: 'Identity.User.ReadWrite',
  ExecBECCheck: 'Identity.User.Read',
  ListMFAUsers: 'Identity.User.Read',
  ListUserDevices: 'Identity.User.Read',
  ListUserGroups: 'Identity.User.Read',
  ListUserSigninLogs: 'Identity.User.Read',
  ListGroups: 'Identity.Group.Read',
  AddGroup: 'Identity.Group.ReadWrite',
  ListMailboxes: 'Exchange.Mailbox.Read',
  ListmailboxPermissions: 'Exchange.Mailbox.Read',
  ListUserTrustedBlockedSenders: 'Exchange.Mailbox.Read',
  ListUserMailboxDetails: 'Exchange.Mailbox.Read',
  ExecSetOoO: 'Exchange.Mailbox.ReadWrite',
  ExecEmailForward: 'Exchange.Mailbox.ReadWrite',
  ListConditionalAccessPolicies: 'Tenant.ConditionalAccess.Read',
  ListNamedLocations: 'Tenant.ConditionalAccess.Read',
  'ListGraphRequest#servicePrincipals': 'CIPP.Core.Read',
  ListStandards: 'Tenant.Standards.Read',
  ExecStandardsRun: 'Tenant.Standards.ReadWrite',
  listStandardTemplates: 'Tenant.Standards.Read',
  ListTenantDrift: 'Tenant.Standards.Read',
  ListTenantAlignment: 'Tenant.Standards.Read',
  AddStandardsTemplate: 'Tenant.Standards.ReadWrite',
  RemoveStandardTemplate: 'Tenant.Standards.ReadWrite',
  ListBPA: undefined, // not in the spec at all; placed by REVIEWED in policy.ts
  ListDomains: 'Tenant.Administration.Read',
  ListDomainHealth: 'Tenant.DomainAnalyser.Read',
  ListLicenses: 'Tenant.Directory.Read',
  ListCSPLicenses: 'Tenant.Directory.Read',
  ListAuditLogs: 'CIPP.Alert.Read',
  ListAlertsQueue: 'CIPP.Alert.Read',
  ListGDAPRoles: 'Tenant.Relationship.Read',
  ListGDAPInvite: 'Tenant.Relationship.Read',
  ListScheduledItems: 'CIPP.Scheduler.Read',
  AddScheduledItem: 'CIPP.Scheduler.ReadWrite',
  PublicPing: 'Public', // placed by REVIEWED in policy.ts
  GetVersion: 'CIPP.Core.Read',
  ListLogs: 'CIPP.Logs.Read',
};

/**
 * Endpoints a named tool calls with POST (or that the spec only offers as POST).
 * RULING (security review): the read tier is GET-only, so these compute to disabled
 * pending review: cipp_bec_check (ExecBECCheck starts investigations) and
 * cipp_list_scheduled_items (WYRE POSTs to ListScheduledItems; not shown read-only).
 * cipp_list_tenants is NOT here: it calls GET and never sends ClearCache.
 */
export const POST_INVOKED_ENDPOINTS: ReadonlySet<string> = new Set(['ExecBECCheck', 'ListScheduledItems']);

/** Looks up the live spec's role for an endpoint; undefined when the spec is not loaded or lacks it. */
export type RoleLookup = (endpoint: string) => { found: boolean; role: string | undefined; hasGet: boolean };

/**
 * Tier of a named tool: the most restrictive tier across every endpoint it
 * calls, each computed by the same `computeTier` the catalogue uses, from the
 * built-in role table AND (when loaded) the live spec. Unknown tool -> undefined.
 */
/**
 * Tier of one endpoint the named tools use: the more restrictive of the
 * built-in role table and (when loaded) the live spec, both via computeTier.
 */
export function endpointTier(endpoint: string, liveRole?: RoleLookup): Tier {
  const postOnly = POST_INVOKED_ENDPOINTS.has(endpoint);
  const tiers: Tier[] = [computeTier(endpoint, KNOWN_ENDPOINT_ROLES[endpoint], { hasGet: !postOnly })];
  const live = liveRole?.(endpoint);
  if (live?.found) tiers.push(computeTier(endpoint, live.role, { hasGet: live.hasGet && !postOnly }));
  return mostRestrictive(tiers);
}

/**
 * Tier of a named tool: the most restrictive tier across every endpoint it
 * calls. Unknown tool -> undefined.
 */
export function namedToolTier(toolName: string, liveRole?: RoleLookup): Tier | undefined {
  const endpoints = NAMED_TOOL_ENDPOINTS[toolName];
  if (!endpoints) return undefined;
  return mostRestrictive(endpoints.map((ep) => endpointTier(ep, liveRole)));
}
