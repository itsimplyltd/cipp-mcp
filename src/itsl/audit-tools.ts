// IT Simply Ltd: read-tier named audit tools for the M365 security and governance review (new file).
//
// ListGraphRequest and ListExoRequest stay BLOCKED for cipp_exec_read and cipp_exec_write. These
// tools are the narrow routes to the handful of reads the review needs. Each one:
//  - calls ONE fixed CIPP endpoint shape built here (a fixed Graph path through ListGraphRequest, the same
//    CIPP route cipp_list_enterprise_apps uses, or ListDBCache with a fixed type); no caller-supplied path,
//    cmdlet, filter or OData option;
//  - uses the Graph version and query options CIPP's own code uses for the same resource (beta; $top=999 only on
//    the two collections CIPP's cache reads with it; no options on singletons) and relies on CIPP's paging;
//  - takes tenantFilter (one tenant, never AllTenants) and, for one tool, a GUID; any other argument is refused;
//  - PROJECTS the answer to an explicit field allow-list at every level, so a field CIPP or Graph adds later, or a
//    credential value, cannot be returned. Credential value fields (and the secret hint) are never in an allow-list.
//  - never cuts a value silently: a cut string, array or row list sets truncated: true and names the field in
//    truncatedFields, and the output text says so. The grant `scope` string is never cut.
// Tier: every tool maps to CIPP.Core.Read endpoints (AUDIT_TOOL_ENDPOINTS in named-tools.ts), so a read-tier user
// is never refused by CIPP's own role check.
//
// Also here: the ListDBCache restriction for cipp_exec_read (restrictDbCache + projectDbCacheResult): one tenant,
// a reviewed cache type, tenantFilter/type/countsOnly only, and every row projected through the same allow-lists.

import type { CatalogueLogger } from './catalogue.js';
import type { ToolContext } from './meta-tools.js';
import { truncateError } from './frame.js';
import { DBCACHE_ALLOWED_TYPES } from './policy.js';

export const AUDIT_AUTHZ_TOOL = 'cipp_get_authorization_policy';
export const AUDIT_GRANTS_TOOL = 'cipp_list_delegated_grants';
export const AUDIT_ROLE_ASSIGNMENTS_TOOL = 'cipp_list_app_role_assignments';
export const AUDIT_APPS_TOOL = 'cipp_list_app_registrations';
export const AUDIT_CONSENT_TOOL = 'cipp_get_consent_policies';
export const AUDIT_CROSS_TENANT_TOOL = 'cipp_get_cross_tenant_policy';
export const AUDIT_SPAM_TOOL = 'cipp_get_outbound_spam_policy';

export const AUDIT_TOOL_NAMES = [
  AUDIT_AUTHZ_TOOL,
  AUDIT_GRANTS_TOOL,
  AUDIT_ROLE_ASSIGNMENTS_TOOL,
  AUDIT_APPS_TOOL,
  AUDIT_CONSENT_TOOL,
  AUDIT_CROSS_TENANT_TOOL,
  AUDIT_SPAM_TOOL,
] as const;

export const AUDIT_MAX_ROWS = 1000;
/** Cap on any one string other than the uncapped fields (scope). Far above what a name or id needs. */
export const AUDIT_MAX_STRING = 4096;
/** Cap on any one array (permission lists, targets, credentials). */
export const AUDIT_MAX_ARRAY = 500;
/** Graph returns at most 20 expanded objects per navigation property. */
export const GRAPH_EXPAND_LIMIT = 20;
const TENANT = /^[A-Za-z0-9._-]{1,255}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);

// ---------------------------------------------------------------------------
// Truncation bookkeeping
// ---------------------------------------------------------------------------

/** Names of the fields that were cut, so the output can say so. */
export class Trunc {
  readonly fields = new Set<string>();
  add(name: string): void {
    this.fields.add(name);
  }
  get any(): boolean {
    return this.fields.size > 0;
  }
}

/** Adds truncated / truncatedFields (and a note) to a result object. */
function withTruncation(result: Json, t: Trunc): Json {
  if (!t.any) return { ...result, truncated: false };
  const fields = [...t.fields].sort();
  const existing = typeof result['note'] === 'string' ? `${result['note']} ` : '';
  return {
    ...result,
    truncated: true,
    truncatedFields: fields,
    note: `${existing}TRUNCATED: some values were cut (${fields.join(', ')}). Do not treat the lists as complete.`,
  };
}

// ---------------------------------------------------------------------------
// ListDBCache restriction (cipp_exec_read)
// ---------------------------------------------------------------------------

const DBCACHE_CANONICAL = new Map(DBCACHE_ALLOWED_TYPES.map((t) => [t.toLowerCase(), t]));
/** The only arguments cipp_exec_read passes to ListDBCache (lower case). groupBy, select, top, latestOnly, dateField are refused. */
const DBCACHE_ALLOWED_ARGS = ['tenantfilter', 'type', 'countsonly'];

export type DbCacheRestriction =
  | { ok: true; args: Record<string, unknown>; type: string; countsOnly: boolean }
  | { ok: false; reason: string };

/**
 * Check a ListDBCache call made through cipp_exec_read (after argument-key canonicalisation and tenant
 * canonicalisation). The call is accepted only when:
 *  - the only arguments are tenantFilter, type and countsOnly (anything else, groupBy included, is refused by name);
 *  - tenantFilter is one tenant: AllTenants is refused in any case, with any spacing, zero-width or Unicode
 *    compatibility variant, and anything that is not a plain tenant identifier is refused;
 *  - type is a single string naming a reviewed cache type (policy.ts), compared case-insensitively;
 *  - countsOnly, if present, is true or false.
 * The canonical spelling of the type is what is sent. The rows that come back are projected (projectDbCacheResult).
 */
export function restrictDbCache(args: Record<string, unknown>): DbCacheRestriction {
  const allowedTypes = DBCACHE_ALLOWED_TYPES.join(', ');
  const seen = new Map<string, unknown>();
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (!DBCACHE_ALLOWED_ARGS.includes(lk) || seen.has(lk)) {
      return { ok: false, reason: `ListDBCache accepts only tenantFilter, type and countsOnly; argument '${k.slice(0, 40)}' is not allowed.` };
    }
    seen.set(lk, v);
  }

  const tenant = seen.get('tenantfilter');
  if (typeof tenant !== 'string' || tenant.trim() === '') {
    return { ok: false, reason: "ListDBCache needs tenantFilter: one tenant's default domain or tenant ID." };
  }
  // Compatibility-fold and drop invisible characters before comparing, so no variant of AllTenants gets through.
  const folded = tenant
    .normalize('NFKC')
    .replace(/[\p{Cc}\p{Cf}\p{Z}]/gu, '')
    .toLowerCase();
  if (folded === 'alltenants') return { ok: false, reason: 'ListDBCache through cipp_exec_read is single-tenant: AllTenants is not allowed.' };
  if (!TENANT.test(tenant.trim())) return { ok: false, reason: "ListDBCache tenantFilter must be one tenant's default domain or tenant ID." };

  if (!seen.has('type')) return { ok: false, reason: `ListDBCache needs a 'type', and only these cache types are allowed: ${allowedTypes}.` };
  const type = seen.get('type');
  if (typeof type !== 'string') {
    return { ok: false, reason: `ListDBCache 'type' must be a single string; only these cache types are allowed: ${allowedTypes}.` };
  }
  const canonical = DBCACHE_CANONICAL.get(type.trim().toLowerCase());
  if (!canonical) {
    return { ok: false, reason: `ListDBCache type '${type.slice(0, 60)}' is not allowed by IT Simply policy. Allowed cache types: ${allowedTypes}.` };
  }

  let countsOnly = false;
  if (seen.has('countsonly')) {
    const c = seen.get('countsonly');
    if (c === true || c === 'true') countsOnly = true;
    else if (c !== false && c !== 'false') return { ok: false, reason: 'ListDBCache countsOnly must be true or false.' };
  }

  // Rebuild the arguments with the declared key spellings, the trimmed tenant and the canonical type.
  const keyOf = (lk: string) => Object.keys(args).find((k) => k.toLowerCase() === lk)!;
  const rebuilt: Record<string, unknown> = {
    [keyOf('tenantfilter')]: tenant.trim(),
    [keyOf('type')]: canonical,
  };
  if (seen.has('countsonly')) rebuilt[keyOf('countsonly')] = seen.get('countsonly');
  return { ok: true, args: rebuilt, type: canonical, countsOnly };
}

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

const TENANT_PROP = { type: 'string', description: "The tenant's default domain or tenant ID. AllTenants is not allowed." };
const annotations = (title: string) => ({ title, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
const schema = (extra: Record<string, unknown> = {}) => ({
  type: 'object',
  properties: { tenantFilter: TENANT_PROP, ...extra },
  required: ['tenantFilter', ...Object.keys(extra)],
  additionalProperties: false,
});

export const AUDIT_TOOL_DEFINITIONS = [
  {
    name: AUDIT_AUTHZ_TOOL,
    description:
      'Entra authorization policy for ONE tenant (live Graph beta policies/authorizationPolicy), projected: defaultUserRolePermissions (app, tenant, security-group and agent-identity-blueprint creation, BitLocker key read), guest role and invite settings, SSPR, MSOL PowerShell, email-verified join and sign-up, risky-app consent.',
    inputSchema: schema(),
    annotations: annotations('Entra authorization policy'),
  },
  {
    name: AUDIT_GRANTS_TOOL,
    description:
      'Delegated OAuth2 permission grants (oauth2PermissionGrants) for ONE tenant, live: id, clientId, resourceId, consentType, principalId, scope (the full scope string, never cut). Resolve the ids against cipp_list_enterprise_apps.',
    inputSchema: schema(),
    annotations: annotations('Delegated permission grants'),
  },
  {
    name: AUDIT_ROLE_ASSIGNMENTS_TOOL,
    description:
      "App role assignments of ONE service principal in ONE tenant, live: resourceId, resourceDisplayName, appRoleId, principalId, principalDisplayName, createdDateTime. Takes the service principal's object id (a GUID, not the appId).",
    inputSchema: schema({ servicePrincipalId: { type: 'string', description: "The service principal's object id (a GUID; not the appId)." } }),
    annotations: annotations('App role assignments of a service principal'),
  },
  {
    name: AUDIT_APPS_TOOL,
    description:
      'App registrations (applications) for ONE tenant, live: id, appId, displayName, createdDateTime, signInAudience, publisherDomain, owners (id and userPrincipalName only; Graph returns at most 20 per app, flagged ownersTruncated), and for each secret or certificate only keyId, displayName, startDateTime, endDateTime. Secret values and hints are never returned.',
    inputSchema: schema(),
    annotations: annotations('App registrations'),
  },
  {
    name: AUDIT_CONSENT_TOOL,
    description:
      'User consent settings for ONE tenant, live: app consent (permissionGrantPolicies) with their include and exclude conditions, and the admin consent request workflow (isEnabled, notifyReviewers, remindersEnabled, requestDurationInDays, reviewers).',
    inputSchema: schema(),
    annotations: annotations('Consent policies'),
  },
  {
    name: AUDIT_CROSS_TENANT_TOOL,
    description:
      'Default cross-tenant access policy for ONE tenant, live: inboundTrust, B2B collaboration and direct connect inbound and outbound settings, automaticUserConsentSettings, tenantRestrictions when present.',
    inputSchema: schema(),
    annotations: annotations('Cross-tenant access policy'),
  },
  {
    name: AUDIT_SPAM_TOOL,
    description:
      "Exchange outbound spam policy for ONE tenant (Get-HostedOutboundSpamFilterPolicy), projected: Name, IsDefault, AutoForwardingMode, the three recipient limits, ActionWhenThresholdReached. This is CIPP's CACHED copy, up to about 24 hours old (cachedAt says when), refreshed by the write-tier cache sync; it is not a live read.",
    inputSchema: schema(),
    annotations: annotations('Outbound spam policy (cached)'),
  },
];

// ---------------------------------------------------------------------------
// Projection helpers
// ---------------------------------------------------------------------------

/**
 * Only the named fields, only primitive values (key lookup is case-insensitive; the canonical name is returned).
 * A string longer than AUDIT_MAX_STRING is cut and its field recorded in `t`, except the fields listed in `uncapped`.
 */
export function pick(row: unknown, fields: readonly string[], t?: Trunc, uncapped: readonly string[] = []): Json {
  const out: Json = {};
  if (!isObj(row)) return out;
  const lower = new Map(Object.entries(row).map(([k, v]) => [k.toLowerCase(), v]));
  for (const f of fields) {
    const v = lower.get(f.toLowerCase());
    if (typeof v === 'string') {
      if (v.length > AUDIT_MAX_STRING && !uncapped.includes(f)) {
        out[f] = v.slice(0, AUDIT_MAX_STRING);
        t?.add(f);
      } else out[f] = v;
    } else if (typeof v === 'number' || typeof v === 'boolean' || v === null) out[f] = v;
  }
  return out;
}

function strings(v: unknown, field: string, t: Trunc): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const all = v.filter((x): x is string => typeof x === 'string');
  if (all.length > AUDIT_MAX_ARRAY || all.some((s) => s.length > AUDIT_MAX_STRING)) t.add(field);
  return all.slice(0, AUDIT_MAX_ARRAY).map((s) => (s.length > AUDIT_MAX_STRING ? s.slice(0, AUDIT_MAX_STRING) : s));
}

/** Map an array through `fn`, capped, recording a cut in `t`. */
function mapArray(v: unknown, field: string, t: Trunc, fn: (item: unknown) => Json): Json[] | undefined {
  if (!Array.isArray(v)) return undefined;
  if (v.length > AUDIT_MAX_ARRAY) t.add(field);
  return v.slice(0, AUDIT_MAX_ARRAY).map(fn);
}

function lowerGet(row: unknown, name: string): unknown {
  if (!isObj(row)) return undefined;
  const k = Object.keys(row).find((x) => x.toLowerCase() === name.toLowerCase());
  return k === undefined ? undefined : row[k];
}

// --- projections -----------------------------------------------------------

const AUTHZ_FIELDS = [
  'id',
  'displayName',
  'guestUserRoleId',
  'allowInvitesFrom',
  'allowedToUseSSPR',
  'blockMsolPowerShell',
  'allowEmailVerifiedUsersToJoinOrganization',
  'allowedToSignUpEmailBasedSubscriptions',
  'allowUserConsentForRiskyApps',
] as const;

/** defaultUserRolePermissions: an explicit list. A field Graph adds later is dropped until reviewed. */
export const DEFAULT_USER_ROLE_PERMISSION_FIELDS = [
  'allowedToCreateApps',
  'allowedToCreateAgentIdentityBlueprints',
  'allowedToCreateSecurityGroups',
  'allowedToCreateTenants',
  'allowedToReadBitlockerKeysForOwnedDevice',
  'allowedToReadOtherUsers',
] as const;

export function projectAuthorizationPolicy(row: unknown, t: Trunc = new Trunc()): Json {
  const policy: Json = pick(row, AUTHZ_FIELDS, t);
  for (const f of ['enabledPreviewFeatures', 'permissionGrantPolicyIdsAssignedToDefaultUserRole']) {
    const a = strings(lowerGet(row, f), f, t);
    if (a) policy[f] = a;
  }
  const dur = lowerGet(row, 'defaultUserRolePermissions');
  if (isObj(dur)) {
    const perms: Json = pick(dur, DEFAULT_USER_ROLE_PERMISSION_FIELDS, t);
    const assigned = strings(dur['permissionGrantPoliciesAssigned'], 'defaultUserRolePermissions.permissionGrantPoliciesAssigned', t);
    if (assigned) perms['permissionGrantPoliciesAssigned'] = assigned;
    policy['defaultUserRolePermissions'] = perms;
  }
  return policy;
}

export const GRANT_FIELDS = ['id', 'clientId', 'resourceId', 'consentType', 'principalId', 'scope'] as const;
/** Fields whose value IS the finding: never cut. */
const UNCAPPED_FIELDS = ['scope'] as const;
export const ROLE_ASSIGNMENT_FIELDS = ['resourceId', 'resourceDisplayName', 'appRoleId', 'principalId', 'principalDisplayName', 'createdDateTime'] as const;
export const APP_FIELDS = ['id', 'appId', 'displayName', 'createdDateTime', 'signInAudience', 'publisherDomain'] as const;
/** No `hint`: it is the first characters of the secret value. */
export const CREDENTIAL_FIELDS = ['keyId', 'displayName', 'startDateTime', 'endDateTime'] as const;

export function projectGrant(row: unknown, t: Trunc = new Trunc()): Json {
  return pick(row, GRANT_FIELDS, t, UNCAPPED_FIELDS);
}

export function projectRoleAssignment(row: unknown, t: Trunc = new Trunc()): Json {
  return pick(row, ROLE_ASSIGNMENT_FIELDS, t);
}

export function projectApp(row: unknown, t: Trunc = new Trunc()): Json {
  const app: Json = pick(row, APP_FIELDS, t);
  for (const f of ['passwordCredentials', 'keyCredentials']) {
    const list = mapArray(lowerGet(row, f), f, t, (c) => pick(c, CREDENTIAL_FIELDS, t));
    if (list) app[f] = list;
  }
  const owners = mapArray(lowerGet(row, 'owners'), 'owners', t, (o) => pick(o, ['id', 'userPrincipalName'], t));
  if (owners) {
    app['owners'] = owners;
    if (owners.length >= GRAPH_EXPAND_LIMIT) {
      app['ownersTruncated'] = true;
      t.add('owners');
    }
  }
  return app;
}

const CONDITION_FIELDS = [
  'id',
  'permissionClassification',
  'permissionType',
  'resourceApplication',
  'clientApplicationsFromVerifiedPublisherOnly',
  'certifiedClientApplicationsOnly',
] as const;
const CONDITION_ARRAYS = ['permissions', 'clientApplicationIds', 'clientApplicationTenantIds', 'clientApplicationPublisherIds'] as const;

function projectConditionSet(c: unknown, t: Trunc): Json {
  const out: Json = pick(c, CONDITION_FIELDS, t);
  for (const f of CONDITION_ARRAYS) {
    const a = strings(lowerGet(c, f), `conditions.${f}`, t);
    if (a) out[f] = a;
  }
  return out;
}

export function projectPermissionGrantPolicy(row: unknown, t: Trunc = new Trunc()): Json {
  const out: Json = pick(row, ['id', 'displayName', 'description', 'includeAllPreApprovedApplications', 'resourceScopeType'], t);
  for (const f of ['includes', 'excludes']) {
    const list = mapArray(lowerGet(row, f), f, t, (c) => projectConditionSet(c, t));
    if (list) out[f] = list;
  }
  return out;
}

export function projectConsentRequestPolicy(row: unknown, t: Trunc = new Trunc()): Json {
  const out: Json = pick(row, ['isEnabled', 'notifyReviewers', 'remindersEnabled', 'requestDurationInDays', 'version'], t);
  const reviewers = mapArray(lowerGet(row, 'reviewers'), 'reviewers', t, (r) => pick(r, ['query', 'queryType', 'queryRoot'], t));
  if (reviewers) out['reviewers'] = reviewers;
  return out;
}

const ACCESS_BLOCKS = ['usersAndGroups', 'applications'] as const;

/** { usersAndGroups, applications } each { accessType, targets[{ target, targetType }] }. */
function projectAccessSettings(v: unknown, field: string, t: Trunc): Json | undefined {
  if (!isObj(v)) return undefined;
  const out: Json = {};
  for (const b of ACCESS_BLOCKS) {
    const block = lowerGet(v, b);
    if (!isObj(block)) continue;
    const projected: Json = pick(block, ['accessType'], t);
    const targets = mapArray(lowerGet(block, 'targets'), `${field}.${b}.targets`, t, (x) => pick(x, ['target', 'targetType'], t));
    if (targets) projected['targets'] = targets;
    out[b] = projected;
  }
  return out;
}

export function projectCrossTenantPolicy(row: unknown, t: Trunc = new Trunc()): Json {
  const out: Json = pick(row, ['isServiceDefault'], t);
  const trust = lowerGet(row, 'inboundTrust');
  if (isObj(trust)) {
    out['inboundTrust'] = pick(trust, ['isMfaAccepted', 'isCompliantDeviceAccepted', 'isHybridAzureADJoinedDeviceAccepted', 'isCompliantNetworkAccepted'], t);
  }
  for (const f of ['b2bCollaborationInbound', 'b2bCollaborationOutbound', 'b2bDirectConnectInbound', 'b2bDirectConnectOutbound']) {
    const p = projectAccessSettings(lowerGet(row, f), f, t);
    if (p) out[f] = p;
  }
  const consent = lowerGet(row, 'automaticUserConsentSettings');
  if (isObj(consent)) out['automaticUserConsentSettings'] = pick(consent, ['inboundAllowed', 'outboundAllowed'], t);
  const tr = lowerGet(row, 'tenantRestrictions');
  if (isObj(tr)) {
    const p = projectAccessSettings(tr, 'tenantRestrictions', t) ?? {};
    const devices = lowerGet(tr, 'devices');
    if (devices === null) p['devices'] = null;
    else if (isObj(devices)) p['devices'] = pick(devices, ['mode', 'rule'], t);
    out['tenantRestrictions'] = p;
  }
  return out;
}

export const SPAM_FIELDS = [
  'Name',
  'IsDefault',
  'AutoForwardingMode',
  'RecipientLimitExternalPerHour',
  'RecipientLimitInternalPerHour',
  'RecipientLimitPerDay',
  'ActionWhenThresholdReached',
] as const;

export function projectSpamPolicy(row: unknown, t: Trunc = new Trunc()): Json {
  return pick(row, SPAM_FIELDS, t);
}

// --- ListDBCache rows through cipp_exec_read ------------------------------

const DB_PROJECTORS: Record<string, (row: unknown, t: Trunc) => Json> = {
  AuthorizationPolicy: projectAuthorizationPolicy,
  OAuth2PermissionGrants: projectGrant,
  AppRoleAssignments: projectRoleAssignment,
  PermissionGrantPolicies: projectPermissionGrantPolicy,
  AdminConsentRequestPolicy: projectConsentRequestPolicy,
  CrossTenantAccessPolicy: projectCrossTenantPolicy,
  ExoHostedOutboundSpamFilterPolicy: projectSpamPolicy,
};

/**
 * Project a ListDBCache response for one of the allowed types through the same allow-lists the audit tools use.
 * Throws an Error (to be shown as the tool error) when CIPP returned something that is not a Results list.
 */
export function projectDbCacheResult(type: string, countsOnly: boolean, raw: unknown): Json {
  const results = isObj(raw) ? raw['Results'] : raw;
  if (typeof results === 'string') throw new Error(truncateError(results));
  if (!Array.isArray(results)) throw new Error('CIPP returned no Results for the cache read.');
  const t = new Trunc();
  const project = (r: unknown): Json =>
    countsOnly ? pick(r, ['Tenant', 'Type', 'Count', 'LastRefresh'], t) : { ...pick(r, ['Tenant'], t), ...DB_PROJECTORS[type]!(r, t) };
  if (results.length > AUDIT_MAX_ROWS) t.add('Results (rows)');
  return withTruncation({ type, returned: results.length, Results: results.slice(0, AUDIT_MAX_ROWS).map(project) }, t);
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export interface AuditToolDeps {
  service: {
    callEndpoint(
      method: 'GET' | 'POST',
      path: string,
      params?: Record<string, unknown>,
      body?: Record<string, unknown> | unknown[]
    ): Promise<unknown>;
  };
  logger: CatalogueLogger & { error(message: string, meta?: unknown): void };
  ctx: ToolContext;
}

export interface AuditToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

const out = (value: unknown, isError = false): AuditToolResult => ({
  content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }],
  ...(isError ? { isError: true } : {}),
});

class AuditError extends Error {}

const errText = (err: unknown): string => truncateError(err instanceof Error ? err.message : String(err));

/**
 * One fixed GET through CIPP's ListGraphRequest. Returns the Results rows. CIPP follows @odata.nextLink to the end
 * (single tenant, no NoPagination or manualPagination sent). `$top`, `$select` and `$expand` are sent only when
 * the caller of this helper (never the tool's user) asks for them.
 */
async function graphRows(
  deps: AuditToolDeps,
  tenant: string,
  endpoint: string,
  options: { top?: boolean; select?: string; expand?: string } = {}
): Promise<Json[]> {
  const params: Record<string, unknown> = { tenantFilter: tenant, Endpoint: endpoint, Version: 'beta' };
  if (options.top) params['$top'] = 999;
  if (options.select) params['$select'] = options.select;
  if (options.expand) params['$expand'] = options.expand;
  let raw: unknown;
  try {
    raw = await deps.service.callEndpoint('GET', 'ListGraphRequest', params);
  } catch (err) {
    throw new AuditError(errText(err));
  }
  const results = isObj(raw) ? raw['Results'] : raw;
  if (typeof results === 'string') throw new AuditError(truncateError(results));
  const rows = Array.isArray(results) ? results : isObj(results) ? [results] : undefined;
  if (!rows) throw new AuditError('CIPP returned no Results for the Graph read.');
  return rows.filter(isObj);
}

function listResult(tenant: string, source: string, rows: unknown[], key: string, t: Trunc): Json {
  const shown = rows.slice(0, AUDIT_MAX_ROWS);
  if (rows.length > AUDIT_MAX_ROWS) t.add(`${key} (rows)`);
  return withTruncation({ tenant, source, returned: rows.length, shown: shown.length, [key]: shown }, t);
}

export async function runAuditTool(name: string, args: Record<string, unknown>, deps: AuditToolDeps): Promise<AuditToolResult> {
  const refuse = (reason: string) => {
    deps.logger.warn('CIPP tool call refused', { tool: name, reason: reason.slice(0, 120), user: deps.ctx.user });
    return out(`Refused: ${reason}`, true);
  };
  const takesSp = name === AUDIT_ROLE_ASSIGNMENTS_TOOL;
  const allowedArgs = takesSp ? ['tenantfilter', 'serviceprincipalid'] : ['tenantfilter'];
  const seen = new Map<string, unknown>();
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (!allowedArgs.includes(lk) || seen.has(lk)) {
      return refuse(`unexpected or repeated argument '${k.slice(0, 40)}'; ${name} accepts only ${takesSp ? 'tenantFilter and servicePrincipalId' : 'tenantFilter'}.`);
    }
    seen.set(lk, v);
  }
  const rawTenant = seen.get('tenantfilter');
  if (typeof rawTenant !== 'string' || rawTenant.trim() === '') return refuse("provide tenantFilter: one tenant's default domain or tenant ID.");
  const tenant = rawTenant.trim();
  if (tenant.toLowerCase() === 'alltenants') return refuse('AllTenants is not allowed - read one tenant at a time.');
  if (!TENANT.test(tenant)) return refuse("tenantFilter must be one tenant's default domain or tenant ID.");

  let spId = '';
  if (takesSp) {
    const raw = seen.get('serviceprincipalid');
    if (typeof raw !== 'string' || !GUID.test(raw.trim())) return refuse("servicePrincipalId must be the service principal's object id (a GUID).");
    spId = raw.trim().toLowerCase();
  }

  deps.logger.info('CIPP audit read', { tool: name, tenant, callerTier: deps.ctx.tier, user: deps.ctx.user });
  const t = new Trunc();

  try {
    switch (name) {
      case AUDIT_AUTHZ_TOOL: {
        const rows = await graphRows(deps, tenant, 'policies/authorizationPolicy');
        if (rows.length === 0) throw new AuditError('CIPP returned no authorization policy.');
        return out(withTruncation({ tenant, source: 'Graph beta policies/authorizationPolicy (live)', policy: projectAuthorizationPolicy(rows[0], t) }, t));
      }
      case AUDIT_GRANTS_TOOL: {
        const rows = await graphRows(deps, tenant, 'oauth2PermissionGrants', { top: true });
        return out(listResult(tenant, 'Graph beta oauth2PermissionGrants (live)', rows.map((r) => projectGrant(r, t)), 'grants', t));
      }
      case AUDIT_ROLE_ASSIGNMENTS_TOOL: {
        const rows = await graphRows(deps, tenant, `servicePrincipals/${spId}/appRoleAssignments`);
        return out({
          servicePrincipalId: spId,
          ...listResult(tenant, 'Graph beta servicePrincipals/{id}/appRoleAssignments (live)', rows.map((r) => projectRoleAssignment(r, t)), 'assignments', t),
        });
      }
      case AUDIT_APPS_TOOL: {
        const select = [...APP_FIELDS, 'passwordCredentials', 'keyCredentials'].join(',');
        const rows = await graphRows(deps, tenant, 'applications', { top: true, select, expand: 'owners($select=id,userPrincipalName)' });
        return out({ ownersIncluded: true, ...listResult(tenant, 'Graph beta applications (live)', rows.map((r) => projectApp(r, t)), 'applications', t) });
      }
      case AUDIT_CONSENT_TOOL: {
        const result: Json = { tenant, source: 'Graph beta policies/permissionGrantPolicies and policies/adminConsentRequestPolicy (live)' };
        try {
          const rows = await graphRows(deps, tenant, 'policies/permissionGrantPolicies');
          if (rows.length > AUDIT_MAX_ROWS) t.add('permissionGrantPolicies (rows)');
          result['permissionGrantPolicies'] = rows.slice(0, AUDIT_MAX_ROWS).map((r) => projectPermissionGrantPolicy(r, t));
        } catch (err) {
          result['permissionGrantPoliciesError'] = errText(err);
        }
        try {
          const rows = await graphRows(deps, tenant, 'policies/adminConsentRequestPolicy');
          result['adminConsentRequestPolicy'] = rows.length > 0 ? projectConsentRequestPolicy(rows[0], t) : null;
        } catch (err) {
          result['adminConsentRequestPolicyError'] = errText(err);
        }
        const failed = 'permissionGrantPoliciesError' in result && 'adminConsentRequestPolicyError' in result;
        return out(withTruncation(result, t), failed);
      }
      case AUDIT_CROSS_TENANT_TOOL: {
        const rows = await graphRows(deps, tenant, 'policies/crossTenantAccessPolicy/default');
        if (rows.length === 0) throw new AuditError('CIPP returned no cross-tenant access policy.');
        return out(withTruncation({ tenant, source: 'Graph beta policies/crossTenantAccessPolicy/default (live)', policy: projectCrossTenantPolicy(rows[0], t) }, t));
      }
      case AUDIT_SPAM_TOOL:
        return await runSpam(tenant, deps, t);
      default:
        return out(`Unknown audit tool: ${name}`, true);
    }
  } catch (err) {
    return out(errText(err), true);
  }
}

export const SPAM_CACHE_TYPE = 'ExoHostedOutboundSpamFilterPolicy';

async function runSpam(tenant: string, deps: AuditToolDeps, t: Trunc): Promise<AuditToolResult> {
  const rowsOf = (raw: unknown): unknown[] => {
    const r = isObj(raw) ? raw['Results'] : raw;
    if (typeof r === 'string') throw new AuditError(truncateError(r));
    if (!Array.isArray(r)) throw new AuditError('CIPP returned no Results for the cache read.');
    return r;
  };
  let policies: unknown[];
  try {
    policies = rowsOf(await deps.service.callEndpoint('GET', 'ListDBCache', { tenantFilter: tenant, type: SPAM_CACHE_TYPE }));
  } catch (err) {
    return out(errText(err), true);
  }
  let cachedAt: string | null = null;
  try {
    const counts = rowsOf(await deps.service.callEndpoint('GET', 'ListDBCache', { tenantFilter: tenant, type: SPAM_CACHE_TYPE, countsOnly: 'true' }));
    const row = counts.find((r) => isObj(r) && String(lowerGet(r, 'Type')).toLowerCase() === SPAM_CACHE_TYPE.toLowerCase());
    const ts = lowerGet(row, 'LastRefresh');
    if (typeof ts === 'string') cachedAt = ts.slice(0, 64);
  } catch {
    cachedAt = null;
  }
  if (policies.length > AUDIT_MAX_ROWS) t.add('policies (rows)');
  return out(
    withTruncation(
      {
        tenant,
        source: "CIPP's cached copy (ListDBCache type ExoHostedOutboundSpamFilterPolicy), up to about 24 hours old, refreshed by the write-tier cache sync",
        cachedAt,
        ...(policies.length === 0
          ? { note: 'The cache holds no outbound spam policy for this tenant (not cached yet, or none returned). A write-tier caller can refresh it with the cache sync.' }
          : {}),
        policies: policies.slice(0, AUDIT_MAX_ROWS).map((p) => projectSpamPolicy(p, t)),
      },
      t
    )
  );
}
