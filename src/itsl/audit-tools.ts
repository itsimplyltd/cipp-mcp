// IT Simply Ltd: read-tier named audit tools for the M365 security and governance review (new file).
//
// ListGraphRequest and ListExoRequest stay BLOCKED for cipp_exec_read and cipp_exec_write. These
// tools are the narrow routes to the handful of reads the review needs. Each one:
//  - calls ONE fixed CIPP endpoint shape built here (a fixed Graph path through ListGraphRequest, the same
//    CIPP route cipp_list_enterprise_apps uses, or ListDBCache with a fixed type); no caller-supplied path,
//    cmdlet, filter or OData option;
//  - takes tenantFilter (one tenant, never AllTenants) and, for one tool, a GUID; any other argument is refused;
//  - PROJECTS the answer to an explicit field allow-list, so a field CIPP or Graph adds later, or a credential
//    value, cannot be returned. Credential value fields are never in an allow-list.
// Tier: every tool maps to CIPP.Core.Read endpoints (AUDIT_TOOL_ENDPOINTS in named-tools.ts), so a read-tier user
// is never refused by CIPP's own role check. Also here: the ListDBCache type allow-list check (restrictDbCache).

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
const MAX_STRING = 512;
const MAX_ARRAY = 100;
const MAX_DEPTH = 6;
const TENANT = /^[A-Za-z0-9._-]{1,255}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// ListDBCache type allow-list
// ---------------------------------------------------------------------------

const DBCACHE_CANONICAL = new Map(DBCACHE_ALLOWED_TYPES.map((t) => [t.toLowerCase(), t]));

/**
 * Check a ListDBCache call's `type` (after argument-key canonicalisation). Returns the arguments with the
 * canonical spelling of the type, or a refusal naming the type. A missing or non-string type is refused too,
 * which also refuses type-less calls such as countsOnly, _availableTypes and _shape listings.
 */
export function restrictDbCache(
  args: Record<string, unknown>
): { ok: true; args: Record<string, unknown> } | { ok: false; reason: string } {
  const key = Object.keys(args).find((k) => k.toLowerCase() === 'type');
  const allowed = DBCACHE_ALLOWED_TYPES.join(', ');
  if (key === undefined) {
    return { ok: false, reason: `ListDBCache needs a 'type', and only these cache types are allowed: ${allowed}.` };
  }
  const value = args[key];
  if (typeof value !== 'string') {
    return { ok: false, reason: `ListDBCache 'type' must be a single string; only these cache types are allowed: ${allowed}.` };
  }
  const canonical = DBCACHE_CANONICAL.get(value.trim().toLowerCase());
  if (!canonical) {
    return { ok: false, reason: `ListDBCache type '${value.slice(0, 60)}' is not allowed by IT Simply policy. Allowed cache types: ${allowed}.` };
  }
  return { ok: true, args: { ...args, [key]: canonical } };
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
      'Delegated OAuth2 permission grants (oauth2PermissionGrants) for ONE tenant, live: id, clientId, resourceId, consentType, principalId, scope. Resolve the ids against cipp_list_enterprise_apps.',
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
      'App registrations (applications) for ONE tenant, live: id, appId, displayName, createdDateTime, signInAudience, publisherDomain, owners (id and userPrincipalName only), and for each secret or certificate only keyId, displayName, startDateTime, endDateTime, hint. Secret values are never returned.',
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

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);

function prim(v: unknown): string | number | boolean | null | undefined {
  if (typeof v === 'string') return v.length > MAX_STRING ? v.slice(0, MAX_STRING) : v;
  if (typeof v === 'number' || typeof v === 'boolean' || v === null) return v;
  return undefined;
}

/** Only the named fields, only primitive values (key lookup is case-insensitive; the canonical name is returned). */
export function pick(row: unknown, fields: readonly string[]): Json {
  const out: Json = {};
  if (!isObj(row)) return out;
  const lower = new Map(Object.entries(row).map(([k, v]) => [k.toLowerCase(), v]));
  for (const f of fields) {
    const v = prim(lower.get(f.toLowerCase()));
    if (v !== undefined) out[f] = v;
  }
  return out;
}

function strings(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v
    .filter((x): x is string => typeof x === 'string')
    .slice(0, MAX_ARRAY)
    .map((s) => (s.length > MAX_STRING ? s.slice(0, MAX_STRING) : s));
}

/** Copy of a policy value: primitives, arrays and objects, without @odata keys and CIPP stamps, bounded in depth and size. */
export function safeCopy(v: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) return undefined;
  const p = prim(v);
  if (p !== undefined) return p;
  if (Array.isArray(v)) return v.slice(0, MAX_ARRAY).map((x) => safeCopy(x, depth + 1));
  if (isObj(v)) {
    const out: Json = {};
    for (const [k, x] of Object.entries(v)) {
      if (k.startsWith('@') || k === 'Tenant' || k === 'CippStatus') continue;
      const c = safeCopy(x, depth + 1);
      if (c !== undefined) out[k] = c;
    }
    return out;
  }
  return undefined;
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

export function projectAuthorizationPolicy(row: unknown): Json {
  const policy: Json = pick(row, AUTHZ_FIELDS);
  for (const f of ['enabledPreviewFeatures', 'permissionGrantPolicyIdsAssignedToDefaultUserRole']) {
    const a = strings(lowerGet(row, f));
    if (a) policy[f] = a;
  }
  const dur = lowerGet(row, 'defaultUserRolePermissions');
  if (isObj(dur)) {
    const perms: Json = {};
    for (const [k, v] of Object.entries(dur)) {
      const p = prim(v);
      if (p !== undefined && !k.startsWith('@')) perms[k] = p;
    }
    const assigned = strings(dur['permissionGrantPoliciesAssigned']);
    if (assigned) perms['permissionGrantPoliciesAssigned'] = assigned;
    policy['defaultUserRolePermissions'] = perms;
  }
  return policy;
}

export const GRANT_FIELDS = ['id', 'clientId', 'resourceId', 'consentType', 'principalId', 'scope'] as const;
export const ROLE_ASSIGNMENT_FIELDS = ['resourceId', 'resourceDisplayName', 'appRoleId', 'principalId', 'principalDisplayName', 'createdDateTime'] as const;
export const APP_FIELDS = ['id', 'appId', 'displayName', 'createdDateTime', 'signInAudience', 'publisherDomain'] as const;
export const CREDENTIAL_FIELDS = ['keyId', 'displayName', 'startDateTime', 'endDateTime', 'hint'] as const;

export function projectApp(row: unknown): Json {
  const app: Json = pick(row, APP_FIELDS);
  for (const f of ['passwordCredentials', 'keyCredentials']) {
    const list = lowerGet(row, f);
    if (Array.isArray(list)) app[f] = list.slice(0, MAX_ARRAY).map((c) => pick(c, CREDENTIAL_FIELDS));
  }
  const owners = lowerGet(row, 'owners');
  if (Array.isArray(owners)) app['owners'] = owners.slice(0, MAX_ARRAY).map((o) => pick(o, ['id', 'userPrincipalName']));
  return app;
}

const CONDITION_FIELDS = ['id', 'permissionClassification', 'permissionType', 'resourceApplication', 'clientApplicationsFromVerifiedPublisherOnly'] as const;
const CONDITION_ARRAYS = ['permissions', 'clientApplicationIds', 'clientApplicationTenantIds', 'clientApplicationPublisherIds'] as const;

function projectConditionSet(c: unknown): Json {
  const out: Json = pick(c, CONDITION_FIELDS);
  for (const f of CONDITION_ARRAYS) {
    const a = strings(lowerGet(c, f));
    if (a) out[f] = a;
  }
  return out;
}

export function projectPermissionGrantPolicy(row: unknown): Json {
  const out: Json = pick(row, ['id', 'displayName', 'description']);
  for (const f of ['includes', 'excludes']) {
    const list = lowerGet(row, f);
    if (Array.isArray(list)) out[f] = list.slice(0, MAX_ARRAY).map(projectConditionSet);
  }
  return out;
}

export function projectConsentRequestPolicy(row: unknown): Json {
  const out: Json = pick(row, ['isEnabled', 'notifyReviewers', 'remindersEnabled', 'requestDurationInDays', 'version']);
  const reviewers = lowerGet(row, 'reviewers');
  if (Array.isArray(reviewers)) out['reviewers'] = reviewers.slice(0, MAX_ARRAY).map((r) => pick(r, ['query', 'queryType', 'queryRoot']));
  return out;
}

export const CROSS_TENANT_FIELDS = [
  'inboundTrust',
  'b2bCollaborationInbound',
  'b2bCollaborationOutbound',
  'b2bDirectConnectInbound',
  'b2bDirectConnectOutbound',
  'automaticUserConsentSettings',
  'tenantRestrictions',
] as const;

export function projectCrossTenantPolicy(row: unknown): Json {
  const out: Json = pick(row, ['isServiceDefault']);
  for (const f of CROSS_TENANT_FIELDS) {
    const v = lowerGet(row, f);
    if (v !== undefined) {
      const c = safeCopy(v);
      if (c !== undefined) out[f] = c;
    }
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

export function projectSpamPolicy(row: unknown): Json {
  return pick(row, SPAM_FIELDS);
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

/** One fixed GET through CIPP's ListGraphRequest. Returns the Results rows. */
async function graphRows(
  deps: AuditToolDeps,
  tenant: string,
  endpoint: string,
  version: 'v1.0' | 'beta',
  options: { select?: string; expand?: string } = {}
): Promise<Json[]> {
  const params: Record<string, unknown> = { tenantFilter: tenant, Endpoint: endpoint, Version: version, $top: 999 };
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

function listResult(tenant: string, source: string, rows: unknown[], key: string): Json {
  const shown = rows.slice(0, AUDIT_MAX_ROWS);
  const truncated = rows.length > AUDIT_MAX_ROWS;
  return {
    tenant,
    source,
    returned: rows.length,
    shown: shown.length,
    truncated,
    ...(truncated ? { note: `Showing the first ${AUDIT_MAX_ROWS} of ${rows.length} rows.` } : {}),
    [key]: shown,
  };
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

  try {
    switch (name) {
      case AUDIT_AUTHZ_TOOL: {
        const rows = await graphRows(deps, tenant, 'policies/authorizationPolicy', 'beta');
        if (rows.length === 0) throw new AuditError('CIPP returned no authorization policy.');
        return out({ tenant, source: 'Graph beta policies/authorizationPolicy (live)', policy: projectAuthorizationPolicy(rows[0]) });
      }
      case AUDIT_GRANTS_TOOL: {
        const rows = await graphRows(deps, tenant, 'oauth2PermissionGrants', 'v1.0', { select: GRANT_FIELDS.join(',') });
        return out(listResult(tenant, 'Graph v1.0 oauth2PermissionGrants (live)', rows.map((r) => pick(r, GRANT_FIELDS)), 'grants'));
      }
      case AUDIT_ROLE_ASSIGNMENTS_TOOL: {
        const rows = await graphRows(deps, tenant, `servicePrincipals/${spId}/appRoleAssignments`, 'v1.0');
        return out({
          servicePrincipalId: spId,
          ...listResult(tenant, 'Graph v1.0 servicePrincipals/{id}/appRoleAssignments (live)', rows.map((r) => pick(r, ROLE_ASSIGNMENT_FIELDS)), 'assignments'),
        });
      }
      case AUDIT_APPS_TOOL: {
        const select = [...APP_FIELDS, 'passwordCredentials', 'keyCredentials'].join(',');
        const rows = await graphRows(deps, tenant, 'applications', 'v1.0', { select, expand: 'owners($select=id,userPrincipalName)' });
        return out({ ownersIncluded: true, ...listResult(tenant, 'Graph v1.0 applications (live)', rows.map(projectApp), 'applications') });
      }
      case AUDIT_CONSENT_TOOL: {
        const result: Json = { tenant, source: 'Graph v1.0 policies/permissionGrantPolicies and policies/adminConsentRequestPolicy (live)' };
        try {
          const rows = await graphRows(deps, tenant, 'policies/permissionGrantPolicies', 'v1.0');
          result['permissionGrantPolicies'] = rows.slice(0, AUDIT_MAX_ROWS).map(projectPermissionGrantPolicy);
        } catch (err) {
          result['permissionGrantPoliciesError'] = errText(err);
        }
        try {
          const rows = await graphRows(deps, tenant, 'policies/adminConsentRequestPolicy', 'v1.0');
          result['adminConsentRequestPolicy'] = rows.length > 0 ? projectConsentRequestPolicy(rows[0]) : null;
        } catch (err) {
          result['adminConsentRequestPolicyError'] = errText(err);
        }
        const failed = 'permissionGrantPoliciesError' in result && 'adminConsentRequestPolicyError' in result;
        return out(result, failed);
      }
      case AUDIT_CROSS_TENANT_TOOL: {
        const rows = await graphRows(deps, tenant, 'policies/crossTenantAccessPolicy/default', 'v1.0');
        if (rows.length === 0) throw new AuditError('CIPP returned no cross-tenant access policy.');
        return out({ tenant, source: 'Graph v1.0 policies/crossTenantAccessPolicy/default (live)', policy: projectCrossTenantPolicy(rows[0]) });
      }
      case AUDIT_SPAM_TOOL:
        return await runSpam(tenant, deps);
      default:
        return out(`Unknown audit tool: ${name}`, true);
    }
  } catch (err) {
    return out(errText(err), true);
  }
}

export const SPAM_CACHE_TYPE = 'ExoHostedOutboundSpamFilterPolicy';

async function runSpam(tenant: string, deps: AuditToolDeps): Promise<AuditToolResult> {
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
    const t = lowerGet(row, 'LastRefresh');
    if (typeof t === 'string') cachedAt = t.slice(0, 64);
  } catch {
    cachedAt = null;
  }
  return out({
    tenant,
    source: "CIPP's cached copy (ListDBCache type ExoHostedOutboundSpamFilterPolicy), up to about 24 hours old, refreshed by the write-tier cache sync",
    cachedAt,
    ...(policies.length === 0
      ? { note: 'The cache holds no outbound spam policy for this tenant (not cached yet, or none returned). A write-tier caller can refresh it with the cache sync.' }
      : {}),
    policies: policies.slice(0, AUDIT_MAX_ROWS).map(projectSpamPolicy),
  });
}
