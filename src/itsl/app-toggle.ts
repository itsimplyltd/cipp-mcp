// IT Simply Ltd: write-tier enterprise-app disable / enable (new file).
//
// ExecApplication is DISABLED for everyone (it can PATCH or delete any application or
// service principal, remove credentials and change signing keys, as CIPP's own app
// identity). These two tools are the one narrow route to it: write tier only, one tenant,
// one service principal by object id, and exactly one request shape, built here and
// nowhere else: Action=Update on servicePrincipals/{id} with { accountEnabled: true|false }.
//
// Before writing, the service principal is read through ListGraphRequest (the same
// read-only path cipp_graph_request uses, built by graph.ts) and refused when it is a
// Microsoft first-party app, an app owned by IT Simply's tenant, anything other than an
// 'Application' service principal, or not found. After writing it is read again, and the
// call only reports success when Graph shows the requested state: CIPP can answer 200
// with a failure in Results.

import type { CatalogueLogger } from './catalogue.js';
import type { ToolContext } from './meta-tools.js';
import { buildGraphRequest } from './graph.js';
import { truncateError } from './frame.js';
import { ITSL_OWN_TENANT_IDS, MICROSOFT_FIRST_PARTY_TENANT_IDS } from './policy.js';
import { refusalReason } from './tier.js';

export const APP_DISABLE_TOOL_NAME = 'cipp_disable_enterprise_app';
export const APP_ENABLE_TOOL_NAME = 'cipp_enable_enterprise_app';
export const APP_TOGGLE_TOOL_NAMES = [APP_DISABLE_TOOL_NAME, APP_ENABLE_TOOL_NAME] as const;

/** The fields the pre-read and the re-read select. */
export const SP_SELECT = 'id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType';

/** Re-read policy after the write (Graph can lag a moment behind its own PATCH). Mutable for tests. */
export const appToggleTiming = { attempts: 3, delayMs: 2000 };

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT = /^[A-Za-z0-9._-]{1,255}$/;
const NOT_FOUND = /does not exist|Request_ResourceNotFound|ResourceNotFound/i;
const MS_SET = new Set(MICROSOFT_FIRST_PARTY_TENANT_IDS.map((t) => t.toLowerCase()));
const ITSL_SET = new Set(ITSL_OWN_TENANT_IDS.map((t) => t.toLowerCase()));

const inputSchema = {
  type: 'object',
  properties: {
    tenantFilter: { type: 'string', description: "The tenant's default domain or tenant ID. AllTenants is not allowed." },
    servicePrincipalId: { type: 'string', description: "The service principal's object id (a GUID; not the appId)." },
  },
  required: ['tenantFilter', 'servicePrincipalId'],
  additionalProperties: false,
};

export const APP_DISABLE_TOOL_DEFINITION = {
  name: APP_DISABLE_TOOL_NAME,
  description:
    "Disable one enterprise application (service principal) in ONE client tenant, so nobody can sign in to it (accountEnabled false). Write tier only. Takes the service principal's object id. Refuses Microsoft first-party apps, apps owned by IT Simply's tenant, managed identities and other non-Application types. Reports before and after; reversible with cipp_enable_enterprise_app.",
  inputSchema,
  annotations: {
    title: 'Disable an enterprise application',
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: true,
  },
};

export const APP_ENABLE_TOOL_DEFINITION = {
  name: APP_ENABLE_TOOL_NAME,
  description:
    "Re-enable one enterprise application (service principal) in ONE client tenant (accountEnabled true). Write tier only. Takes the service principal's object id. The same refusals as cipp_disable_enterprise_app apply. Reports before and after.",
  inputSchema,
  annotations: {
    title: 'Enable an enterprise application',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

export interface AppToggleDeps {
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
  /** Injectable wait (tests). */
  sleep?: (ms: number) => Promise<void>;
}

export interface AppToggleResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

interface ServicePrincipal {
  id: string;
  appId: unknown;
  displayName: unknown;
  accountEnabled: boolean;
  appOwnerOrganizationId: unknown;
  servicePrincipalType: unknown;
}

type ReadOutcome = { kind: 'found'; sp: ServicePrincipal } | { kind: 'notfound' } | { kind: 'error'; message: string };

const out = (value: unknown, isError = false): AppToggleResult => ({
  content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }],
  ...(isError ? { isError: true } : {}),
});

const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** One read-only GET of the service principal through ListGraphRequest, built by graph.ts. */
async function readSp(tenant: string, id: string, deps: AppToggleDeps): Promise<ReadOutcome> {
  const built = buildGraphRequest({ tenantFilter: tenant, endpoint: `servicePrincipals/${id}`, select: SP_SELECT, Version: 'v1.0' });
  if (!built.ok) return { kind: 'error', message: `the service principal read was refused: ${built.reason}` };
  let raw: unknown;
  try {
    raw = await deps.service.callEndpoint('GET', 'ListGraphRequest', built.params);
  } catch (err) {
    const m = errText(err);
    return NOT_FOUND.test(m) ? { kind: 'notfound' } : { kind: 'error', message: m };
  }
  const results = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>)['Results'] : raw;
  if (!Array.isArray(results)) {
    const m = typeof results === 'string' ? results : 'CIPP returned no Results array for the service principal read.';
    return NOT_FOUND.test(m) ? { kind: 'notfound' } : { kind: 'error', message: m };
  }
  const rows = results.filter((r) => r && typeof r === 'object' && !Array.isArray(r)) as Array<Record<string, unknown>>;
  if (results.length === 0) return { kind: 'notfound' };
  if (rows.length !== 1 || results.length !== 1) return { kind: 'error', message: 'the service principal read did not return exactly one object.' };
  const r = rows[0]!;
  if (typeof r['id'] !== 'string' || r['id'].toLowerCase() !== id.toLowerCase()) {
    return { kind: 'error', message: 'the service principal read returned a different object than the one requested.' };
  }
  if (typeof r['accountEnabled'] !== 'boolean') return { kind: 'error', message: 'the service principal read returned no accountEnabled value.' };
  return {
    kind: 'found',
    sp: {
      id: r['id'],
      appId: r['appId'],
      displayName: r['displayName'],
      accountEnabled: r['accountEnabled'],
      appOwnerOrganizationId: r['appOwnerOrganizationId'],
      servicePrincipalType: r['servicePrincipalType'],
    },
  };
}

/** Why this service principal may not be toggled here, or undefined. */
function protectedReason(sp: ServicePrincipal): string | undefined {
  const owner = sp.appOwnerOrganizationId;
  if (typeof owner !== 'string' || !GUID.test(owner)) {
    return 'its appOwnerOrganizationId is missing or not a GUID, so it cannot be checked against the protected tenants.';
  }
  if (MS_SET.has(owner.toLowerCase())) return 'it is a Microsoft first-party application.';
  if (ITSL_SET.has(owner.toLowerCase())) return "it is owned by IT Simply's own tenant (IT Simply tooling such as the gateway, data gateway, CIPP SAM or Practice Intelligence).";
  if (sp.servicePrincipalType !== 'Application') {
    return `its servicePrincipalType is '${String(sp.servicePrincipalType).slice(0, 40)}', not 'Application' (managed identities, legacy and social identity principals are refused).`;
  }
  return undefined;
}

/** CIPP's Results text from a write response, truncated. */
function cippResultsText(raw: unknown): string {
  const results = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>)['Results'] : raw;
  const s = typeof results === 'string' ? results : JSON.stringify(results ?? null);
  return truncateError(s);
}

export async function runAppToggle(name: string, args: Record<string, unknown>, deps: AppToggleDeps): Promise<AppToggleResult> {
  const desired = name === APP_ENABLE_TOOL_NAME;
  const verb = desired ? 'enabled' : 'disabled';
  const refuse = (reason: string, meta: Record<string, unknown> = {}) => {
    deps.logger.warn('CIPP tool call refused', { tool: name, reason: reason.slice(0, 120), ...meta, user: deps.ctx.user });
    return out(`Refused: ${reason}`, true);
  };

  // Tier: write only. tools/list hides these from read callers too; this is the call-time check.
  if (deps.ctx.tier !== 'write') {
    deps.logger.warn('CIPP tool call refused', { tool: name, targetTier: 'write', callerTier: deps.ctx.tier, user: deps.ctx.user });
    return out(refusalReason(name, 'write', deps.ctx.tier), true);
  }

  // Exactly two arguments, compared case-insensitively, no duplicates.
  const seen = new Map<string, unknown>();
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if ((lk !== 'tenantfilter' && lk !== 'serviceprincipalid') || seen.has(lk)) {
      return refuse(`unexpected or repeated argument '${k.slice(0, 40)}'; only tenantFilter and servicePrincipalId are accepted.`);
    }
    seen.set(lk, v);
  }
  const rawTenant = seen.get('tenantfilter');
  const rawId = seen.get('serviceprincipalid');
  if (typeof rawTenant !== 'string' || rawTenant.trim() === '') return refuse("provide tenantFilter: one tenant's default domain or tenant ID.");
  const tenant = rawTenant.trim();
  if (tenant.toLowerCase() === 'alltenants') return refuse('AllTenants is not allowed - change one tenant at a time.');
  if (!TENANT.test(tenant)) return refuse("tenantFilter must be one tenant's default domain or tenant ID.");
  if (typeof rawId !== 'string' || !GUID.test(rawId.trim())) {
    return refuse("servicePrincipalId must be the service principal's object id, a GUID such as 00000000-0000-0000-0000-000000000000.");
  }
  const requestedId = rawId.trim().toLowerCase();

  // Pre-read (read-only).
  const before = await readSp(tenant, requestedId, deps);
  if (before.kind === 'notfound') return refuse(`service principal ${requestedId} was not found in ${tenant}. Nothing was changed.`, { tenant });
  if (before.kind === 'error') {
    return out(truncateError(`Could not read service principal ${requestedId} in ${tenant}; nothing was changed. ${before.message}`), true);
  }
  const sp = before.sp;
  const why = protectedReason(sp);
  if (why) return refuse(`'${String(sp.displayName).slice(0, 100)}' (${sp.id}) cannot be ${verb} here: ${why} Nothing was changed.`, { tenant, id: sp.id });

  const report = { tenant, id: sp.id, appId: sp.appId, displayName: sp.displayName };
  if (sp.accountEnabled === desired) {
    return out({ ...report, before: sp.accountEnabled, after: sp.accountEnabled, result: `already ${verb}` });
  }

  // The write: the one fixed shape. Payload is an object, as CIPP's own UI sends it
  // (Invoke-ExecApplication runs `$Request.Body.Payload | ConvertTo-Json`; a string would be
  // sent to Graph as a JSON string literal, not as an object).
  const body = { tenantFilter: tenant, Id: sp.id, Type: 'servicePrincipals', Action: 'Update', Payload: { accountEnabled: desired } };
  deps.logger.info('CIPP enterprise app toggle', { tool: name, tenant, id: sp.id, accountEnabled: desired, user: deps.ctx.user });
  let writeFailed = false;
  let cippResults: string;
  try {
    cippResults = cippResultsText(await deps.service.callEndpoint('POST', 'ExecApplication', undefined, body));
  } catch (err) {
    writeFailed = true;
    cippResults = truncateError(errText(err));
  }

  // Re-read until Graph shows the requested state, a fixed number of times. Never writes again.
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let after: ReadOutcome = { kind: 'error', message: 'not read' };
  const attempts = writeFailed ? 1 : Math.max(1, appToggleTiming.attempts);
  for (let i = 0; i < attempts; i++) {
    if (i > 0 && appToggleTiming.delayMs > 0) await sleep(appToggleTiming.delayMs);
    after = await readSp(tenant, sp.id, deps);
    if (after.kind === 'found' && after.sp.accountEnabled === desired) break;
  }
  const afterState = after.kind === 'found' ? after.sp.accountEnabled : null;
  if (!writeFailed && afterState === desired) {
    return out({ ...report, before: sp.accountEnabled, after: afterState });
  }
  deps.logger.warn('CIPP enterprise app toggle did not take effect', { tool: name, tenant, id: sp.id, writeFailed, user: deps.ctx.user });
  return out(
    {
      ...report,
      before: sp.accountEnabled,
      after: afterState,
      error:
        afterState === null
          ? `The service principal could not be re-read after the write, so it is not confirmed ${verb}. ${truncateError(after.kind === 'error' ? after.message : 'not found')}`
          : afterState === desired
            ? `CIPP reported the write as failed, but Graph now shows accountEnabled ${String(afterState)}. Check the app before acting again.`
            : `The service principal is not ${verb}: accountEnabled is ${String(afterState)} after the write.`,
      cippResults,
    },
    true
  );
}
