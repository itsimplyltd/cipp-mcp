// IT Simply Ltd: the catalogue meta-tools and the tier gate (new file).
//
// cipp_search_tools / cipp_get_tool_info / cipp_exec_read / cipp_exec_write / cipp_graph_request
// mirror the public CIPP MCP's meta-tool pattern. Every path that reaches CIPP
// from here checks the target's tier against the caller's SIGNED tier first.

import {
  Catalogue,
  CatalogueEntry,
  CatalogueLogger,
  CatalogueStore,
  catalogueStore,
  defaultSpecFetchers,
  canonicaliseArguments,
  findEntry,
  routeArguments,
  searchEntries,
  SpecApi,
  SpecFetcher,
} from './catalogue.js';
import { buildGraphRequest } from './graph.js';
import { endpointTier, KNOWN_ENDPOINT_ROLES, NAMED_TOOL_ENDPOINTS, namedToolTier, RoleLookup } from './named-tools.js';
import { CallerTier, computeTier, isCallable, refusalReason, Tier } from './tier.js';

export interface ToolContext {
  /** From a verified S2S v2 header only; `read` when nothing was verified. */
  tier: CallerTier;
  /** UPN from a verified S2S v2 header, for logging. */
  user?: string | undefined;
}

export const DEFAULT_CONTEXT: ToolContext = { tier: 'read' };

export const META_TOOL_NAMES = [
  'cipp_search_tools',
  'cipp_get_tool_info',
  'cipp_exec_read',
  'cipp_exec_write',
  'cipp_graph_request',
] as const;

export interface MetaToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

export const META_TOOL_DEFINITIONS: MetaToolDefinition[] = [
  {
    name: 'cipp_search_tools',
    description:
      "Search or browse the catalogue of CIPP API endpoints that you are allowed to call. Returns name, category, method, tier and a one-line summary; use cipp_get_tool_info for the input schema and cipp_exec_read to run one. Endpoints your tier cannot call are never listed. Call with no query to browse; use 'category' to narrow (e.g. 'Identity', 'Email-Exchange', 'Endpoint', 'Tenant', 'Security', 'Teams-Sharepoint', 'CIPP').",
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Keywords; every word must match the name, summary, description or category.' },
        category: { type: 'string', description: "Category prefix, e.g. 'Identity' or 'Email-Exchange'." },
        limit: { type: 'number', description: 'Maximum results (default 25, max 100).' },
        offset: { type: 'number', description: 'Skip this many results (paging).' },
      },
    },
    annotations: { title: 'Search CIPP endpoint catalogue', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cipp_get_tool_info',
    description:
      'Get the description and input schema of one or more CIPP endpoints from the catalogue. Refuses endpoints you cannot call.',
    inputSchema: {
      type: 'object',
      properties: {
        names: {
          type: 'array',
          items: { type: 'string' },
          description: 'Endpoint names exactly as returned by cipp_search_tools (max 10).',
        },
      },
      required: ['names'],
    },
    annotations: { title: 'Get CIPP endpoint schema', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cipp_exec_read',
    description:
      "Run a read-only CIPP catalogue endpoint by name (entries cipp_search_tools marks run_with cipp_exec_read). Arguments go in 'arguments' and become query parameters of a GET. Runs only read-tier endpoints; write, disabled and blocked entries are refused. CIPP still applies your own CIPP role.",
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Endpoint name from cipp_search_tools.' },
        arguments: { type: 'object', description: 'Arguments matching the schema from cipp_get_tool_info.' },
      },
      required: ['name'],
    },
    annotations: { title: 'Run a read-only CIPP endpoint', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cipp_exec_write',
    description:
      "Run a write-tier CIPP catalogue endpoint by name (entries marked run_with cipp_exec_write; at launch only cache and sync triggers). Needs the CIPP.Write gateway role. Refuses read entries (use cipp_exec_read), and disabled or blocked entries. Arguments go in 'arguments': declared query parameters plus a JSON body. CIPP still applies your own CIPP role.",
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Endpoint name from cipp_search_tools.' },
        arguments: { type: 'object', description: 'Arguments matching the schema from cipp_get_tool_info.' },
      },
      required: ['name'],
    },
    annotations: { title: 'Run a write-tier CIPP endpoint', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: 'cipp_graph_request',
    description:
      "Run a read-only Microsoft Graph GET against a tenant through CIPP (ListGraphRequest). Provide the tenant and a Graph path under an allowed collection (users, groups, devices, servicePrincipals, applications, domains, organization, subscribedSkus, directoryRoles, roleManagement/directory, identity/conditionalAccess, policies, auditLogs, reports, security/alerts_v2, security/incidents, deviceManagement/managedDevices|deviceCompliancePolicies|deviceConfigurations, teams, sites), plus optional select, filter, top, expand (the OData options, written without the $). Functions, actions, secrets and authentication methods are refused.",
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: { type: 'string', description: "Tenant domain or ID, or 'AllTenants'." },
        endpoint: { type: 'string', description: "Graph path, e.g. 'users' or 'security/alerts_v2'." },
        select: { type: 'string', description: 'OData $select.' },
        filter: { type: 'string', description: 'OData $filter.' },
        top: { type: 'number', description: 'OData $top, 1 to 999.' },
        expand: { type: 'string', description: 'OData $expand.' },
        format: { type: 'string', description: "OData $format; only 'application/json'." },
        Version: { type: 'string', description: "'v1.0' (default) or 'beta'." },
      },
      required: ['tenantFilter', 'endpoint'],
    },
    annotations: { title: 'Read from Microsoft Graph via CIPP', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
];

export function isMetaTool(name: string): boolean {
  return (META_TOOL_NAMES as readonly string[]).includes(name);
}

/** Role lookup against the loaded catalogue (never triggers a fetch). */
export function liveRoleLookup(store: CatalogueStore = catalogueStore): RoleLookup | undefined {
  const cat = store.peek();
  if (!cat) return undefined;
  return (endpoint) => {
    const e = findEntry(cat, endpoint);
    return e ? { found: true, role: e.role, hasGet: e.hasGet } : { found: false, role: undefined, hasGet: false };
  };
}

/** Whether a named tool is callable by this caller (the single rule used by tools/list AND dispatch). */
export function namedToolDecision(
  toolName: string,
  ctx: ToolContext,
  store: CatalogueStore = catalogueStore
): { tier: Tier; allowed: boolean; reason: string } | undefined {
  const tier = namedToolTier(toolName, liveRoleLookup(store));
  if (!tier) return undefined;
  const allowed = isCallable(tier, ctx.tier);
  return { tier, allowed, reason: allowed ? '' : refusalReason(toolName, tier, ctx.tier) };
}

export interface MetaDeps {
  service: SpecApi;
  logger: CatalogueLogger & { error(message: string, meta?: unknown): void };
  ctx: ToolContext;
  store?: CatalogueStore;
  /** Override the spec sources (tests). */
  fetchers?: SpecFetcher[];
}

export interface MetaResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

const text = (value: unknown, isError = false): MetaResult => ({
  content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }],
  ...(isError ? { isError: true } : {}),
});

async function loadCatalogue(deps: MetaDeps): Promise<Catalogue> {
  const store = deps.store ?? catalogueStore;
  return store.get(deps.fetchers ?? defaultSpecFetchers(deps.service), deps.logger);
}

/** Refusal logging: tool, target, tier, user. Never arguments, never tokens. */
function logRefusal(deps: MetaDeps, tool: string, target: string, tier: Tier | 'unknown'): void {
  deps.logger.warn('CIPP tool call refused', { tool, target, targetTier: tier, callerTier: deps.ctx.tier, user: deps.ctx.user });
}

export async function runMetaTool(name: string, args: Record<string, unknown>, deps: MetaDeps): Promise<MetaResult> {
  switch (name) {
    case 'cipp_search_tools': {
      let cat: Catalogue;
      try {
        cat = await loadCatalogue(deps);
      } catch (err) {
        return text(err instanceof Error ? err.message : String(err), true);
      }
      const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
      const opts = {
        ...(typeof args['query'] === 'string' ? { query: args['query'] } : {}),
        ...(typeof args['category'] === 'string' ? { category: args['category'] } : {}),
        ...(num(args['limit']) !== undefined ? { limit: num(args['limit']) } : {}),
        ...(num(args['offset']) !== undefined ? { offset: num(args['offset']) } : {}),
      };
      return text(searchEntries(cat, opts, (e) => isCallable(e.tier, deps.ctx.tier)));
    }

    case 'cipp_get_tool_info': {
      const raw = args['names'] ?? args['name'];
      const names = (Array.isArray(raw) ? raw : [raw]).filter((n): n is string => typeof n === 'string').slice(0, 10);
      if (names.length === 0) return text("Provide 'names': an array of endpoint names.", true);
      let cat: Catalogue;
      try {
        cat = await loadCatalogue(deps);
      } catch (err) {
        return text(err instanceof Error ? err.message : String(err), true);
      }
      const out = names.map((n) => {
        const blockedByName = computeTier(n, undefined) === 'blocked';
        const e = findEntry(cat, n);
        const tier: Tier | undefined = blockedByName ? 'blocked' : e?.tier;
        if (!tier || !e) return { name: n, error: `'${n}' is not an endpoint in this server's CIPP catalogue.` };
        if (!isCallable(tier, deps.ctx.tier)) {
          logRefusal(deps, 'cipp_get_tool_info', e.name, tier);
          return { name: n, error: refusalReason(e.name, tier, deps.ctx.tier) };
        }
        return describe(e);
      });
      return text(out);
    }

    case 'cipp_exec_read':
    case 'cipp_exec_write': {
      const want: Tier = name === 'cipp_exec_write' ? 'write' : 'read';
      if (want === 'write' && deps.ctx.tier !== 'write') {
        logRefusal(deps, name, 'cipp_exec_write', 'write');
        return text('Refused: cipp_exec_write is a write-tier tool and your gateway tier is read. Ask IT Simply to grant the CIPP.Write role.', true);
      }
      const target = args['name'];
      if (typeof target !== 'string' || target.trim() === '') return text("Provide 'name': the endpoint to run.", true);
      const callArgs = args['arguments'];
      if (callArgs !== undefined && (typeof callArgs !== 'object' || callArgs === null || Array.isArray(callArgs))) {
        return text("'arguments' must be an object.", true);
      }
      // Blocked-by-name needs no catalogue: refuse before any network work.
      if (computeTier(target, undefined) === 'blocked') {
        logRefusal(deps, name, target, 'blocked');
        return text(refusalReason(target, 'blocked', deps.ctx.tier), true);
      }
      let cat: Catalogue;
      try {
        cat = await loadCatalogue(deps);
      } catch (err) {
        return text(err instanceof Error ? err.message : String(err), true);
      }
      const entry = findEntry(cat, target);
      if (!entry) {
        logRefusal(deps, name, target, 'unknown');
        return text(`'${target}' is not an endpoint in this server's CIPP catalogue. Use cipp_search_tools to find endpoint names.`, true);
      }
      // Recompute from role and name rather than trusting a stored field.
      const tier = computeTier(entry.name, entry.role, { hasGet: entry.hasGet });
      if (!isCallable(tier, deps.ctx.tier)) {
        logRefusal(deps, name, entry.name, tier);
        return text(refusalReason(entry.name, tier, deps.ctx.tier), true);
      }
      if (tier !== want) {
        logRefusal(deps, name, entry.name, tier);
        return text(`Refused: '${entry.name}' is a ${tier}-tier endpoint; run it with ${runWith(tier)}, not ${name}.`, true);
      }
      const canon = canonicaliseArguments(entry, (callArgs ?? {}) as Record<string, unknown>);
      if (!canon.ok) return text(`Refused: ${canon.reason}`, true);
      const finalArgs = canon.args;
      if (want === 'write' && hasAllTenants(finalArgs)) {
        logRefusal(deps, name, entry.name, tier);
        return text('Refused: AllTenants is not allowed on write-tier calls - run it per tenant.', true);
      }
      const { params, body } = routeArguments(entry, finalArgs);
      deps.logger.info('CIPP exec', { target: entry.name, tier, callerTier: deps.ctx.tier, user: deps.ctx.user });
      const result = await deps.service.callEndpoint(entry.method, entry.name, params, body);
      return text(result);
    }

    case 'cipp_graph_request': {
      const effective = endpointTier('ListGraphRequest#servicePrincipals', liveRoleLookup(deps.store ?? catalogueStore));
      if (!isCallable(effective, deps.ctx.tier)) {
        logRefusal(deps, name, 'cipp_graph_request', effective);
        return text(refusalReason('cipp_graph_request', effective, deps.ctx.tier), true);
      }
      const built = buildGraphRequest(args);
      if (!built.ok) {
        logRefusal(deps, name, 'graph request', 'blocked');
        return text(`Refused: ${built.reason}`, true);
      }
      deps.logger.info('CIPP graph read', { path: built.params['Endpoint'], tier: deps.ctx.tier, user: deps.ctx.user });
      return text(await deps.service.callEndpoint('GET', 'ListGraphRequest', built.params));
    }

    default:
      return text(`Unknown meta tool: ${name}`, true);
  }
}

/** True if any tenantFilter (any key casing, at any depth) is "AllTenants" (trimmed, case-insensitive). */
function hasAllTenants(node: unknown, depth = 0): boolean {
  if (depth > 8 || node === null || typeof node !== 'object') return false;
  if (Array.isArray(node)) return node.some((n) => hasAllTenants(n, depth + 1));
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (k.toLowerCase() === 'tenantfilter' && typeof v === 'string' && v.trim().toLowerCase() === 'alltenants') return true;
    if (hasAllTenants(v, depth + 1)) return true;
  }
  return false;
}

/** Which exec tool runs an entry of this tier. */
export function runWith(tier: Tier): string {
  return tier === 'write' ? 'cipp_exec_write' : 'cipp_exec_read';
}

function describe(e: CatalogueEntry) {
  return {
    run_with: runWith(e.tier),
    name: e.name,
    category: e.category,
    method: e.method,
    tier: e.tier,
    summary: e.summary,
    description: e.description,
    inputSchema: e.inputSchema,
  };
}

/** Endpoints every named tool calls must have a row in the role table; used by tests and a boot check. */
export function namedToolEndpointsMissingRoles(): string[] {
  const missing: string[] = [];
  for (const eps of Object.values(NAMED_TOOL_ENDPOINTS)) {
    for (const ep of eps) if (!(ep in KNOWN_ENDPOINT_ROLES)) missing.push(ep);
  }
  return [...new Set(missing)];
}
