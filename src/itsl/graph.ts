// IT Simply Ltd: the only route to Microsoft Graph (new file).
//
// cipp_graph_request builds the CIPP ListGraphRequest call ITSELF from a fixed
// parameter set and an allowlist of read collections (policy.ts). There is no
// passthrough of arbitrary keys, so nextLink, manualPagination, AsApp, queue
// overrides and case-variant spellings of Endpoint cannot reach CIPP.
//
// tenantFilter=AllTenants is accepted on purpose (N6): CIPP scopes the tenants a
// user can reach by their CIPP role, so this costs load, not extra data.

import { GRAPH_ALLOWED_PREFIXES, GRAPH_CONTENT_SEGMENTS, GRAPH_DENY_TERMS } from './policy.js';

export type GraphResult =
  | { ok: true; params: Record<string, unknown> }
  | { ok: false; reason: string };

const ALLOWED_KEYS = new Set(['tenantfilter', 'endpoint', '$select', '$filter', '$top', '$expand', 'version', '$format']);
const MAX_VALUE_LENGTH = 1000;

/** Segments after which a final `microsoft.graph.<type>` OData cast is accepted. */
const CAST_PARENTS = new Set([
  'memberof',
  'transitivememberof',
  'members',
  'transitivemembers',
  'owners',
  'ownedobjects',
  'registeredowners',
  'registeredusers',
]);
const CAST_TYPES = /^microsoft\.graph\.(group|user|device|serviceprincipal|application|orgcontact|directoryrole)$/i;
/** Exactly one usage-report function directly under reports/, with an exact period. */
const REPORT_FUNCTION = /^reports\/(get[a-z0-9]+)\(period='(d7|d30|d90|d180)'\)$/i;
/** ASCII only: no homoglyphs, no encoded forms. */
const PATH_CHARS = /^[A-Za-z0-9._:,@$'/-]+$/;

function denied(text: string): boolean {
  const lower = text.toLowerCase();
  return GRAPH_DENY_TERMS.some((t) => lower.includes(t));
}

function words(text: string): string[] {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function containsContentWord(text: string): boolean {
  return words(text).some((w) => GRAPH_CONTENT_SEGMENTS.includes(w));
}

/** Normalise and validate a Graph path. Returns the path (version prefix stripped) or a reason. */
export function normaliseGraphPath(raw: unknown): { path: string; version: 'v1.0' | 'beta' } | { error: string } {
  if (typeof raw !== 'string') return { error: 'endpoint must be a string.' };
  let p = raw.trim();
  if (p === '' || p.length > 500) return { error: 'endpoint is empty or too long.' };
  p = p.replace(/^\/+/, '');
  let version: 'v1.0' | 'beta' = 'v1.0';
  const vm = /^(v1\.0|beta)(\/|$)/i.exec(p);
  if (vm) {
    version = vm[1]!.toLowerCase() === 'beta' ? 'beta' : 'v1.0';
    p = p.slice(vm[0].length);
  }
  p = p.replace(/\/+$/, '');
  if (p === '' || p.includes('//')) return { error: 'endpoint is empty or malformed.' };

  // The one permitted use of parentheses: a usage-report function with an exact period.
  const rf = REPORT_FUNCTION.exec(p);
  if (rf) {
    return { path: `reports/${rf[1]}(period='${rf[2]!.toUpperCase()}')`, version };
  }

  if (!PATH_CHARS.test(p)) {
    return { error: "endpoint contains a forbidden character (only ASCII letters, digits and ._:,@$'/- are allowed)." };
  }
  if (p.includes('..') || p.toLowerCase().includes('$batch')) return { error: 'endpoint contains a forbidden sequence.' };

  const segments = p.split('/').map((s) => s.toLowerCase());
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    if (seg === '.') return { error: 'endpoint contains a "." segment.' };
    if (seg.startsWith('microsoft.graph.')) {
      const last = i === segments.length - 1;
      if (last && i > 0 && CAST_PARENTS.has(segments[i - 1]!) && CAST_TYPES.test(seg)) continue;
      return { error: 'endpoint looks like a Graph function, action or unsupported cast, which is not allowed.' };
    }
    if (/^get[a-z]/.test(seg)) return { error: 'endpoint looks like a Graph function or action, which is not allowed.' };
    if (seg === 'authentication') return { error: 'authentication methods are not readable here.' };
    if (GRAPH_CONTENT_SEGMENTS.includes(seg)) {
      return { error: 'customer content (mail, calendar, files, chats, notes, contacts, photos, list items) is not readable here.' };
    }
  }
  const lower = segments.join('/');
  if (denied(lower)) return { error: 'endpoint touches a protected resource.' };
  const allowed = GRAPH_ALLOWED_PREFIXES.some((pre) => lower === pre || lower.startsWith(pre + '/'));
  if (!allowed) {
    return { error: `endpoint is not in the allowed Graph collections (${GRAPH_ALLOWED_PREFIXES.join(', ')}).` };
  }
  return { path: lower, version };
}

/** Validate cipp_graph_request arguments and build the exact ListGraphRequest query. */
export function buildGraphRequest(args: Record<string, unknown>): GraphResult {
  const byKey = new Map<string, unknown>();
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (byKey.has(lk)) return { ok: false, reason: `duplicate argument '${k}' (keys are compared case-insensitively).` };
    if (!ALLOWED_KEYS.has(lk)) return { ok: false, reason: `argument '${k}' is not allowed.` };
    byKey.set(lk, v);
  }
  const tenant = byKey.get('tenantfilter');
  if (typeof tenant !== 'string' || !/^[A-Za-z0-9._-]{1,255}$/.test(tenant)) {
    return { ok: false, reason: 'tenantFilter must be a tenant domain, tenant ID or AllTenants.' };
  }
  const norm = normaliseGraphPath(byKey.get('endpoint'));
  if ('error' in norm) return { ok: false, reason: norm.error };

  let version = norm.version;
  if (byKey.has('version')) {
    const v = byKey.get('version');
    if (v !== 'v1.0' && v !== 'beta') return { ok: false, reason: "version must be 'v1.0' or 'beta'." };
    version = v;
  }

  // Always explicit: CIPP defaults to beta when Version is absent (N5).
  const params: Record<string, unknown> = { tenantFilter: tenant, Endpoint: norm.path, Version: version };
  for (const key of ['$select', '$filter', '$expand']) {
    if (!byKey.has(key)) continue;
    const v = byKey.get(key);
    // eslint-disable-next-line no-control-regex
    if (typeof v !== 'string' || v.length > MAX_VALUE_LENGTH || /[\u0000-\u001f]/.test(v)) {
      return { ok: false, reason: `${key} must be a short string.` };
    }
    // Whole-word matches only for `authentication` ('authenticationMethods' is a different word).
    const touchesAuth = words(v).includes('authentication');
    const touchesContent = key !== '$filter' && containsContentWord(v);
    if (denied(v) || touchesContent || touchesAuth || v.includes('%')) {
      return { ok: false, reason: `${key} touches a protected resource.` };
    }
    params[key] = v;
  }
  if (byKey.has('$format')) {
    if (byKey.get('$format') !== 'application/json') return { ok: false, reason: "$format must be exactly 'application/json'." };
    params['$format'] = 'application/json';
  }
  if (byKey.has('$top')) {
    const t = byKey.get('$top');
    if (typeof t !== 'number' || !Number.isInteger(t) || t < 1 || t > 999) {
      return { ok: false, reason: '$top must be an integer from 1 to 999.' };
    }
    params['$top'] = t;
  }
  return { ok: true, params };
}
