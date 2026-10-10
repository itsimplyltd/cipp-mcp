// IT Simply Ltd: the only route to Microsoft Graph (new file).
//
// cipp_graph_request builds the CIPP ListGraphRequest call ITSELF from a fixed
// parameter set and an allowlist of read collections (policy.ts). There is no
// passthrough of arbitrary keys, so nextLink, manualPagination, AsApp, queue
// overrides and case-variant spellings of Endpoint cannot reach CIPP.

import { GRAPH_ALLOWED_PREFIXES, GRAPH_CONTENT_SEGMENTS, GRAPH_DENY_TERMS } from './policy.js';

export type GraphResult =
  | { ok: true; params: Record<string, unknown> }
  | { ok: false; reason: string };

const ALLOWED_KEYS = new Set(['tenantfilter', 'endpoint', '$select', '$filter', '$top', '$expand', 'version']);
const MAX_VALUE_LENGTH = 1000;

function denied(text: string): boolean {
  const lower = text.toLowerCase();
  return GRAPH_DENY_TERMS.some((t) => lower.includes(t));
}

function containsContentWord(text: string): boolean {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .some((w) => GRAPH_CONTENT_SEGMENTS.includes(w));
}

/** Normalise and validate a Graph path. Returns the lower-case path (version prefix stripped) or a reason. */
export function normaliseGraphPath(raw: unknown): { path: string; version: 'v1.0' | 'beta' } | { error: string } {
  if (typeof raw !== 'string') return { error: 'endpoint must be a string.' };
  let p = raw.trim();
  if (p === '' || p.length > 500) return { error: 'endpoint is empty or too long.' };
  if (/[%?#()\\\s]/.test(p) || p.includes('..') || p.toLowerCase().includes('$batch')) {
    return { error: 'endpoint contains a forbidden character or sequence.' };
  }
  p = p.replace(/^\/+/, '');
  let version: 'v1.0' | 'beta' = 'v1.0';
  const vm = /^(v1\.0|beta)(\/|$)/i.exec(p);
  if (vm) {
    version = vm[1]!.toLowerCase() === 'beta' ? 'beta' : 'v1.0';
    p = p.slice(vm[0].length);
  }
  p = p.replace(/\/+$/, '');
  if (p === '' || p.includes('//')) return { error: 'endpoint is empty or malformed.' };
  const segments = p.split('/');
  for (const seg of segments) {
    // Function and action shapes: microsoft.graph.xyz, getFooBar, anything with parentheses (rejected above).
    if (/^microsoft\.graph\./i.test(seg) || /^get[A-Z]/.test(seg)) {
      return { error: 'endpoint looks like a Graph function or action, which is not allowed.' };
    }
    if (seg.toLowerCase() === 'authentication') return { error: 'authentication methods are not readable here.' };
    if (GRAPH_CONTENT_SEGMENTS.includes(seg.toLowerCase())) {
      return { error: 'customer content (mail, calendar, files, chats, notes, contacts, photos, list items) is not readable here.' };
    }
  }
  const lower = p.toLowerCase();
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

  const params: Record<string, unknown> = { tenantFilter: tenant, Endpoint: norm.path };
  if (version === 'beta') params['Version'] = 'beta';
  for (const key of ['$select', '$filter', '$expand']) {
    if (!byKey.has(key)) continue;
    const v = byKey.get(key);
    // eslint-disable-next-line no-control-regex
    if (typeof v !== 'string' || v.length > MAX_VALUE_LENGTH || /[\u0000-\u001f]/.test(v)) {
      return { ok: false, reason: `${key} must be a short string.` };
    }
    const touchesContent = key !== '$filter' && containsContentWord(v);
    if (denied(v) || touchesContent || /authentication/i.test(v) || v.includes('%')) {
      return { ok: false, reason: `${key} touches a protected resource.` };
    }
    params[key] = v;
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
