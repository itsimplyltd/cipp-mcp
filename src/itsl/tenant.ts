// IT Simply Ltd: central tenantFilter canonicalisation (new file).
//
// CIPP resolves a tenantFilter differently per endpoint. A tenant's non-default
// domain can make some endpoints return a clean but EMPTY dataset (HTTP 200) or a
// 500/403 instead of an error, which reads as "no data". Every tenantFilter of
// every tool call is therefore resolved here, against the CALLER's own ListTenants,
// to the tenant's defaultDomainName, or refused. An unknown value is never passed on.
//
// ListTenants fields matched (Invoke-ListTenants / Get-Tenants in CIPP-API):
// defaultDomainName, initialDomainName (the .onmicrosoft.com domain), customerId
// (tenant GUID) and `domains` when the payload carries it. Invoke-ListTenants calls
// Get-Tenants with -SkipDomains, so `domains` is normally absent and arbitrary
// verified domains are NOT resolvable; displayName is ambiguous and never matched.

import { createHash } from 'node:crypto';

export const TENANT_CACHE_TTL_MS = 10 * 60 * 1000;
/** An unknown value is remembered this long, so a typo cannot cause a ListTenants call per request. */
export const TENANT_NEGATIVE_TTL_MS = 30 * 1000;
const MAX_DEPTH = 8;

export interface TenantLister {
  listTenants<T = unknown>(): Promise<T>;
}
interface InfoLogger {
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
}

interface TenantIndex {
  /** lower-cased identifier -> canonical defaultDomainName */
  byKey: Map<string, string>;
  defaults: string[];
}
interface CacheEntry {
  at: number;
  index: TenantIndex;
  /** lower-cased unknown value -> time it was last found unknown */
  unknown: Map<string, number>;
}

const cache = new Map<string, CacheEntry>();

/** Test hook. */
export function clearTenantCache(): void {
  cache.clear();
}

const norm = (s: string): string => s.trim().toLowerCase();

function userKey(user: string): string {
  return createHash('sha256').update(norm(user)).digest('hex');
}

function buildIndex(payload: unknown): TenantIndex | undefined {
  let rows: unknown = payload;
  if (rows && typeof rows === 'object' && !Array.isArray(rows)) {
    const r = (rows as Record<string, unknown>)['Results'];
    rows = Array.isArray(r) ? r : [rows];
  }
  if (!Array.isArray(rows)) return undefined;
  const byKey = new Map<string, string>();
  const ambiguous = new Set<string>();
  const defaults: string[] = [];
  const add = (key: unknown, def: string) => {
    if (typeof key !== 'string' || key.trim() === '') return;
    const k = norm(key);
    const existing = byKey.get(k);
    if (existing !== undefined && existing !== def) ambiguous.add(k);
    else byKey.set(k, def);
  };
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const t = row as Record<string, unknown>;
    const def = t['defaultDomainName'];
    const cid = t['customerId'];
    if (typeof def !== 'string' || def.trim() === '' || /^(invalid|alltenants)$/i.test(def.trim())) continue;
    if (typeof cid !== 'string' || cid.trim() === '' || cid === 'AllTenants') continue;
    const canonical = def.trim();
    defaults.push(canonical);
    add(canonical, canonical);
    add(cid, canonical);
    add(t['initialDomainName'], canonical);
    const domains = t['domains'];
    if (typeof domains === 'string') add(domains, canonical);
    else if (Array.isArray(domains)) {
      for (const d of domains) {
        if (typeof d === 'string') add(d, canonical);
        else if (d && typeof d === 'object') {
          const o = d as Record<string, unknown>;
          add(o['id'] ?? o['name'], canonical);
        }
      }
    }
  }
  // A key claimed by two different tenants must not resolve at all.
  for (const k of ambiguous) byKey.delete(k);
  if (defaults.length === 0) return undefined;
  return { byKey, defaults };
}

/** Obvious near match on defaultDomainName: one name contains the other, or the leading labels do. */
function suggest(value: string, defaults: string[]): string | undefined {
  const v = norm(value);
  const vRoot = v.split('.')[0] ?? '';
  return defaults.find((d) => {
    const dl = norm(d);
    if (dl.includes(v) || v.includes(dl)) return true;
    const dRoot = dl.split('.')[0] ?? '';
    return dRoot.length >= 4 && vRoot.length >= 4 && (vRoot.includes(dRoot) || dRoot.includes(vRoot));
  });
}

export type CanonResult = { ok: true; args: Record<string, unknown> } | { ok: false; error: string };

/** Collects every tenantFilter value (any key casing, any depth) other than AllTenants. */
function collect(node: unknown, depth: number, out: Set<string>): void {
  if (depth > MAX_DEPTH || node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    node.forEach((n) => collect(n, depth + 1, out));
    return;
  }
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (k.toLowerCase() === 'tenantfilter' && typeof v === 'string') {
      const t = v.trim();
      if (t !== '' && t.toLowerCase() !== 'alltenants') out.add(t);
    } else collect(v, depth + 1, out);
  }
}

function rewrite(node: unknown, map: Map<string, string>, depth: number): unknown {
  if (depth > MAX_DEPTH || node === null || typeof node !== 'object') return node;
  if (Array.isArray(node)) return node.map((n) => rewrite(n, map, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (k.toLowerCase() === 'tenantfilter' && typeof v === 'string') out[k] = map.get(v.trim()) ?? v;
    else out[k] = rewrite(v, map, depth + 1);
  }
  return out;
}

/**
 * Resolve every tenantFilter in `args` to its canonical defaultDomainName, or refuse.
 * `service` MUST be the per-request service (the caller's own token).
 */
export async function canonicaliseTenantArgs(
  args: Record<string, unknown>,
  deps: { service: TenantLister; user?: string | undefined; logger: InfoLogger; now?: () => number }
): Promise<CanonResult> {
  const wanted = new Set<string>();
  collect(args, 0, wanted);
  if (wanted.size === 0) return { ok: true, args };

  const now = (deps.now ?? Date.now)();
  // Without a verified user there is no safe cache key: look up every time.
  const key = deps.user ? userKey(deps.user) : undefined;
  let entry = key ? cache.get(key) : undefined;
  if (entry && now - entry.at > TENANT_CACHE_TTL_MS) entry = undefined;

  const load = async (): Promise<CacheEntry | string> => {
    let payload: unknown;
    try {
      payload = await deps.service.listTenants();
    } catch (err) {
      deps.logger.warn('Tenant lookup failed; refusing call', { error: err instanceof Error ? err.message : String(err) });
      return 'Refused: could not verify the tenant (CIPP ListTenants failed). Try again shortly.';
    }
    const index = buildIndex(payload);
    if (!index) return 'Refused: could not verify the tenant (CIPP ListTenants returned no usable tenant list).';
    const fresh: CacheEntry = { at: now, index, unknown: new Map() };
    if (key) cache.set(key, fresh);
    return fresh;
  };

  let fetched = false;
  if (!entry) {
    const r = await load();
    if (typeof r === 'string') return { ok: false, error: r };
    entry = r;
    fetched = true;
  }

  const map = new Map<string, string>();
  for (const value of wanted) {
    const k = norm(value);
    let canonical = entry.index.byKey.get(k);
    if (canonical === undefined && !fetched) {
      // A tenant onboarded since the cache was built: refresh once, unless this
      // value was already found unknown moments ago (negative cache).
      const lastMiss = entry.unknown.get(k);
      if (lastMiss === undefined || now - lastMiss > TENANT_NEGATIVE_TTL_MS) {
        const r = await load();
        if (typeof r === 'string') return { ok: false, error: r };
        entry = r;
        fetched = true;
        canonical = entry.index.byKey.get(k);
      }
    }
    if (canonical === undefined) {
      entry.unknown.set(k, now);
      const near = suggest(value, entry.index.defaults);
      return {
        ok: false,
        error:
          `Refused: unknown tenant '${value.slice(0, 100)}'. Use the tenant's defaultDomainName from cipp_list_tenants` +
          (near ? ` (did you mean '${near}'?)` : '') +
          '.',
      };
    }
    map.set(value, canonical);
  }
  for (const [from, to] of map) {
    if (from !== to) deps.logger.info('tenantFilter canonicalised', { from, to, user: deps.user });
  }
  return { ok: true, args: rewrite(args, map, 0) as Record<string, unknown> };
}
