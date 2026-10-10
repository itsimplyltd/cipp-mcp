// IT Simply Ltd: tiered catalogue of CIPP API endpoints (new file).
//
// Projects CIPP's OpenAPI document into one entry per path (GET and POST
// merged), computes each entry's tier, and serves search / info / exec lookups.
// The shape follows CIPP's own public-MCP projection as BEHAVIOUR only; no code
// from CIPP-API (AGPL-3.0) is copied, and no copy of the spec is stored in
// this repository.

import { computeTier, Tier } from './tier.js';

export interface CatalogueEntry {
  name: string;
  category: string;
  summary: string;
  description: string;
  /** Method used to call the endpoint: POST when the path has both. */
  method: 'GET' | 'POST';
  role: string | undefined;
  /** The path has a GET operation (read tier requires it; read entries are always invoked as GET). */
  hasGet: boolean;
  tier: Tier;
  inputSchema: Record<string, unknown>;
  /** Names of query-string parameters (for POST, the rest of the arguments go in the body). */
  queryParams: readonly string[];
  /** The request body is a JSON array; it is exposed as a single `body` argument. */
  bodyIsArray: boolean;
}

export interface Catalogue {
  entries: Map<string, CatalogueEntry>; // key: lower-cased name
  builtAt: number;
  source: string;
}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

const MAX_DEREF_DEPTH = 4;

/** Resolve `#/...` references inside the spec; unresolvable or too-deep ones become `{}`. */
function deref(spec: Json, node: unknown, depth = 0): unknown {
  if (Array.isArray(node)) return node.map((n) => deref(spec, n, depth));
  if (!isObj(node)) return node;
  const ref = node['$ref'];
  if (typeof ref === 'string') {
    if (depth >= MAX_DEREF_DEPTH || !ref.startsWith('#/')) return {};
    let target: unknown = spec;
    for (const part of ref.slice(2).split('/')) {
      target = isObj(target) ? target[part.replace(/~1/g, '/').replace(/~0/g, '~')] : undefined;
    }
    return target === undefined ? {} : deref(spec, target, depth + 1);
  }
  const out: Json = {};
  for (const [k, v] of Object.entries(node)) {
    out[k] = deref(spec, v, depth);
  }
  return out;
}

/** Defensive unwrap: the raw OpenAPI document, a `{Results: doc}` wrapper, or a JSON string of either. */
export function unwrapSpec(raw: unknown): Json {
  let v: unknown = raw;
  for (let i = 0; i < 3; i++) {
    if (typeof v === 'string') {
      try {
        v = JSON.parse(v);
      } catch {
        break;
      }
    }
    if (isObj(v) && isObj(v['paths'])) return v;
    if (isObj(v) && v['Results'] !== undefined) {
      v = v['Results'];
      continue;
    }
    if (isObj(v) && v['spec'] !== undefined) {
      v = v['spec'];
      continue;
    }
    if (Array.isArray(v) && v.length === 1) {
      v = v[0];
      continue;
    }
    break;
  }
  throw new Error('Spec payload is not an OpenAPI document (no "paths" object).');
}

/** Project an OpenAPI document into the tiered catalogue. */
export function projectSpec(rawSpec: unknown, source = 'unknown', now = Date.now()): Catalogue {
  const spec = unwrapSpec(rawSpec);
  const paths = spec['paths'] as Json;
  const entries = new Map<string, CatalogueEntry>();

  for (const [pathKey, pathItem] of Object.entries(paths)) {
    if (!isObj(pathItem)) continue;
    const name = pathKey.replace(/^\/?api\//, '').replace(/^\//, '');
    if (!/^[A-Za-z0-9_]+$/.test(name)) continue; // never let an odd path segment reach a URL

    const get = isObj(pathItem['get']) ? pathItem['get'] : undefined;
    const post = isObj(pathItem['post']) ? pathItem['post'] : undefined;
    const op = post ?? get; // a GET/POST pair is one entry; the POST carries the body
    if (!op) continue;

    // The role is the most restrictive across the methods present: if either
    // operation is not `.Read`, the whole path is not read.
    const roles = [get, post].map((o) =>
      o && typeof o['x-cipp-role'] === 'string' ? (o['x-cipp-role'] as string) : undefined
    );
    const present = [get, post].filter((o) => o !== undefined).length;
    const known = roles.filter((r): r is string => r !== undefined);
    const nonRead = known.find((r) => !/\.Read$/i.test(r));
    const role = nonRead ?? (known.length === present ? known[0] : undefined);

    const properties: Json = {};
    const required: string[] = [];
    const queryParams: string[] = [];
    const seenParams = new Set<string>();
    for (const o of [post, get]) {
      if (!o || !Array.isArray(o['parameters'])) continue;
      for (const p0 of o['parameters']) {
        const p = deref(spec, p0);
        if (!isObj(p) || typeof p['name'] !== 'string') continue;
        const pname = p['name'];
        if (seenParams.has(pname)) continue;
        seenParams.add(pname);
        if (p['in'] === 'query') queryParams.push(pname);
        const schema: Json = isObj(p['schema']) ? { ...p['schema'] } : {};
        if (typeof p['description'] === 'string' && schema['description'] === undefined) {
          schema['description'] = p['description'];
        }
        properties[pname] = schema;
        if (p['required'] === true) required.push(pname);
      }
    }

    let bodyIsArray = false;
    const reqBody = isObj(op['requestBody']) ? op['requestBody'] : undefined;
    const content = reqBody && isObj(reqBody['content']) ? reqBody['content'] : undefined;
    const json = content && isObj(content['application/json']) ? content['application/json'] : undefined;
    const bodySchema = json ? deref(spec, json['schema']) : undefined;
    if (isObj(bodySchema)) {
      if (bodySchema['type'] === 'array') {
        bodyIsArray = true;
        properties['body'] = bodySchema;
      } else if (isObj(bodySchema['properties'])) {
        for (const [k, v] of Object.entries(bodySchema['properties'])) {
          if (properties[k] === undefined) properties[k] = v;
        }
        if (Array.isArray(bodySchema['required'])) {
          for (const r of bodySchema['required']) if (typeof r === 'string') required.push(r);
        }
      }
    }

    const tier = computeTier(name, role, { hasGet: get !== undefined });
    // A read entry is only ever invoked as GET; everything else keeps the POST/GET it has.
    const method: 'GET' | 'POST' = tier === 'read' || !post ? 'GET' : 'POST';
    const tags = Array.isArray(op['tags']) ? op['tags'] : [];
    entries.set(name.toLowerCase(), {
      name,
      category: typeof tags[0] === 'string' ? tags[0] : 'Uncategorised',
      summary: typeof op['summary'] === 'string' ? op['summary'] : name,
      description: typeof op['description'] === 'string' ? op['description'] : '',
      method,
      role,
      hasGet: get !== undefined,
      tier,
      inputSchema: {
        type: 'object',
        properties,
        ...(required.length > 0 ? { required: [...new Set(required)] } : {}),
      },
      queryParams,
      bodyIsArray,
    });
  }
  return { entries, builtAt: now, source };
}

// ---------------------------------------------------------------------------
// Lookup and search
// ---------------------------------------------------------------------------

export function findEntry(cat: Catalogue, name: string): CatalogueEntry | undefined {
  return cat.entries.get(name.toLowerCase());
}

export interface SearchOptions {
  query?: string;
  category?: string;
  limit?: number;
  offset?: number;
}

/** Search or browse entries. `visible` filters to what the caller may run, so refused tiers are never listed. */
export function searchEntries(
  cat: Catalogue,
  opts: SearchOptions,
  visible: (e: CatalogueEntry) => boolean
) {
  const terms = (opts.query ?? '').toLowerCase().split(/\s+/).filter(Boolean);
  const category = opts.category?.toLowerCase();
  const scored: Array<{ e: CatalogueEntry; score: number }> = [];
  for (const e of cat.entries.values()) {
    if (!visible(e)) continue;
    if (category && !e.category.toLowerCase().startsWith(category)) continue;
    let score = 1;
    if (terms.length > 0) {
      const name = e.name.toLowerCase();
      const hay = `${e.summary} ${e.description} ${e.category}`.toLowerCase();
      score = 0;
      for (const t of terms) {
        if (name === t) score += 20;
        else if (name.includes(t)) score += 10;
        else if (hay.includes(t)) score += 2;
        else {
          score = 0; // every term must match somewhere
          break;
        }
      }
    }
    if (score > 0) scored.push({ e, score });
  }
  scored.sort((a, b) => b.score - a.score || a.e.name.localeCompare(b.e.name));
  const limit = Math.min(Math.max(opts.limit ?? 25, 1), 100);
  const offset = Math.max(opts.offset ?? 0, 0);
  return {
    total: scored.length,
    offset,
    results: scored.slice(offset, offset + limit).map(({ e }) => ({
      name: e.name,
      category: e.category,
      method: e.method,
      tier: e.tier,
      summary: e.summary,
    })),
  };
}

// ---------------------------------------------------------------------------
// Fetching, caching, refresh
// ---------------------------------------------------------------------------

/** A source of the OpenAPI document. Fetchers are pluggable so tests (and the fallback) need no network. */
export interface SpecFetcher {
  name: string;
  fetch(): Promise<unknown>;
}

export interface CatalogueLogger {
  info(message: string, meta?: unknown): void;
  warn(message: string, meta?: unknown): void;
  debug(message: string, meta?: unknown): void;
}

export const CATALOGUE_TTL_MS = 6 * 60 * 60 * 1000;
const FAILURE_BACKOFF_MS = 5 * 60 * 1000;

/**
 * Holds the last good catalogue. Lazy: built on the first request, refreshed
 * when older than the TTL. A failed refresh keeps serving the last good copy;
 * with none, `get` throws a clear error (named tools do not need it).
 */
export class CatalogueStore {
  private current: Catalogue | undefined;
  private inFlight: Promise<Catalogue> | undefined;
  private lastFailureAt = 0;
  private seen = new Set<string>();

  constructor(
    private readonly ttlMs = CATALOGUE_TTL_MS,
    private readonly clock: () => number = Date.now
  ) {}

  /** The loaded catalogue, if any, without triggering a fetch. */
  peek(): Catalogue | undefined {
    return this.current;
  }

  /** Drop all state (tests). */
  reset(): void {
    this.current = undefined;
    this.inFlight = undefined;
    this.lastFailureAt = 0;
    this.seen = new Set();
  }

  async get(fetchers: readonly SpecFetcher[], logger: CatalogueLogger): Promise<Catalogue> {
    const now = this.clock();
    if (this.current && now - this.current.builtAt < this.ttlMs) return this.current;
    // Within the back-off after a failure, keep serving the stale copy rather than hammering CIPP.
    if (this.current && this.lastFailureAt > 0 && now - this.lastFailureAt < FAILURE_BACKOFF_MS) {
      return this.current;
    }
    if (!this.inFlight) {
      this.inFlight = this.refresh(fetchers, logger).finally(() => {
        this.inFlight = undefined;
      });
    }
    try {
      return await this.inFlight;
    } catch (err) {
      this.lastFailureAt = this.clock();
      if (this.current) {
        logger.warn('CIPP spec refresh failed; serving the last good catalogue', { error: errMsg(err) });
        return this.current;
      }
      throw err;
    }
  }

  private async refresh(fetchers: readonly SpecFetcher[], logger: CatalogueLogger): Promise<Catalogue> {
    const failures: string[] = [];
    for (const f of fetchers) {
      try {
        const cat = projectSpec(await f.fetch(), f.name, this.clock());
        if (cat.entries.size === 0) throw new Error('spec contained no usable paths');
        const prev = this.current;
        this.current = cat;
        this.logNew(cat, logger);
        this.logTierDrift(prev, cat, logger);
        return cat;
      } catch (err) {
        failures.push(`${f.name}: ${errMsg(err)}`);
        logger.debug('CIPP spec source failed', { source: f.name, error: errMsg(err) });
      }
    }
    throw new Error(
      `The CIPP endpoint catalogue is unavailable (every spec source failed: ${failures.join('; ')}). Named cipp_* tools still work.`
    );
  }

  /** Rule 8: any endpoint whose computed tier differs from the previous load is logged once. */
  private logTierDrift(prev: Catalogue | undefined, cat: Catalogue, logger: CatalogueLogger): void {
    if (!prev) return;
    for (const [key, e] of cat.entries) {
      const before = prev.entries.get(key);
      if (before && before.tier !== e.tier) {
        logger.warn('CIPP endpoint tier changed', { name: e.name, from: before.tier, to: e.tier, role: e.role });
      }
    }
  }

  /** Decision 5: each endpoint new to this process is logged once, with its tier. */
  private logNew(cat: Catalogue, logger: CatalogueLogger): void {
    const first = this.seen.size === 0;
    const fresh = [...cat.entries.values()].filter((e) => !this.seen.has(e.name.toLowerCase()));
    for (const e of fresh) this.seen.add(e.name.toLowerCase());
    const counts: Record<string, number> = {};
    for (const e of cat.entries.values()) counts[e.tier] = (counts[e.tier] ?? 0) + 1;
    logger.info('CIPP catalogue loaded', { source: cat.source, endpoints: cat.entries.size, tiers: counts });
    if (first) return; // the summary above covers the initial load
    for (const e of fresh) {
      logger.info('New CIPP endpoint', { name: e.name, role: e.role, tier: e.tier });
    }
  }
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Process-wide store; the per-request handlers share it so the 6-hour cache survives stateless requests. */
export const catalogueStore = new CatalogueStore();

// ---------------------------------------------------------------------------
// Default fetchers
// ---------------------------------------------------------------------------

/** The slice of CippService the fetchers need. */
export interface SpecApi {
  callEndpoint<T = unknown>(
    method: 'GET' | 'POST',
    path: string,
    params?: Record<string, unknown>,
    body?: Record<string, unknown> | unknown[],
    timeoutMs?: number
  ): Promise<T>;
}

const SPEC_TIMEOUT_MS = 60_000;

async function fetchJson(url: string, fetchImpl: typeof fetch): Promise<unknown> {
  const res = await fetchImpl(url, {
    signal: AbortSignal.timeout(SPEC_TIMEOUT_MS),
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  return JSON.parse(await res.text());
}

/**
 * Sources, in order:
 *  1. our own CIPP's `GET /api/ListOpenApiSpec` with the caller's token (path overridable with ITSL_SPEC_PATH).
 *  2. the `openapi.enriched.json` asset on the CIPP-API GitHub release that matches `GET /api/GetVersion`.
 *  3. `Config/openapi.json` of that release tag, fetched at runtime (never stored in this repo).
 * (2) and (3) exist because (1) could not be confirmed to exist in CIPP's public code; see the build report.
 */
export function defaultSpecFetchers(api: SpecApi, fetchImpl: typeof fetch = fetch): SpecFetcher[] {
  const specPath = process.env.ITSL_SPEC_PATH || 'ListOpenApiSpec';
  const repo = process.env.ITSL_SPEC_GITHUB_REPO || 'KelvinTegelaar/CIPP-API';
  let tagPromise: Promise<string> | undefined;
  const releaseTag = (): Promise<string> => {
    tagPromise ??= api.callEndpoint<unknown>('GET', 'GetVersion').then((v) => {
      const raw = isObj(v) ? (v['version'] ?? v['Version'] ?? v['LocalCIPPAPIVersion'] ?? v['localVersion']) : v;
      const m = /\d+\.\d+\.\d+/.exec(String(raw ?? ''));
      if (!m) throw new Error('GetVersion did not return a version number');
      return m[0];
    });
    return tagPromise;
  };
  return [
    { name: 'cipp-api', fetch: () => api.callEndpoint('GET', specPath, undefined, undefined, SPEC_TIMEOUT_MS) },
    {
      name: 'github-release-asset',
      fetch: async () =>
        fetchJson(`https://github.com/${repo}/releases/download/${await releaseTag()}/openapi.enriched.json`, fetchImpl),
    },
    {
      name: 'github-tag-file',
      fetch: async () =>
        fetchJson(`https://raw.githubusercontent.com/${repo}/${await releaseTag()}/Config/openapi.json`, fetchImpl),
    },
  ];
}

// ---------------------------------------------------------------------------
// Exec argument routing
// ---------------------------------------------------------------------------

/** Query parameters that make a GET change state or widen privilege; never forwarded on a read GET. */
const STRIPPED_ON_READ = new Set(['clearcache', 'triggerrefresh', 'asapp', 'queuenameoverride']);

/**
 * Canonicalise argument keys to the declared spelling and reject duplicates that
 * differ only by case (CIPP reads query keys case-insensitively, first wins).
 */
export function canonicaliseArguments(
  entry: CatalogueEntry,
  args: Record<string, unknown>
): { ok: true; args: Record<string, unknown> } | { ok: false; reason: string } {
  const declared = new Map<string, string>();
  for (const k of Object.keys((entry.inputSchema['properties'] as Json) ?? {})) declared.set(k.toLowerCase(), k);
  const seen = new Set<string>();
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (seen.has(lk)) return { ok: false, reason: `duplicate argument '${k}' (keys are compared case-insensitively).` };
    seen.add(lk);
    out[declared.get(lk) ?? k] = v;
  }
  return { ok: true, args: out };
}

/** Split `exec` arguments into query and body for the entry's method. */
export function routeArguments(
  entry: CatalogueEntry,
  args: Record<string, unknown>
): { params: Record<string, unknown>; body: Record<string, unknown> | unknown[] | undefined } {
  const asQuery = (v: unknown): unknown => (v !== null && typeof v === 'object' ? JSON.stringify(v) : v);
  const params: Record<string, unknown> = {};
  if (entry.method === 'GET') {
    const strip = entry.tier === 'read';
    for (const [k, v] of Object.entries(args)) {
      if (strip && STRIPPED_ON_READ.has(k.toLowerCase())) continue;
      params[k] = asQuery(v);
    }
    return { params, body: undefined };
  }
  if (entry.bodyIsArray && Array.isArray(args['body'])) {
    for (const [k, v] of Object.entries(args)) if (entry.queryParams.includes(k)) params[k] = asQuery(v);
    return { params, body: args['body'] as unknown[] };
  }
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (entry.queryParams.includes(k)) params[k] = asQuery(v);
    else body[k] = v;
  }
  return { params, body };
}
