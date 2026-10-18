// IT Simply Ltd: factory for the read-tier "refresh one cache family" tools (new file).
//
// ExecCIPPDBCache is a write-tier endpoint. Each tool built here is a narrow
// exception to that: any caller, read tier included, may refresh a FIXED set of
// caches for ONE tenant, at most once per tenant per cooldown. The cache names
// are fixed when the tool is built and never taken from the caller, so no other
// cache type and none of the other sync triggers become reachable through it.
// CIPP still applies the caller's own CIPP role (ExecCIPPDBCache needs
// CIPP.Core.ReadWrite).
//
// The cooldown is in memory, per replica: with N replicas the worst case is N
// runs per tenant per window. Each tool has its own cooldown map, so a cooldown
// on one tool never blocks another.

import type { CatalogueLogger } from './catalogue.js';
import type { ToolContext } from './meta-tools.js';

export interface CacheSyncDeps {
  service: { callEndpoint(method: 'GET' | 'POST', path: string, params?: Record<string, unknown>): Promise<unknown> };
  logger: CatalogueLogger & { error(message: string, meta?: unknown): void };
  ctx: ToolContext;
  /** Injectable clock (tests). */
  now?: () => number;
}

export interface CacheSyncResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export interface CacheSyncSpec {
  toolName: string;
  /** Cache names posted to ExecCIPPDBCache, in order. Fixed in code. */
  cacheNames: readonly string[];
  cooldownMs: number;
  /** Short noun for messages, e.g. 'sharing sync'. */
  label: string;
  /** Log line for an accepted run, e.g. 'CIPP sharing sync'. */
  logMessage: string;
  /** The report to re-read afterwards, named in the cooldown refusal. */
  reportName: string;
  /** Result `next` text. */
  next: string;
}

const text = (value: string, isError = false): CacheSyncResult => ({
  content: [{ type: 'text', text: value }],
  ...(isError ? { isError: true } : {}),
});

export function createCacheSync(spec: CacheSyncSpec): {
  run(args: Record<string, unknown>, deps: CacheSyncDeps): Promise<CacheSyncResult>;
  clearCooldowns(): void;
} {
  /** lower-cased canonical tenant -> time the last accepted run started. */
  const lastRun = new Map<string, number>();
  const cooldownMinutes = Math.round(spec.cooldownMs / 60000);

  async function run(args: Record<string, unknown>, deps: CacheSyncDeps): Promise<CacheSyncResult> {
    const now = deps.now ?? Date.now;
    const extra = Object.keys(args).filter((k) => k.toLowerCase() !== 'tenantfilter');
    if (extra.length > 0) return text(`Refused: unexpected argument(s) ${extra.join(', ')}; only tenantFilter is accepted.`, true);
    const raw = Object.entries(args).find(([k]) => k.toLowerCase() === 'tenantfilter')?.[1];
    if (typeof raw !== 'string' || raw.trim() === '') return text("Provide tenantFilter: one tenant's default domain or tenant ID.", true);
    const tenant = raw.trim();
    if (tenant.toLowerCase() === 'alltenants') {
      deps.logger.warn('CIPP tool call refused', { tool: spec.toolName, reason: 'AllTenants', user: deps.ctx.user });
      return text('Refused: AllTenants is not allowed - sync one tenant at a time.', true);
    }

    const key = tenant.toLowerCase();
    const t = now();
    const prev = lastRun.get(key);
    if (prev !== undefined && t - prev < spec.cooldownMs) {
      const mins = Math.ceil((spec.cooldownMs - (t - prev)) / 60000);
      deps.logger.warn('CIPP tool call refused', { tool: spec.toolName, reason: 'cooldown', tenant, user: deps.ctx.user });
      return text(
        `Refused: a ${spec.label} for ${tenant} was started less than ${cooldownMinutes} minutes ago. Try again in about ${mins} minute(s); the earlier sync may still be running, so re-read ${spec.reportName} first.`,
        true
      );
    }
    // Claim the slot before calling CIPP so two concurrent calls cannot both start a run.
    lastRun.set(key, t);

    deps.logger.info(spec.logMessage, { tool: spec.toolName, tenant, callerTier: deps.ctx.tier, user: deps.ctx.user });
    const results: Array<{ cache: string; ok: boolean; result: unknown }> = [];
    for (const name of spec.cacheNames) {
      try {
        const r = await deps.service.callEndpoint('POST', 'ExecCIPPDBCache', { Name: name, tenantFilter: tenant });
        results.push({ cache: name, ok: true, result: r });
      } catch (err) {
        results.push({ cache: name, ok: false, result: err instanceof Error ? err.message : String(err) });
      }
    }
    const anyOk = results.some((r) => r.ok);
    if (!anyOk) lastRun.delete(key); // nothing started, so do not hold the tenant for the cooldown
    return text(JSON.stringify({ tenant, started: anyOk, caches: results, next: spec.next }, null, 2), !anyOk);
  }

  return { run, clearCooldowns: () => lastRun.clear() };
}
