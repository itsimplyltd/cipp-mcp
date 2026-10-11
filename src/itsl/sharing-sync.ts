// IT Simply Ltd: read-tier SharePoint / OneDrive sharing sync (new file).
//
// ExecCIPPDBCache is a write-tier endpoint. This tool is the one narrow
// exception (Grant, 2026-10-12): any caller, read tier included, may refresh
// the three caches the Sharing report (ListSharePointSharing) is built from,
// for ONE tenant, at most once per tenant per cooldown. The cache names are
// fixed here and never taken from the caller, so no other cache type and none
// of the other sync triggers become reachable through it. CIPP still applies
// the caller's own CIPP role (ExecCIPPDBCache needs CIPP.Core.ReadWrite).
//
// The cooldown is in memory, per replica: with N replicas the worst case is N
// runs per tenant per window.

import type { CatalogueLogger } from './catalogue.js';
import type { ToolContext } from './meta-tools.js';

/** The caches Get-CIPPSharePointSharingReport reads, in the order the CIPP UI syncs them. */
export const SHARING_CACHE_NAMES = ['SharePointSharingLinks', 'SharePointSiteUsage', 'OneDriveUsage'] as const;

export const SHARING_SYNC_COOLDOWN_MS = 15 * 60 * 1000;

export const SHARING_SYNC_TOOL_NAME = 'cipp_sync_sharepoint_sharing';

export const SHARING_SYNC_TOOL_DEFINITION = {
  name: SHARING_SYNC_TOOL_NAME,
  description:
    "Refresh CIPP's SharePoint and OneDrive sharing data for ONE tenant (the caches behind ListSharePointSharing: sharing links, site usage, OneDrive usage). Use it when ListSharePointSharing reports linksSynced false or an old lastDataRefresh. Available at the read tier. One tenant per call (AllTenants is refused) and at most once per tenant every 15 minutes. The sync runs in the background in CIPP and takes several minutes; re-read ListSharePointSharing afterwards, and wait before heavy per-site reads such as ListSiteBrowserPermissions, which throttle while a sync is running. CIPP still applies your own CIPP role.",
  inputSchema: {
    type: 'object',
    properties: {
      tenantFilter: { type: 'string', description: "The tenant's default domain or tenant ID. AllTenants is not allowed." },
    },
    required: ['tenantFilter'],
  },
  annotations: {
    title: 'Sync SharePoint and OneDrive sharing data',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

export interface SharingSyncDeps {
  service: { callEndpoint(method: 'GET' | 'POST', path: string, params?: Record<string, unknown>): Promise<unknown> };
  logger: CatalogueLogger & { error(message: string, meta?: unknown): void };
  ctx: ToolContext;
  /** Injectable clock (tests). */
  now?: () => number;
}

export interface SharingSyncResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

/** lower-cased canonical tenant -> time the last accepted run started. */
const lastRun = new Map<string, number>();

export function clearSharingSyncCooldowns(): void {
  lastRun.clear();
}

const text = (value: string, isError = false): SharingSyncResult => ({
  content: [{ type: 'text', text: value }],
  ...(isError ? { isError: true } : {}),
});

export async function runSharingSync(args: Record<string, unknown>, deps: SharingSyncDeps): Promise<SharingSyncResult> {
  const now = deps.now ?? Date.now;
  const extra = Object.keys(args).filter((k) => k.toLowerCase() !== 'tenantfilter');
  if (extra.length > 0) return text(`Refused: unexpected argument(s) ${extra.join(', ')}; only tenantFilter is accepted.`, true);
  const raw = Object.entries(args).find(([k]) => k.toLowerCase() === 'tenantfilter')?.[1];
  if (typeof raw !== 'string' || raw.trim() === '') return text('Provide tenantFilter: one tenant\'s default domain or tenant ID.', true);
  const tenant = raw.trim();
  if (tenant.toLowerCase() === 'alltenants') {
    deps.logger.warn('CIPP tool call refused', { tool: SHARING_SYNC_TOOL_NAME, reason: 'AllTenants', user: deps.ctx.user });
    return text('Refused: AllTenants is not allowed - sync one tenant at a time.', true);
  }

  const key = tenant.toLowerCase();
  const t = now();
  const prev = lastRun.get(key);
  if (prev !== undefined && t - prev < SHARING_SYNC_COOLDOWN_MS) {
    const mins = Math.ceil((SHARING_SYNC_COOLDOWN_MS - (t - prev)) / 60000);
    deps.logger.warn('CIPP tool call refused', { tool: SHARING_SYNC_TOOL_NAME, reason: 'cooldown', tenant, user: deps.ctx.user });
    return text(
      `Refused: a sharing sync for ${tenant} was started less than 15 minutes ago. Try again in about ${mins} minute(s); the earlier sync may still be running, so re-read ListSharePointSharing first.`,
      true
    );
  }
  // Claim the slot before calling CIPP so two concurrent calls cannot both start a run.
  lastRun.set(key, t);

  deps.logger.info('CIPP sharing sync', { tenant, callerTier: deps.ctx.tier, user: deps.ctx.user });
  const results: Array<{ cache: string; ok: boolean; result: unknown }> = [];
  for (const name of SHARING_CACHE_NAMES) {
    try {
      const r = await deps.service.callEndpoint('POST', 'ExecCIPPDBCache', { Name: name, tenantFilter: tenant });
      results.push({ cache: name, ok: true, result: r });
    } catch (err) {
      results.push({ cache: name, ok: false, result: err instanceof Error ? err.message : String(err) });
    }
  }
  const anyOk = results.some((r) => r.ok);
  if (!anyOk) lastRun.delete(key); // nothing started, so do not hold the tenant for 15 minutes
  return text(
    JSON.stringify(
      {
        tenant,
        started: anyOk,
        caches: results,
        next:
          'The sync runs in the background in CIPP and usually takes several minutes. Re-read ListSharePointSharing and check linksSynced and lastDataRefresh. Wait before ListSiteBrowserPermissions.',
      },
      null,
      2
    ),
    !anyOk
  );
}
