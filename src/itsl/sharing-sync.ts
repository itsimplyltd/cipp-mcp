// IT Simply Ltd: read-tier SharePoint / OneDrive sharing sync (new file).
//
// ExecCIPPDBCache is a write-tier endpoint. This tool is the one narrow
// exception (Grant, 2026-10-12): any caller, read tier included, may refresh
// the three caches the Sharing report (ListSharePointSharing) is built from,
// for ONE tenant, at most once per tenant per cooldown. The mechanics (fixed
// cache names, one tenant, in-memory cooldown) live in cache-sync.ts.

import { createCacheSync, type CacheSyncDeps, type CacheSyncResult } from './cache-sync.js';

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

export type SharingSyncDeps = CacheSyncDeps;
export type SharingSyncResult = CacheSyncResult;

const sharingSync = createCacheSync({
  toolName: SHARING_SYNC_TOOL_NAME,
  cacheNames: SHARING_CACHE_NAMES,
  cooldownMs: SHARING_SYNC_COOLDOWN_MS,
  label: 'sharing sync',
  logMessage: 'CIPP sharing sync',
  reportName: 'ListSharePointSharing',
  next: 'The sync runs in the background in CIPP and usually takes several minutes. Re-read ListSharePointSharing and check linksSynced and lastDataRefresh. Wait before ListSiteBrowserPermissions.',
});

export const clearSharingSyncCooldowns = sharingSync.clearCooldowns;
export const runSharingSync = sharingSync.run;
