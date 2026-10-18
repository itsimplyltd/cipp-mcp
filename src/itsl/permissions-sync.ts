// IT Simply Ltd: read-tier SharePoint permissions sync (new file).
//
// Same narrow exception to the write-tier ExecCIPPDBCache as sharing-sync.ts
// (Grant, 2026-10-19): any caller, read tier included, may refresh the one
// SharePointPermissions cache that ListSharePointPermissions (CIPP role
// Sharepoint.Site.Read, a read-tier GET) is built from, for ONE tenant. The
// cache name is fixed here. policy.ts still refuses SharePointPermissions in the
// ListDBCache allow-list (a read of customer content): this only triggers the
// refresh. The mechanics live in cache-sync.ts.

import { createCacheSync } from './cache-sync.js';

/** The one cache Get-CIPPSharePointPermissionsReport reads. */
export const PERMISSIONS_CACHE_NAMES = ['SharePointPermissions'] as const;

// 60 minutes, not the 15 of the sharing sync: this scan walks the permissions of
// every site and library in the tenant, which is heavier than the three sharing
// caches, so a repeat run is held back longer.
export const PERMISSIONS_SYNC_COOLDOWN_MS = 60 * 60 * 1000;

export const PERMISSIONS_SYNC_TOOL_NAME = 'cipp_sync_sharepoint_permissions';

export const PERMISSIONS_SYNC_TOOL_DEFINITION = {
  name: PERMISSIONS_SYNC_TOOL_NAME,
  description:
    "Refresh CIPP's SharePoint permissions scan for ONE tenant (the SharePointPermissions cache behind ListSharePointPermissions: site and library permission assignments, broad claims, external grants, unique-permission libraries). Use it when ListSharePointPermissions has no data or an old scan. Available at the read tier. One tenant per call (AllTenants is refused) and at most once per tenant every 60 minutes, because the scan walks every site. The sync runs in the background in CIPP and can take a long time on large tenants; re-read ListSharePointPermissions afterwards, and wait before heavy per-site reads such as ListSiteBrowserPermissions, which throttle while a sync is running. CIPP still applies your own CIPP role.",
  inputSchema: {
    type: 'object',
    properties: {
      tenantFilter: { type: 'string', description: "The tenant's default domain or tenant ID. AllTenants is not allowed." },
    },
    required: ['tenantFilter'],
  },
  annotations: {
    title: 'Sync SharePoint permissions scan',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

const permissionsSync = createCacheSync({
  toolName: PERMISSIONS_SYNC_TOOL_NAME,
  cacheNames: PERMISSIONS_CACHE_NAMES,
  cooldownMs: PERMISSIONS_SYNC_COOLDOWN_MS,
  label: 'permissions sync',
  logMessage: 'CIPP permissions sync',
  reportName: 'ListSharePointPermissions',
  next: 'The sync runs in the background in CIPP and can take a long time on large tenants. Re-read ListSharePointPermissions and check the scan summary. Wait before ListSiteBrowserPermissions.',
});

export const clearPermissionsSyncCooldowns = permissionsSync.clearCooldowns;
export const runPermissionsSync = permissionsSync.run;
