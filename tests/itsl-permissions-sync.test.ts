// cipp_sync_sharepoint_permissions: the second read-tier exception to the write-tier ExecCIPPDBCache.
// One fixed cache (SharePointPermissions), one tenant, 60-minute cooldown per tenant.

// tenantFilter canonicalisation has its own suite (itsl-tenant.test.ts); here it is a passthrough.
jest.mock('../src/itsl/tenant.js', () => ({
  canonicaliseTenantArgs: async (args: Record<string, unknown>) => ({ ok: true, args }),
}));

import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { computeTier } from '../src/itsl/tier.js';
import { ToolContext } from '../src/itsl/meta-tools.js';
import { clearSharingSyncCooldowns } from '../src/itsl/sharing-sync.js';
import {
  clearPermissionsSyncCooldowns,
  PERMISSIONS_CACHE_NAMES,
  PERMISSIONS_SYNC_COOLDOWN_MS,
  PERMISSIONS_SYNC_ENDPOINT,
  runPermissionsSync,
} from '../src/itsl/permissions-sync.js';
import { jsonResponse } from './helpers.js';

const READ: ToolContext = { tier: 'read', user: 'r@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'w@example.com' };
type FetchMock = jest.Mock<Promise<Response>, [string, RequestInit?]>;
let fetchMock: FetchMock;
let svc: CippService;

beforeEach(() => {
  catalogueStore.reset();
  clearPermissionsSyncCooldowns();
  clearSharingSyncCooldowns();
  fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>(() => Promise.resolve(jsonResponse({ Results: 'started' })));
  global.fetch = fetchMock as unknown as typeof fetch;
  svc = new CippService({ cipp: { baseUrl: 'https://cipp.example', apiKey: 'tok' } }, new Logger('error'));
});
afterEach(() => jest.restoreAllMocks());

const handler = (ctx: ToolContext) => new CippToolHandler(svc, new Logger('error'), ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;
const cippCalls = () => fetchMock.mock.calls.filter(([u]) => u.startsWith('https://cipp.example/api/'));
const TOOL = 'cipp_sync_sharepoint_permissions';
const SHARING = 'cipp_sync_sharepoint_sharing';

describe('listing', () => {
  it('is listed for read and write callers alike', () => {
    for (const ctx of [READ, WRITE]) expect(handler(ctx).getToolDefinitions().map((t) => t.name)).toContain(TOOL);
  });

  it('ExecSharePointPermissionsSync is not a generic tool: never read tier', async () => {
    // POST, role Sharepoint.Reports.ReadWrite (CIPP 11.2.1 spec): not read, not on the write allow-list.
    expect(computeTier('ExecSharePointPermissionsSync', 'Sharepoint.Reports.ReadWrite', { hasGet: false })).not.toBe('read');
    expect(computeTier('ExecSharePointPermissionsSync', 'Sharepoint.Reports.ReadWrite')).not.toBe('read');
    for (const tool of ['cipp_exec_read', 'cipp_exec_write']) {
      const res = await handler(READ).handleToolCall(tool, {
        name: 'ExecSharePointPermissionsSync',
        arguments: { Name: 'SharePointPermissions', tenantFilter: 't.example' },
      });
      expect(res.isError).toBe(true);
    }
    expect(cippCalls().filter(([u]) => u.includes('ExecSharePointPermissionsSync'))).toEqual([]);
  });

  it('read callers still cannot reach ExecCIPPDBCache directly', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_write', {
      name: 'ExecCIPPDBCache',
      arguments: { Name: 'SharePointPermissions', tenantFilter: 't.example' },
    });
    expect(res.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });
});

describe('a read caller runs the sync', () => {
  it('posts the dedicated ExecSharePointPermissionsSync with Name SharePointPermissions and the tenant, once', async () => {
    const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' });
    expect(res.isError).toBeUndefined();
    const calls = cippCalls();
    expect(calls).toHaveLength(1);
    const [u, init] = calls[0]!;
    expect(u).toContain('/api/ExecSharePointPermissionsSync');
    expect(u).not.toContain('ExecCIPPDBCache');
    expect(PERMISSIONS_SYNC_ENDPOINT).toBe('ExecSharePointPermissionsSync');
    expect(init?.method).toBe('POST');
    expect(new URL(u).searchParams.get('Name')).toBe('SharePointPermissions');
    expect(new URL(u).searchParams.get('tenantFilter')).toBe('aviva.org.nz');
    expect([...PERMISSIONS_CACHE_NAMES]).toEqual(['SharePointPermissions']);
  });

  it('accepts tenantFilter in any key case', async () => {
    const res = await handler(READ).handleToolCall(TOOL, { TenantFilter: 'aviva.org.nz' });
    expect(res.isError).toBeUndefined();
    expect(new URL(cippCalls()[0]![0]).searchParams.get('tenantFilter')).toBe('aviva.org.nz');
  });

  it('names the consuming read endpoint in its description and result', async () => {
    const def = handler(READ).getToolDefinitions().find((t) => t.name === TOOL)!;
    expect(def.description).toMatch(/ListSharePointPermissions/);
    expect(def.description).toMatch(/background/);
    const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' });
    expect(text(res)).toMatch(/ListSharePointPermissions/);
  });
});

describe('refusals', () => {
  it('the caller cannot change the cache Name', async () => {
    for (const extra of [{ Name: 'Mailboxes' }, { name: 'Users' }, { Types: 'Users' }]) {
      const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz', ...extra });
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/only tenantFilter/);
    }
    expect(cippCalls()).toEqual([]);
  });

  it.each(['AllTenants', 'alltenants', ' ALLTENANTS '])('refuses %p', async (t) => {
    const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: t });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/AllTenants is not allowed/);
    expect(cippCalls()).toEqual([]);
  });

  it.each(['', '   '])('refuses an empty tenant %p', async (t) => {
    const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: t });
    expect(res.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });

  it('refuses a missing tenant', async () => {
    const res = await handler(READ).handleToolCall(TOOL, {});
    expect(res.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });
});

describe('cooldown', () => {
  it('is 60 minutes', () => {
    expect(PERMISSIONS_SYNC_COOLDOWN_MS).toBe(60 * 60 * 1000);
  });

  it('refuses a second run for the same tenant, whoever asks, and does not hold other tenants', async () => {
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' })).isError).toBeUndefined();
    const again = await handler(WRITE).handleToolCall(TOOL, { tenantFilter: 'AVIVA.org.nz' });
    expect(again.isError).toBe(true);
    expect(text(again)).toMatch(/less than 60 minutes ago/);
    expect(cippCalls()).toHaveLength(1);
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'other.example' })).isError).toBeUndefined();
    expect(cippCalls()).toHaveLength(2);
  });

  it('expires after the window (injected clock)', async () => {
    let now = 1_000_000;
    const deps = { service: svc, logger: new Logger('error'), ctx: READ, now: () => now };
    expect((await runPermissionsSync({ tenantFilter: 't.example' }, deps)).isError).toBeUndefined();
    now += PERMISSIONS_SYNC_COOLDOWN_MS - 1000;
    const held = await runPermissionsSync({ tenantFilter: 't.example' }, deps);
    expect(held.isError).toBe(true);
    expect(text(held)).toMatch(/about 1 minute/);
    now += 1000;
    expect((await runPermissionsSync({ tenantFilter: 't.example' }, deps)).isError).toBeUndefined();
  });

  it('releases the tenant when nothing started (the CIPP call failed)', async () => {
    fetchMock.mockImplementation(() => Promise.reject(new Error('CIPP unreachable')));
    const failed = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' });
    expect(failed.isError).toBe(true);
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({ Results: 'started' })));
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' })).isError).toBeUndefined();
  });

  it('is independent of the sharing sync, in both directions', async () => {
    expect((await handler(READ).handleToolCall(SHARING, { tenantFilter: 'aviva.org.nz' })).isError).toBeUndefined();
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' })).isError).toBeUndefined();
    // each is now held by its own cooldown only
    expect((await handler(READ).handleToolCall(SHARING, { tenantFilter: 'aviva.org.nz' })).isError).toBe(true);
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' })).isError).toBe(true);
    clearSharingSyncCooldowns();
    expect((await handler(READ).handleToolCall(SHARING, { tenantFilter: 'aviva.org.nz' })).isError).toBeUndefined();
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' })).isError).toBe(true);
  });
});
