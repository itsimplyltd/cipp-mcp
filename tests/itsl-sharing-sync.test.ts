// cipp_sync_sharepoint_sharing: the read-tier exception to the write-tier ExecCIPPDBCache.
// Fixed cache names, one tenant, 15-minute cooldown per tenant.

// tenantFilter canonicalisation has its own suite (itsl-tenant.test.ts); here it is a passthrough.
jest.mock('../src/itsl/tenant.js', () => ({
  canonicaliseTenantArgs: async (args: Record<string, unknown>) => ({ ok: true, args }),
}));

import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { ToolContext } from '../src/itsl/meta-tools.js';
import {
  clearSharingSyncCooldowns,
  runSharingSync,
  SHARING_CACHE_NAMES,
  SHARING_SYNC_COOLDOWN_MS,
} from '../src/itsl/sharing-sync.js';
import { jsonResponse } from './helpers.js';

const READ: ToolContext = { tier: 'read', user: 'r@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'w@example.com' };
type FetchMock = jest.Mock<Promise<Response>, [string, RequestInit?]>;
let fetchMock: FetchMock;
let svc: CippService;

beforeEach(() => {
  catalogueStore.reset();
  clearSharingSyncCooldowns();
  fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>(() => Promise.resolve(jsonResponse({ Results: 'started' })));
  global.fetch = fetchMock as unknown as typeof fetch;
  svc = new CippService({ cipp: { baseUrl: 'https://cipp.example', apiKey: 'tok' } }, new Logger('error'));
});
afterEach(() => jest.restoreAllMocks());

const handler = (ctx: ToolContext) => new CippToolHandler(svc, new Logger('error'), ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;
const cippCalls = () => fetchMock.mock.calls.map(([u]) => u).filter((u) => u.startsWith('https://cipp.example/api/'));
const TOOL = 'cipp_sync_sharepoint_sharing';

describe('listing', () => {
  it('is listed for read and write callers alike', () => {
    for (const ctx of [READ, WRITE]) expect(handler(ctx).getToolDefinitions().map((t) => t.name)).toContain(TOOL);
  });

  it('read callers still cannot reach ExecCIPPDBCache directly', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'Mailboxes', tenantFilter: 't.example' } });
    expect(res.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });
});

describe('a read caller runs the sync', () => {
  it('starts exactly the three sharing caches for the one tenant, as POST with query parameters', async () => {
    const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' });
    expect(res.isError).toBeUndefined();
    const calls = fetchMock.mock.calls.filter(([u]) => u.includes('/api/ExecCIPPDBCache'));
    expect(calls).toHaveLength(3);
    expect(calls.map(([u]) => new URL(u).searchParams.get('Name'))).toEqual([...SHARING_CACHE_NAMES]);
    for (const [u, init] of calls) {
      expect(init?.method).toBe('POST');
      expect(new URL(u).searchParams.get('tenantFilter')).toBe('aviva.org.nz');
    }
    expect(cippCalls()).toHaveLength(3);
  });

  it('is framed as untrusted tenant data', async () => {
    const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' });
    expect(text(res).split('\n')[0]).toMatch(/^\[CIPP data for tenant aviva\.org\.nz /);
  });
});

describe('refusals', () => {
  it.each(['AllTenants', 'alltenants', ' ALLTENANTS '])('refuses %p', async (t) => {
    const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: t });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/AllTenants is not allowed/);
    expect(cippCalls()).toEqual([]);
  });

  it('refuses a missing tenant', async () => {
    const res = await handler(READ).handleToolCall(TOOL, {});
    expect(res.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });

  it('refuses any extra argument, so a caller cannot choose a different cache', async () => {
    for (const extra of [{ Name: 'Mailboxes' }, { Types: 'Users' }, { name: 'ExecSyncDEP' }]) {
      const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz', ...extra });
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/only tenantFilter/);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('shares the central value checks', async () => {
    const res = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'a/../b' });
    expect(res.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });
});

describe('cooldown', () => {
  it('refuses a second run for the same tenant within 15 minutes, whoever asks, and allows it after', async () => {
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' })).isError).toBeUndefined();
    const again = await handler(WRITE).handleToolCall(TOOL, { tenantFilter: 'AVIVA.org.nz' });
    expect(again.isError).toBe(true);
    expect(text(again)).toMatch(/less than 15 minutes ago/);
    expect(cippCalls()).toHaveLength(3);

    // Other tenants are not held.
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'other.example' })).isError).toBeUndefined();
    expect(cippCalls()).toHaveLength(6);
  });

  it('expires after the window (injected clock)', async () => {
    let now = 1_000_000;
    const deps = { service: svc, logger: new Logger('error'), ctx: READ, now: () => now };
    expect((await runSharingSync({ tenantFilter: 't.example' }, deps)).isError).toBeUndefined();
    now += SHARING_SYNC_COOLDOWN_MS - 1000;
    const held = await runSharingSync({ tenantFilter: 't.example' }, deps);
    expect(held.isError).toBe(true);
    expect(text(held)).toMatch(/about 1 minute/);
    now += 1000;
    expect((await runSharingSync({ tenantFilter: 't.example' }, deps)).isError).toBeUndefined();
  });

  it('releases the tenant when nothing started (every CIPP call failed)', async () => {
    fetchMock.mockImplementation(() => Promise.reject(new Error('CIPP unreachable')));
    const failed = await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' });
    expect(failed.isError).toBe(true);
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({ Results: 'started' })));
    expect((await handler(READ).handleToolCall(TOOL, { tenantFilter: 'aviva.org.nz' })).isError).toBeUndefined();
  });
});
