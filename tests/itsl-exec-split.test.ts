// cipp_exec_tool is split into cipp_exec_read (read-tier only) and cipp_exec_write
// (write-tier only, listed only for write callers). Both share one implementation.

// tenantFilter canonicalisation has its own suite (itsl-tenant.test.ts); here it is a passthrough so these suites' CIPP call counts stay exact.
jest.mock('../src/itsl/tenant.js', () => ({
  canonicaliseTenantArgs: async (args: Record<string, unknown>) => ({ ok: true, args }),
}));

import fixture from './fixtures/openapi-fixture.json';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { META_TOOL_DEFINITIONS, ToolContext } from '../src/itsl/meta-tools.js';
import { jsonResponse } from './helpers.js';

const READ: ToolContext = { tier: 'read', user: 'r@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'w@example.com' };
type FetchMock = jest.Mock<Promise<Response>, [string, RequestInit?]>;
let fetchMock: FetchMock;
let svc: CippService;

beforeEach(() => {
  catalogueStore.reset();
  fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>((url) =>
    Promise.resolve(jsonResponse(url.includes('/api/ListOpenApiSpec') ? fixture : { ok: true }))
  );
  global.fetch = fetchMock as unknown as typeof fetch;
  svc = new CippService({ cipp: { baseUrl: 'https://cipp.example', apiKey: 'tok' } }, new Logger('error'));
});
afterEach(() => jest.restoreAllMocks());

const handler = (ctx: ToolContext) => new CippToolHandler(svc, new Logger('error'), ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;
const body = (r: { content: Array<{ text: string }> }) => text(r).split('\n').slice(1).join('\n');
const cippCalls = () =>
  fetchMock.mock.calls.map(([u]) => u).filter((u) => u.startsWith('https://cipp.example/api/') && !u.includes('/api/ListOpenApiSpec'));
const names = (ctx: ToolContext) => handler(ctx).getToolDefinitions().map((t) => t.name);

describe('listing and annotations', () => {
  it('cipp_exec_tool no longer exists, for anyone, in any form', async () => {
    expect(names(READ)).not.toContain('cipp_exec_tool');
    expect(names(WRITE)).not.toContain('cipp_exec_tool');
    expect(META_TOOL_DEFINITIONS.some((t) => t.name === 'cipp_exec_tool')).toBe(false);
    await expect(handler(WRITE).handleToolCall('cipp_exec_tool', { name: 'ListThings' })).rejects.toThrow(/Unknown tool/);
  });

  it('a read caller never sees cipp_exec_write; a write caller sees both', () => {
    expect(names(READ)).toContain('cipp_exec_read');
    expect(names(READ)).not.toContain('cipp_exec_write');
    expect(names(WRITE)).toContain('cipp_exec_read');
    expect(names(WRITE)).toContain('cipp_exec_write');
  });

  it('annotations are as specified', () => {
    const by = (n: string) => META_TOOL_DEFINITIONS.find((t) => t.name === n)!;
    expect(by('cipp_exec_read').annotations).toMatchObject({ readOnlyHint: true, openWorldHint: true, destructiveHint: false, idempotentHint: true });
    expect(by('cipp_exec_write').annotations).toMatchObject({ readOnlyHint: false, openWorldHint: true, destructiveHint: false, idempotentHint: false });
    expect(by('cipp_exec_read').description).toMatch(/read-only/i);
  });
});

describe('cipp_exec_read', () => {
  it('runs read entries as GET', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 't.example' } });
    expect(res.isError).toBeUndefined();
    expect(fetchMock.mock.calls.find(([u]) => u.includes('/api/ListThings'))![1]?.method).toBe('GET');
  });

  it.each(['ExecCIPPDBCache', 'ExecSyncDEP', 'ExecExtensionSync', 'ExecTestRun'])('refuses write entry %s at both tiers (write caller is pointed at cipp_exec_write)', async (name) => {
    const args = { name, arguments: { Name: 'x', tenantFilter: 't' } };
    const asWrite = await handler(WRITE).handleToolCall('cipp_exec_read', args);
    expect(asWrite.isError).toBe(true);
    expect(text(asWrite)).toMatch(/cipp_exec_write/);
    expect((await handler(READ).handleToolCall('cipp_exec_read', args)).isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });

  it.each(['ExecDisableUser', 'ExecBaselineRun', 'ListNoRole', 'ListMixed', 'ListPostOnlyRead', 'ExecBECCheck', 'ExecGetRecoveryKey', 'ListGraphRequest', 'ExecListBackup', 'ListApiTest'])('refuses disabled/blocked entry %s at any tier, via both exec tools', async (name) => {
    for (const ctx of [READ, WRITE]) {
      for (const tool of ['cipp_exec_read', 'cipp_exec_write']) {
        const res = await handler(ctx).handleToolCall(tool, { name });
        expect(res.isError).toBe(true);
        expect(text(res)).toMatch(/blocked|disabled|write-tier|CIPP\.Write/);
      }
    }
    expect(cippCalls()).toEqual([]);
  });

  it('the earlier reviewer bypass payloads are still refused via cipp_exec_read', async () => {
    const payloads = [
      { name: 'ListGraphRequest', arguments: { tenantFilter: 'x', ENDPOINT: 'directory/deviceLocalCredentials/abc' } },
      { name: 'ListGraphRequest', arguments: { Endpoint: 'users', manualPagination: true, nextLink: 'https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys/x' } },
      { name: 'ListUsers', arguments: { tenantFilter: 'x', UserID: '../directory/deviceLocalCredentials/abc?$select=credentials#' } },
      { name: 'ListDeviceDetails', arguments: { tenantFilter: 'x', DeviceID: '../../informationProtection/bitlocker/recoveryKeys/abc?$select=key' } },
      { name: 'ListGraphReports', arguments: { tenantFilter: 'x', report: '../informationProtection/bitlocker/recoveryKeys#' } },
      { name: 'ListThings', arguments: { tenantFilter: 'a', TENANTFILTER: 'b' } },
      { name: 'ListThings', arguments: { siteUrl: 'https://evil.example/x' } },
    ];
    for (const p of payloads) {
      for (const ctx of [READ, WRITE]) expect((await handler(ctx).handleToolCall('cipp_exec_read', p)).isError).toBe(true);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('strips ClearCache and runs ListTenants as GET', async () => {
    await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListTenants', arguments: { ClearCache: true, AllTenantSelector: true } });
    const [url, init] = fetchMock.mock.calls.find(([u]) => u.includes('/api/ListTenants'))!;
    expect(init?.method).toBe('GET');
    expect(url.toLowerCase()).not.toContain('clearcache');
  });
});

describe('cipp_exec_write', () => {
  it('a read caller is refused outright, even for a write entry, and CIPP never sees it', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'x', tenantFilter: 't' } });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/CIPP\.Write/);
    expect(cippCalls()).toEqual([]);
  });

  it('a write caller runs write entries: POST, query params in the URL', async () => {
    const res = await handler(WRITE).handleToolCall('cipp_exec_write', {
      name: 'ExecCIPPDBCache',
      arguments: { Name: 'SharePointSharingLinks', tenantFilter: 'aviva.org.nz' },
    });
    expect(res.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls.find(([u]) => u.includes('/api/ExecCIPPDBCache'))!;
    expect(init?.method).toBe('POST');
    expect(new URL(url).searchParams.get('Name')).toBe('SharePointSharingLinks');
  });

  it('refuses read entries (even for a write caller), pointing at cipp_exec_read', async () => {
    const res = await handler(WRITE).handleToolCall('cipp_exec_write', { name: 'ListThings', arguments: { tenantFilter: 't' } });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/cipp_exec_read/);
    expect(cippCalls()).toEqual([]);
  });

  it('shares the value checks and framing', async () => {
    const bad = await handler(WRITE).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'a/../b', tenantFilter: 't' } });
    expect(bad.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
    const ok = await handler(WRITE).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'x', tenantFilter: 'aviva.org.nz' } });
    expect(text(ok).split('\n')[0]).toMatch(/^\[CIPP data for tenant aviva\.org\.nz /);
  });
});

describe('search and tool-info say which exec tool runs each entry', () => {
  it('search results carry run_with', async () => {
    const r = JSON.parse(body(await handler(WRITE).handleToolCall('cipp_search_tools', { limit: 100 })));
    const by = (n: string) => r.results.find((x: { name: string }) => x.name === n);
    expect(by('ListThings').run_with).toBe('cipp_exec_read');
    expect(by('ExecCIPPDBCache').run_with).toBe('cipp_exec_write');
  });

  it('tool info carries run_with', async () => {
    const r = JSON.parse(body(await handler(WRITE).handleToolCall('cipp_get_tool_info', { names: ['ListThings', 'ExecCIPPDBCache'] })));
    expect(r[0].run_with).toBe('cipp_exec_read');
    expect(r[1].run_with).toBe('cipp_exec_write');
  });
});
