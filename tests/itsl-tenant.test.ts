// Central tenantFilter canonicalisation, through the single dispatch path
// (CippToolHandler.handleToolCall): named tools, cipp_exec_read/write, cipp_graph_request.

import fixture from './fixtures/openapi-fixture.json';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { clearTenantCache, TENANT_CACHE_TTL_MS } from '../src/itsl/tenant.js';
import { ToolContext } from '../src/itsl/meta-tools.js';
import { jsonResponse } from './helpers.js';

const logger = new Logger('error');
const READ: ToolContext = { tier: 'read', user: 'reader@example.com' };
const OTHER: ToolContext = { tier: 'read', user: 'other@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'writer@example.com' };

const GUID = '11111111-2222-3333-4444-555555555555';
const TENANTS = [
  { customerId: GUID, defaultDomainName: 'aviva.org.nz', initialDomainName: 'aviva.onmicrosoft.com', displayName: 'Aviva' },
  {
    customerId: '99999999-2222-3333-4444-555555555555',
    defaultDomainName: 'other.co.nz',
    initialDomainName: 'other.onmicrosoft.com',
    displayName: 'Other',
    domains: ['other.co.nz', 'other-alias.com'],
  },
];

type FetchMock = jest.Mock<Promise<Response>, [string, RequestInit?]>;
let fetchMock: FetchMock;
let tenantsFail = false;
let tenantsPayload: unknown;

function installFetch(): void {
  fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>((url) => {
    if (url.includes('/api/ListOpenApiSpec')) return Promise.resolve(jsonResponse(fixture));
    if (url.includes('/api/GetVersion')) return Promise.resolve(jsonResponse({ version: '10.9.1' }));
    if (url.startsWith('https://github.com') || url.startsWith('https://raw.githubusercontent.com')) {
      return Promise.resolve({ ok: false, status: 404, text: async () => 'nope' } as unknown as Response);
    }
    if (url.includes('/api/ListTenants?') || url.endsWith('/api/ListTenants')) {
      if (tenantsFail) return Promise.resolve({ ok: false, status: 500, text: async () => 'boom' } as unknown as Response);
      return Promise.resolve(jsonResponse(tenantsPayload));
    }
    return Promise.resolve(jsonResponse({ ok: true }));
  });
  global.fetch = fetchMock as unknown as typeof fetch;
}

const urls = (name: string): string[] => fetchMock.mock.calls.map(([u]) => u).filter((u) => u.includes(`/api/${name}`));
const tenantListCalls = (): number => urls('ListTenants').length;
const sentTenant = (name: string): string | null => new URL(urls(name)[0]!).searchParams.get('tenantFilter');

let svc: CippService;
const handler = (ctx: ToolContext) => new CippToolHandler(svc, logger, ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;

beforeEach(() => {
  catalogueStore.reset();
  clearTenantCache();
  tenantsFail = false;
  tenantsPayload = TENANTS;
  installFetch();
  svc = new CippService({ cipp: { baseUrl: 'https://cipp.example', apiKey: 'tok' } }, logger);
});
afterEach(() => jest.restoreAllMocks());

describe('tenantFilter canonicalisation', () => {
  it('the default domain passes unchanged (case-insensitive, trimmed)', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: '  AVIVA.org.nz ' } });
    expect(res.isError).toBeUndefined();
    expect(sentTenant('ListThings')).toBe('aviva.org.nz');
  });

  it('a tenant GUID becomes the default domain', async () => {
    const res = await handler(READ).handleToolCall('cipp_list_tenants', {}).then(() => handler(READ).handleToolCall('cipp_get_tenant_details', { tenantFilter: GUID }));
    expect(res.isError).toBeUndefined();
    expect(sentTenant('ListTenantDetails')).toBe('aviva.org.nz');
  });

  it('the initial domain and a domain listed in the payload become the default domain', async () => {
    await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 'aviva.onmicrosoft.com' } });
    expect(sentTenant('ListThings')).toBe('aviva.org.nz');
    fetchMock.mockClear();
    await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { TenantFilter: 'other-alias.com' } });
    expect(sentTenant('ListThings')).toBe('other.co.nz');
  });

  it('an unknown tenant is refused with a near-match suggestion and never reaches CIPP', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 'avivafamilies.org.nz' } });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain("unknown tenant 'avivafamilies.org.nz'");
    expect(text(res)).toContain("did you mean 'aviva.org.nz'?");
    expect(urls('ListThings')).toEqual([]);
  });

  it('an unknown tenant with no near match is refused without a suggestion', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 'zzz.example' } });
    expect(res.isError).toBe(true);
    expect(text(res)).not.toContain('did you mean');
  });

  it('AllTenants is left untouched for reads, and needs no ListTenants call', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 'alltenants' } });
    expect(res.isError).toBeUndefined();
    expect(sentTenant('ListThings')).toBe('alltenants');
    expect(tenantListCalls()).toBe(0);
  });

  it('cipp_exec_write still refuses AllTenants', async () => {
    const res = await handler(WRITE).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'X', tenantFilter: 'AllTenants' } });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain('AllTenants');
  });

  it('cipp_exec_write canonicalises a GUID', async () => {
    const res = await handler(WRITE).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'X', tenantFilter: GUID } });
    expect(res.isError).toBeUndefined();
    expect(sentTenant('ExecCIPPDBCache')).toBe('aviva.org.nz');
  });

  it('cipp_graph_request resolves its tenantFilter', async () => {
    await handler(READ).handleToolCall('cipp_graph_request', { tenantFilter: 'aviva.onmicrosoft.com', endpoint: 'users' });
    expect(sentTenant('ListGraphRequest')).toBe('aviva.org.nz');
    fetchMock.mockClear();
    const res = await handler(READ).handleToolCall('cipp_graph_request', { tenantFilter: 'nope.example', endpoint: 'users' });
    expect(res.isError).toBe(true);
    expect(urls('ListGraphRequest')).toEqual([]);
  });

  it('nested objects under cipp_exec_read arguments are canonicalised', async () => {
    await handler(READ).handleToolCall('cipp_exec_read', {
      name: 'ListThings',
      arguments: { userId: 'u1', nested: { tenantfilter: GUID, list: [{ tenantFilter: 'aviva.onmicrosoft.com' }] } },
    });
    const raw = decodeURIComponent(urls('ListThings')[0]!);
    expect(raw).not.toContain(GUID);
    expect(raw).not.toContain('onmicrosoft.com');
    const bad = await handler(READ).handleToolCall('cipp_exec_read', {
      name: 'ListThings',
      arguments: { nested: { tenantFilter: 'unknown.example' } },
    });
    expect(bad.isError).toBe(true);
  });

  it('ListTenants itself does not recurse or trigger a lookup', async () => {
    fetchMock.mockClear();
    const res = await handler(READ).handleToolCall('cipp_list_tenants', {});
    expect(res.isError).toBeUndefined();
    expect(tenantListCalls()).toBe(1);
    fetchMock.mockClear();
    await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListTenants', arguments: { tenantFilter: 'whatever.example' } });
    expect(tenantListCalls()).toBe(1);
  });

  it('fails closed when ListTenants fails or returns nothing usable', async () => {
    tenantsFail = true;
    let res = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 'aviva.org.nz' } });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain('could not verify the tenant');
    expect(urls('ListThings')).toEqual([]);
    tenantsFail = false;
    tenantsPayload = [{ Results: 'Failed to retrieve tenants', defaultDomainName: '', customerId: '' }];
    res = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 'aviva.org.nz' } });
    expect(res.isError).toBe(true);
    expect(urls('ListThings')).toEqual([]);
  });
});

describe('tenant list cache', () => {
  const call = (ctx: ToolContext, t: string) =>
    handler(ctx).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: t } });

  it('is reused for the same user, and isolated between users', async () => {
    await call(READ, 'aviva.org.nz');
    await call(READ, GUID);
    expect(tenantListCalls()).toBe(1);
    await call(OTHER, 'aviva.org.nz');
    expect(tenantListCalls()).toBe(2);
  });

  it('expires after the TTL', async () => {
    const spy = jest.spyOn(Date, 'now');
    spy.mockReturnValue(1_000_000);
    await call(READ, 'aviva.org.nz');
    spy.mockReturnValue(1_000_000 + TENANT_CACHE_TTL_MS + 1);
    await call(READ, 'aviva.org.nz');
    expect(tenantListCalls()).toBe(2);
  });

  it('remembers an unknown value briefly instead of re-listing per request', async () => {
    const spy = jest.spyOn(Date, 'now');
    spy.mockReturnValue(2_000_000);
    await call(READ, 'aviva.org.nz'); // builds the cache
    spy.mockReturnValue(2_000_000 + 60_000);
    await call(READ, 'typo.example'); // stale enough to refresh once
    expect(tenantListCalls()).toBe(2);
    spy.mockReturnValue(2_000_000 + 61_000);
    await call(READ, 'typo.example'); // negative-cached
    expect(tenantListCalls()).toBe(2);
  });

  it('with no verified user nothing is cached', async () => {
    await call({ tier: 'read' }, 'aviva.org.nz');
    await call({ tier: 'read' }, 'aviva.org.nz');
    expect(tenantListCalls()).toBe(2);
  });
});
