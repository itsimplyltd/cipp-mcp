// Anthropic's API rejects tool input-schema property names outside /^[a-zA-Z0-9_.-]{1,64}$/
// (cipp_graph_request once shipped "$select"). Also: cipp_graph_request's bare OData names,
// and AllTenants refused on cipp_exec_write.

// tenantFilter canonicalisation has its own suite (itsl-tenant.test.ts); here it is a passthrough so these suites' CIPP call counts stay exact.
jest.mock('../src/itsl/tenant.js', () => ({
  canonicaliseTenantArgs: async (args: Record<string, unknown>) => ({ ok: true, args }),
}));

import fixture from './fixtures/openapi-fixture.json';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { ToolContext } from '../src/itsl/meta-tools.js';
import { buildGraphRequest } from '../src/itsl/graph.js';
import { jsonResponse } from './helpers.js';

const READ: ToolContext = { tier: 'read', user: 'r@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'w@example.com' };
const NAME_RE = /^[a-zA-Z0-9_.-]{1,64}$/;
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
const cippCalls = () =>
  fetchMock.mock.calls.map(([u]) => u).filter((u) => u.startsWith('https://cipp.example/api/') && !u.includes('/api/ListOpenApiSpec'));

function badNames(node: unknown, path: string, out: string[]): void {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) return node.forEach((n, i) => badNames(n, `${path}[${i}]`, out));
  const o = node as Record<string, unknown>;
  const props = o['properties'];
  if (props && typeof props === 'object' && !Array.isArray(props)) {
    for (const k of Object.keys(props)) if (!NAME_RE.test(k)) out.push(`${path}.properties.${k}`);
  }
  for (const [k, v] of Object.entries(o)) badNames(v, `${path}.${k}`, out);
}

describe('every listed tool has API-legal input-schema property names', () => {
  it.each([['read', READ], ['write', WRITE]] as const)('%s caller', (_n, ctx) => {
    const tools = handler(ctx).getToolDefinitions() as Array<{ name: string; inputSchema: unknown }>;
    expect(tools.length).toBeGreaterThan(30);
    const bad: string[] = [];
    for (const t of tools) badNames(t.inputSchema, t.name, bad);
    expect(bad).toEqual([]);
  });

  it('the checker itself catches a $-prefixed name (control)', () => {
    const bad: string[] = [];
    badNames({ type: 'object', properties: { ok: { type: 'string' }, $select: { type: 'string' } } }, 't', bad);
    expect(bad).toEqual(['t.properties.$select']);
  });
});

describe('cipp_graph_request uses bare OData names and maps them', () => {
  it('schema exposes select, filter, top, expand, format (no $ names)', () => {
    const t = handler(READ).getToolDefinitions().find((x) => x.name === 'cipp_graph_request') as { inputSchema: { properties: Record<string, unknown> } };
    expect(Object.keys(t.inputSchema.properties).sort()).toEqual(['Version', 'endpoint', 'expand', 'filter', 'format', 'select', 'tenantFilter', 'top']);
  });

  it('maps to the $-prefixed names in the CIPP call', async () => {
    const res = await handler(READ).handleToolCall('cipp_graph_request', {
      tenantFilter: 't', endpoint: 'users', select: 'id', filter: 'accountEnabled eq true', top: 5, expand: 'manager', format: 'application/json',
    });
    expect(res.isError).toBeUndefined();
    const u = new URL(cippCalls()[0]!);
    expect(u.searchParams.get('$select')).toBe('id');
    expect(u.searchParams.get('$filter')).toBe('accountEnabled eq true');
    expect(u.searchParams.get('$top')).toBe('5');
    expect(u.searchParams.get('$expand')).toBe('manager');
    expect(u.searchParams.get('$format')).toBe('application/json');
  });

  it.each([['$select', 'select'], ['$filter', 'filter'], ['$top', 'top'], ['$expand', 'expand'], ['$format', 'format'], ['$Select', 'select']])(
    'legacy key %s is rejected with a message naming %s',
    async (legacy, bare) => {
      const r = buildGraphRequest({ tenantFilter: 't', endpoint: 'users', [legacy]: legacy === '$top' ? 5 : 'x' });
      expect(r.ok).toBe(false);
      expect((r as { reason: string }).reason).toContain(`use '${bare}'`);
      const res = await handler(READ).handleToolCall('cipp_graph_request', { tenantFilter: 't', endpoint: 'users', [legacy]: 'x' });
      expect(res.isError).toBe(true);
      expect(cippCalls()).toEqual([]);
    }
  );

  it('all validation still applies to the mapped values', () => {
    const base = { tenantFilter: 't', endpoint: 'users' };
    for (const bad of [{ expand: 'bitlocker' }, { select: 'recoveryKey' }, { select: 'activationLockBypassCode' }, { expand: 'messages' }, { top: 0 }, { top: 1000 }, { format: 'application/xml' }]) {
      expect(buildGraphRequest({ ...base, ...bad }).ok).toBe(false);
    }
    expect(buildGraphRequest({ ...base, top: 999, format: 'application/json' }).ok).toBe(true);
  });

  it('central value checks cover the new keys, and format may carry its slash', async () => {
    const bad = await handler(READ).handleToolCall('cipp_graph_request', { tenantFilter: 't', endpoint: 'users', select: 'a/b' });
    expect(bad.isError).toBe(true);
    expect(text(bad)).toMatch(/argument 'select'/);
    const ok = await handler(READ).handleToolCall('cipp_graph_request', { tenantFilter: 't', endpoint: 'users', format: 'application/json' });
    expect(ok.isError).toBeUndefined();
  });
});

describe('cipp_exec_write refuses AllTenants', () => {
  const MSG = 'AllTenants is not allowed on write-tier calls - run it per tenant.';
  it.each(['tenantFilter', 'TenantFilter', 'TENANTFILTER', 'tenantfilter'])('refuses key %s with AllTenants in any case or padding', async (key) => {
    for (const value of ['AllTenants', 'alltenants', 'ALLTENANTS', ' AllTenants ']) {
      const res = await handler(WRITE).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'x', [key]: value } });
      expect(res.isError).toBe(true);
      expect(text(res)).toContain(MSG);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('refuses a nested tenantFilter too, and does so for every write entry', async () => {
    for (const name of ['ExecSyncDEP', 'ExecTestRun', 'ExecExtensionSync']) {
      const res = await handler(WRITE).handleToolCall('cipp_exec_write', { name, arguments: { tenantFilter: 'AllTenants' } });
      expect(text(res)).toContain(MSG);
    }
    const nested = await handler(WRITE).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'x', body: { TenantFilter: 'AllTenants' } } });
    expect(text(nested)).toContain(MSG);
    expect(cippCalls()).toEqual([]);
  });

  it('a specific tenant still works on write; reads keep AllTenants', async () => {
    const ok = await handler(WRITE).handleToolCall('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'x', tenantFilter: 'aviva.org.nz' } });
    expect(ok.isError).toBeUndefined();
    const read = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 'AllTenants' } });
    expect(read.isError).toBeUndefined();
    const graph = await handler(READ).handleToolCall('cipp_graph_request', { tenantFilter: 'AllTenants', endpoint: 'users' });
    expect(graph.isError).toBeUndefined();
  });
});
