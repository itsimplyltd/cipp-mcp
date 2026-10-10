// IT Simply guard tests at the single dispatch path (CippToolHandler.handleToolCall):
// no blocked or disabled endpoint, and no write endpoint for a read caller, is
// reachable through cipp_exec_tool or through any named tool.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import fixture from './fixtures/openapi-fixture.json';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { TOOL_DEFINITIONS } from '../src/mcp/tool.definitions.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { NAMED_TOOL_ENDPOINTS, namedToolTier } from '../src/itsl/named-tools.js';
import { META_TOOL_NAMES, ToolContext } from '../src/itsl/meta-tools.js';
import { jsonResponse } from './helpers.js';

const logger = new Logger('error');
const READ: ToolContext = { tier: 'read', user: 'reader@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'writer@example.com' };

const BLOCKED_LITERAL = [
  'ExecGetLocalAdminPassword',
  'ExecGetRecoveryKey',
  'ExecSendPush',
  'ExecMailTest',
  'ExecBreachSearch',
  'ExecCPVRefresh',
  'ExecStandardsRun',
  'ExecCIPPDBCacheAdmin',
  'ExecMcp',
  'ListOpenApiSpec',
  'ListCippDocs',
  'ListExtensionsConfig',
];

const WYRE_WRITE_TOOLS = [
  'cipp_create_user',
  'cipp_edit_user',
  'cipp_disable_user',
  'cipp_reset_password',
  'cipp_reset_mfa',
  'cipp_revoke_sessions',
  'cipp_offboard_user',
  'cipp_create_group',
  'cipp_set_out_of_office',
  'cipp_set_email_forwarding',
  'cipp_run_standards_check',
  'cipp_create_standard_template',
  'cipp_delete_standard_template',
  'cipp_add_scheduled_item',
];

type FetchMock = jest.Mock<Promise<Response>, [string, RequestInit?]>;
let fetchMock: FetchMock;
let svc: CippService;

/** CIPP stub: serves the fixture spec for ListOpenApiSpec, `{ok:true}` for everything else. */
function installFetch(specOk = true): void {
  fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>((url) => {
    if (url.includes('/api/ListOpenApiSpec')) {
      if (!specOk) return Promise.resolve({ ok: false, status: 404, text: async () => 'nope' } as unknown as Response);
      return Promise.resolve(jsonResponse(fixture));
    }
    if (url.includes('/api/GetVersion')) return Promise.resolve(jsonResponse({ version: '10.9.1' }));
    if (url.startsWith('https://github.com') || url.startsWith('https://raw.githubusercontent.com')) {
      return Promise.resolve({ ok: false, status: 404, text: async () => 'nope' } as unknown as Response);
    }
    return Promise.resolve(jsonResponse({ ok: true }));
  });
  global.fetch = fetchMock as unknown as typeof fetch;
}

const cippCalls = (): string[] =>
  fetchMock.mock.calls.map(([u]) => u).filter((u) => u.startsWith('https://cipp.example/api/') && !u.includes('/api/ListOpenApiSpec'));

const handler = (ctx: ToolContext) => new CippToolHandler(svc, logger, ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;

beforeEach(() => {
  catalogueStore.reset();
  installFetch();
  svc = new CippService({ cipp: { baseUrl: 'https://cipp.example', apiKey: 'tok' } }, logger);
});

afterEach(() => jest.restoreAllMocks());

describe('named tools: tier from the CIPP endpoint they call', () => {
  it('the 14 WYRE write tools are disabled, or blocked for cipp_run_standards_check', () => {
    for (const t of WYRE_WRITE_TOOLS) {
      expect(namedToolTier(t)).toBe(t === 'cipp_run_standards_check' ? 'blocked' : 'disabled');
    }
  });

  it('the 33 read-only named tools are read tier', () => {
    const reads = TOOL_DEFINITIONS.map((t) => t.name).filter((n) => !WYRE_WRITE_TOOLS.includes(n));
    expect(reads).toHaveLength(33);
    for (const t of reads) expect(namedToolTier(t)).toBe('read');
  });

  it.each(WYRE_WRITE_TOOLS)('%s is refused for read AND write callers and never reaches CIPP', async (tool) => {
    for (const ctx of [READ, WRITE]) {
      const res = await handler(ctx).handleToolCall(tool, { tenantFilter: 't.example', userId: 'u', displayName: 'd' });
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/^Refused:/);
      expect(text(res)).not.toMatch(/not found/i);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('a live spec cannot loosen a named tool, only tighten it', async () => {
    // Spec says ListUsers is ReadWrite: the named tool must stop being read.
    const tightened = JSON.parse(JSON.stringify(fixture));
    tightened.paths['/api/ListUsers'] = { get: { 'x-cipp-role': 'Identity.User.ReadWrite' } };
    fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>(() => Promise.resolve(jsonResponse(tightened)));
    global.fetch = fetchMock as unknown as typeof fetch;
    await handler(READ).handleToolCall('cipp_search_tools', {}); // loads the catalogue
    const res = await handler(READ).handleToolCall('cipp_list_users', { tenantFilter: 't' });
    expect(res.isError).toBe(true);
  });

  it('read named tools run for a read caller', async () => {
    const res = await handler(READ).handleToolCall('cipp_ping', {});
    expect(res.isError).toBeUndefined();
    expect(cippCalls()).toEqual(['https://cipp.example/api/PublicPing']);
  });

  it('works with no catalogue at all (spec sources down)', async () => {
    installFetch(false);
    const res = await handler(READ).handleToolCall('cipp_list_bpa', { tenantFilter: 't' });
    expect(res.isError).toBeUndefined();
    const search = await handler(READ).handleToolCall('cipp_search_tools', {});
    expect(search.isError).toBe(true);
    expect(text(search)).toMatch(/catalogue is unavailable/);
  });

  it('rejects an unknown tool name before the switch', async () => {
    await expect(handler(WRITE).handleToolCall('cipp_made_up', {})).rejects.toThrow(/Unknown tool/);
  });
});

describe('tools/list is filtered by tier', () => {
  it('shows read callers no write, disabled or blocked tools, and every caller the meta tools', () => {
    for (const ctx of [READ, WRITE]) {
      const names = handler(ctx).getToolDefinitions().map((t) => t.name);
      for (const w of WYRE_WRITE_TOOLS) expect(names).not.toContain(w);
      for (const m of META_TOOL_NAMES) expect(names).toContain(m);
      expect(names).toContain('cipp_list_users');
      expect(names).toContain('cipp_list_tenants');
      expect(names).toHaveLength(33 + META_TOOL_NAMES.length);
    }
  });
});

describe('cipp_exec_tool enforcement', () => {
  it.each(BLOCKED_LITERAL)('%s is refused for read and write callers, with and without a catalogue', async (name) => {
    for (const ctx of [READ, WRITE]) {
      for (const specOk of [true, false]) {
        catalogueStore.reset();
        installFetch(specOk);
        const res = await handler(ctx).handleToolCall('cipp_exec_tool', { name, arguments: { tenantFilter: 't' } });
        expect(res.isError).toBe(true);
        expect(text(res)).toMatch(/blocked/);
        expect(cippCalls()).toEqual([]);
      }
    }
  });

  it('refuses spelling variants of blocked names', async () => {
    for (const name of ['execgetrecoverykey', 'EXECGETRECOVERYKEY', 'ExecGetRecoveryKey ', 'ExecGetRecoveryKey/', '../ExecGetRecoveryKey', 'ExecGetRecoveryKey?x=1']) {
      const res = await handler(WRITE).handleToolCall('cipp_exec_tool', { name, arguments: {} });
      expect(res.isError).toBe(true);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('refuses by role pattern: SuperAdmin, AppSettings and Extension reads', async () => {
    for (const name of ['ListSuperThing', 'ListAppSettingThing', 'ListExtensionStatus', 'ExecAppSettingWrite']) {
      const res = await handler(WRITE).handleToolCall('cipp_exec_tool', { name });
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/blocked/);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('refuses disabled endpoints for everyone with a reason that is not "not found"', async () => {
    for (const name of ['ExecDisableUser', 'ExecBaselineRun', 'ListSneakyReadWrite', 'AddTestReport', 'ListNoRole', 'ListMixed']) {
      for (const ctx of [READ, WRITE]) {
        const res = await handler(ctx).handleToolCall('cipp_exec_tool', { name });
        expect(res.isError).toBe(true);
        expect(text(res)).toMatch(/disabled/);
        expect(text(res)).not.toMatch(/not found|not an endpoint/i);
      }
    }
    expect(cippCalls()).toEqual([]);
  });

  it('a read-tier caller cannot run ANY write entry', async () => {
    const writes = ['ExecCIPPDBCache', 'ExecSyncAPDevices', 'ExecSyncDEP', 'ExecSyncVPP', 'ExecExtensionSync', 'ExecTestRefresh', 'ExecTestRun'];
    for (const name of writes) {
      const res = await handler(READ).handleToolCall('cipp_exec_tool', { name, arguments: { Name: 'x', tenantFilter: 't' } });
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/write-tier/);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('a write-tier caller can run the write entries: POST, query params in the URL, rest in the body', async () => {
    const res = await handler(WRITE).handleToolCall('cipp_exec_tool', {
      name: 'ExecCIPPDBCache',
      arguments: { Name: 'SharePointSharingLinks', tenantFilter: 'aviva.org.nz' },
    });
    expect(res.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls.find(([u]) => u.includes('/api/ExecCIPPDBCache'))!;
    expect(init?.method).toBe('POST');
    const u = new URL(url);
    expect(u.searchParams.get('Name')).toBe('SharePointSharingLinks');
    expect(u.searchParams.get('tenantFilter')).toBe('aviva.org.nz');
    expect(JSON.parse(init!.body as string)).toEqual({});
  });

  it('read entries run for a read caller, sending the per-user token', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_tool', { name: 'ListThings', arguments: { tenantFilter: 't.example', userId: 'u1' } });
    expect(res.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls.find(([u]) => u.includes('/api/ListThings'))!;
    expect(init?.method).toBe('GET');
    expect(new URL(url).searchParams.get('userId')).toBe('u1');
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer tok');
  });

  it('an endpoint missing from the catalogue is refused, not called', async () => {
    const res = await handler(WRITE).handleToolCall('cipp_exec_tool', { name: 'NotInSpec' });
    expect(res.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });

  it('refuses ListGraphRequest paths that would reopen blocked secrets, via exec and cipp_graph_request', async () => {
    for (const endpoint of ['informationProtection/bitlocker/recoveryKeys', 'deviceManagement/x/deviceLocalCredentials', 'users/u/authentication/temporaryAccessPassMethods', 'a%2Fbitlocker%2Fkeys']) {
      const viaExec = await handler(WRITE).handleToolCall('cipp_exec_tool', { name: 'ListGraphRequest', arguments: { tenantFilter: 't', Endpoint: endpoint } });
      expect(viaExec.isError).toBe(true);
      const viaGraph = await handler(WRITE).handleToolCall('cipp_graph_request', { tenantFilter: 't', endpoint });
      expect(viaGraph.isError).toBe(true);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('cipp_graph_request runs an ordinary read', async () => {
    const res = await handler(READ).handleToolCall('cipp_graph_request', { tenantFilter: 't', endpoint: 'users', $top: 5 });
    expect(res.isError).toBeUndefined();
    const [url] = fetchMock.mock.calls.find(([u]) => u.includes('/api/ListGraphRequest'))!;
    expect(new URL(url).searchParams.get('Endpoint')).toBe('users');
    expect(new URL(url).searchParams.get('$top')).toBe('5');
  });
});

describe('cipp_search_tools / cipp_get_tool_info', () => {
  it('search shows a read caller ListThings but not ExecCIPPDBCache; a write caller sees it', async () => {
    const r = JSON.parse(text(await handler(READ).handleToolCall('cipp_search_tools', { limit: 100 })));
    const names: string[] = r.results.map((x: { name: string }) => x.name);
    expect(names).toContain('ListThings');
    expect(names).not.toContain('ExecCIPPDBCache');
    const w = JSON.parse(text(await handler(WRITE).handleToolCall('cipp_search_tools', { limit: 100 })));
    expect(w.results.map((x: { name: string }) => x.name)).toContain('ExecCIPPDBCache');
  });

  it('get_tool_info returns a schema for callable entries and refuses the rest, naming the reason', async () => {
    const res = JSON.parse(
      text(await handler(READ).handleToolCall('cipp_get_tool_info', { names: ['ListThings', 'ExecCIPPDBCache', 'ExecGetRecoveryKey', 'ExecDisableUser'] }))
    );
    expect(res[0].inputSchema).toBeDefined();
    expect(res[1].error).toMatch(/write-tier/);
    expect(res[2].error).toMatch(/blocked/);
    expect(res[3].error).toMatch(/disabled/);
  });
});

describe('source guards: the named-tool table cannot go stale', () => {
  const src = (p: string) => readFileSync(join(__dirname, '..', 'src', p), 'utf8').replace(/\r\n/g, '\n');

  it('every CIPP endpoint called in cipp.service.ts is covered by NAMED_TOOL_ENDPOINTS', () => {
    const used = new Set<string>();
    const re = /this\.request(?:<[^>]*>)?\(\s*'(?:GET|POST|PATCH|PUT|DELETE)',\s*'([A-Za-z0-9_]+)'/g;
    const service = src('services/cipp.service.ts');
    let m: RegExpExecArray | null;
    while ((m = re.exec(service))) used.add(m[1]!);
    expect(used.size).toBeGreaterThan(30);
    const covered = new Set(Object.values(NAMED_TOOL_ENDPOINTS).flat());
    expect([...used].filter((e) => !covered.has(e))).toEqual([]);
  });

  it('every `case` in the handler switch and every tool definition is in the table, and vice versa', () => {
    const cases = [...src('handlers/tool.handler.ts').matchAll(/case '(cipp_[a-z_]+)':/g)].map((m) => m[1]!);
    const table = Object.keys(NAMED_TOOL_ENDPOINTS);
    expect(new Set(cases)).toEqual(new Set(table));
    expect(new Set(TOOL_DEFINITIONS.map((t) => t.name))).toEqual(new Set(table));
    expect(table).toHaveLength(47);
  });

  it('only the tier-checked path calls CippService.callEndpoint', () => {
    for (const f of ['handlers/tool.handler.ts', 'mcp/server.ts']) {
      expect(src(f)).not.toMatch(/callEndpoint/);
    }
  });
});
