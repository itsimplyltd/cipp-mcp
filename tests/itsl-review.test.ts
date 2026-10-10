// Guard tests for the security-review rulings (fix round). Each fails if its
// ruling is reverted:
//  1 Graph relays blocked in the catalogue   2 cipp_graph_request allowlist
//  3 read tier is GET-only                   4 backup/diagnostic endpoints blocked
//  5 no argument values logged pre-gate

import fixture from './fixtures/openapi-fixture.json';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { ToolContext } from '../src/itsl/meta-tools.js';
import { buildGraphRequest, normaliseGraphPath } from '../src/itsl/graph.js';
import { GRAPH_ALLOWED_PREFIXES } from '../src/itsl/policy.js';
import { jsonResponse } from './helpers.js';

const READ: ToolContext = { tier: 'read', user: 'reader@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'writer@example.com' };

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

const handler = (ctx: ToolContext, logger: Logger = new Logger('error')) => new CippToolHandler(svc, logger, ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;
const cippCalls = () =>
  fetchMock.mock.calls.map(([u]) => u).filter((u) => u.startsWith('https://cipp.example/api/') && !u.includes('/api/ListOpenApiSpec'));

describe('rule 1: Graph relays are blocked in the catalogue', () => {
  const attempts = [
    { name: 'ListGraphRequest', arguments: { tenantFilter: 'x', ENDPOINT: 'directory/deviceLocalCredentials/abc' } },
    { name: 'ListGraphRequest', arguments: { Endpoint: 'users', manualPagination: true, nextLink: 'https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys/x' } },
    { name: 'ListGraphRequest', arguments: { Endpoint: 'users' } },
    { name: 'ListGraphBulkRequest', arguments: {} },
    { name: 'ExecGraphExplorerPreset', arguments: {} },
    { name: 'ExecGraphRequestProfile', arguments: {} },
  ];
  it.each(attempts.map((a, i) => [i, a] as const))('attempt %i is refused at both tiers and never reaches CIPP', async (_i, a) => {
    for (const ctx of [READ, WRITE]) {
      const res = await handler(ctx).handleToolCall('cipp_exec_read', a);
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/Refused:/); // blocked by name, or refused earlier by value validation
    }
    expect(cippCalls()).toEqual([]);
  });

  it('cipp_list_enterprise_apps (a fixed servicePrincipals GET) still works', async () => {
    const res = await handler(READ).handleToolCall('cipp_list_enterprise_apps', { tenantFilter: 't' });
    expect(res.isError).toBeUndefined();
    expect(cippCalls().some((u) => u.includes('/api/ListGraphRequest'))).toBe(true);
  });
});

describe('rule 2: cipp_graph_request is allowlist-based', () => {
  const graph = (args: Record<string, unknown>, ctx = READ) => handler(ctx).handleToolCall('cipp_graph_request', args);

  it('allowlist contains exactly the agreed starting collections', () => {
    expect([...GRAPH_ALLOWED_PREFIXES]).toEqual([
      'users', 'groups', 'devices', 'serviceprincipals', 'applications', 'domains', 'organization', 'subscribedskus',
      'directoryroles', 'rolemanagement/directory', 'identity/conditionalaccess', 'policies', 'auditlogs', 'reports',
      'security/alerts_v2', 'security/incidents', 'devicemanagement/manageddevices',
      'devicemanagement/devicecompliancepolicies', 'teams', 'sites',
    ]);
  });

  it('runs an allowed collection as a fixed GET with only the fixed parameters', async () => {
    const res = await graph({ tenantFilter: 't.example', endpoint: '/v1.0/Users/abc/memberOf', top: 5, select: 'id,displayName' });
    expect(res.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls.find(([u]) => u.includes('/api/ListGraphRequest'))!;
    expect(init?.method).toBe('GET');
    const u = new URL(url);
    expect([...u.searchParams.keys()].sort()).toEqual(['$select', '$top', 'Endpoint', 'Version', 'tenantFilter']);
    expect(u.searchParams.get('Version')).toBe('v1.0'); // always explicit (N5)
    expect(u.searchParams.get('Endpoint')).toBe('users/abc/memberof');
  });

  it('maps a beta prefix to Version=beta and strips the prefix', () => {
    const r = buildGraphRequest({ tenantFilter: 't', endpoint: 'beta/groups' });
    expect(r).toEqual({ ok: true, params: { tenantFilter: 't', Endpoint: 'groups', Version: 'beta' } });
  });

  it('accepts every allowlisted prefix and nested paths beneath it, and nothing else', () => {
    for (const p of GRAPH_ALLOWED_PREFIXES) {
      expect('error' in normaliseGraphPath(p)).toBe(false);
      expect('error' in normaliseGraphPath(p + '/abc')).toBe(false);
      expect('error' in normaliseGraphPath(p + 'x')).toBe(true); // prefix match is on a segment boundary
    }
  });

  it.each([
    'informationProtection/bitlocker/recoveryKeys',
    'devices/abc/bitlocker',
    'directory/deviceLocalCredentials/abc',
    'users/u/authentication/methods',
    'users/u/authentication/temporaryAccessPassMethods',
    'deviceManagement/managedDevices/abc/getFileVaultKey',
    'deviceManagement/deviceConfigurations/abc/getOmaSettingPlainTextValue',
    'deviceManagement/managedDevices/abc/recoveryKeys',
    'users/abc/secretReferenceValueId',
    'users/../informationProtection',
    'users%2F..%2Fx',
    'users?$select=id',
    'users#frag',
    'users/$batch',
    '$batch',
    'users/microsoft.graph.delta',
    'users/getByIds',
    'users/abc/getMemberObjects',
    "users('abc')",
    'users//abc',
    '',
    'mail',
    'drives',
    'me/messages',
    'deviceManagement/windowsAutopilotDeviceIdentities',
  ])('refuses %j', async (endpoint) => {
    expect((await graph({ tenantFilter: 't', endpoint })).isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });

  it('refuses a non-string endpoint (fails closed)', async () => {
    for (const endpoint of [undefined, null, 5, ['users'], { a: 1 }]) {
      expect((await graph({ tenantFilter: 't', endpoint })).isError).toBe(true);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('refuses unknown keys, nextLink, manualPagination, AsApp and keys duplicated by case', async () => {
    const extras = [
      { nextLink: 'https://graph.microsoft.com/x' },
      { manualPagination: true },
      { AsApp: true },
      { QueueNameOverride: 'x' },
      { ENDPOINT: 'users' },
      { Endpoint: 'users' },
      { TENANTFILTER: 'b' },
      { $Select: 'id', select: 'id' },
    ];
    for (const extra of extras) {
      expect((await graph({ tenantFilter: 't', endpoint: 'users', ...extra })).isError).toBe(true);
    }
    expect(cippCalls()).toEqual([]);
  });

  it('validates $select/$filter/$expand/$top and refuses denylisted terms in them', async () => {
    const bads = [
      { expand: 'bitlocker' },
      { expand: 'deviceLocalCredentials' },
      { select: 'recoveryKey' },
      { filter: "x eq 'informationProtection'" },
      { top: 0 },
      { top: 1000 },
      { top: '5' },
      { top: 1.5 },
      { select: 5 },
      { expand: 'a'.repeat(1001) },
    ];
    for (const bad of bads) {
      expect((await graph({ tenantFilter: 't', endpoint: 'users', ...bad })).isError).toBe(true);
    }
    expect(cippCalls()).toEqual([]);
    const ok = await graph({ tenantFilter: 't', endpoint: 'users', filter: 'accountEnabled eq true', expand: 'manager', top: 999 });
    expect(ok.isError).toBeUndefined();
  });

  it('refuses a bad tenantFilter', () => {
    for (const tenantFilter of [undefined, '', 'a b', 'x&y=1', 5]) {
      expect(buildGraphRequest({ tenantFilter, endpoint: 'users' }).ok).toBe(false);
    }
  });
});

describe('rule 3: the read tier is GET-only', () => {
  it('exec of ListTenants is a GET; ClearCache, TriggerRefresh and AsApp never reach CIPP', async () => {
    const ok = await handler(READ).handleToolCall('cipp_exec_read', {
      name: 'ListTenants',
      arguments: { ClearCache: true, TriggerRefresh: true, AllTenantSelector: true, AsApp: true },
    });
    expect(ok.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls.find(([u]) => u.includes('/api/ListTenants'))!;
    expect(init?.method).toBe('GET');
    expect(url).toContain('AllTenantSelector=true');
    for (const bad of ['clearcache', 'triggerrefresh', 'asapp']) expect(url.toLowerCase()).not.toContain(bad);
  });

  it('POST-only .Read entries, ExecBECCheck and ListAuditLogSearches are disabled at both tiers', async () => {
    for (const name of ['ListPostOnlyRead', 'ExecBECCheck', 'ListAuditLogSearches']) {
      for (const ctx of [READ, WRITE]) {
        const res = await handler(ctx).handleToolCall('cipp_exec_read', { name });
        expect(res.isError).toBe(true);
        expect(text(res)).toMatch(/disabled/);
      }
    }
    expect(cippCalls()).toEqual([]);
  });

  it('named tools that POST to a read endpoint are refused and never reach CIPP', async () => {
    for (const tool of ['cipp_bec_check', 'cipp_list_scheduled_items']) {
      for (const ctx of [READ, WRITE]) {
        expect((await handler(ctx).handleToolCall(tool, { tenantFilter: 't', userId: 'u' })).isError).toBe(true);
      }
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('cipp_list_tenants is a GET and cannot send ClearCache', async () => {
    await handler(READ).handleToolCall('cipp_list_tenants', { allTenants: true, ClearCache: true });
    const [url, init] = fetchMock.mock.calls.find(([u]) => u.includes('/api/ListTenants'))!;
    expect(init?.method).toBe('GET');
    expect(url.toLowerCase()).not.toContain('clearcache');
  });

  it('exec refuses keys differing only by case and canonicalises declared spellings', async () => {
    const dup = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 'a', TENANTFILTER: 'b' } });
    expect(dup.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
    await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { TENANTFILTER: 'a' } });
    expect(new URL(cippCalls()[0]!).searchParams.get('tenantFilter')).toBe('a');
  });
});

describe('rule 4: backup and diagnostic endpoints are blocked', () => {
  it('no *Backup* endpoint, CIPP.Backup role, ExecListBackup, ListApiTest or ListExoRequest is callable', async () => {
    for (const name of ['ListSomeBackupThing', 'ListRoleBackupOnly', 'ExecListBackup', 'ListApiTest', 'ListExoRequest']) {
      for (const ctx of [READ, WRITE]) {
        const res = await handler(ctx).handleToolCall('cipp_exec_read', { name });
        expect(res.isError).toBe(true);
        expect(text(res)).toMatch(/blocked/);
      }
    }
    expect(cippCalls()).toEqual([]);
  });
});

describe('rule 5: argument values are never logged before the gate', () => {
  it('a refused cipp_create_user does not log its password, at any level', async () => {
    const lines: string[] = [];
    const cap = (...a: unknown[]) => lines.push(JSON.stringify(a));
    const logger = { debug: cap, info: cap, warn: cap, error: cap } as unknown as Logger;
    await handler(READ, logger).handleToolCall('cipp_create_user', { tenantFilter: 't', password: 'Sup3rS3cretPw!', displayName: 'x', userPrincipalName: 'u@x' });
    await handler(WRITE, logger).handleToolCall('cipp_reset_password', { tenantFilter: 't', userId: 'u', newPassword: 'Sup3rS3cretPw!' });
    // and a permitted call logs keys only
    await handler(READ, logger).handleToolCall('cipp_list_users', { tenantFilter: 'secret-tenant.example' });
    expect(lines.length).toBeGreaterThan(0);
    for (const l of lines) expect(l).not.toContain('Sup3rS3cretPw!');
    expect(lines.join('\n')).toContain('argumentKeys');
  });
});
