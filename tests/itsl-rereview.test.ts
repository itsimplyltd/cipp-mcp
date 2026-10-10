// Guard tests for fix round 2 (re-review): argument value validation (N1),
// Graph deny terms / allowlist / content segments (N2, N3), path normalisation
// (N4), explicit Version (N5), report functions and OData casts.

import fixture from './fixtures/openapi-fixture.json';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { ToolContext } from '../src/itsl/meta-tools.js';
import { buildGraphRequest, normaliseGraphPath } from '../src/itsl/graph.js';
import { validateArgumentValues } from '../src/itsl/values.js';
import { GRAPH_ALLOWED_PREFIXES, VALUE_SLASH_ALLOWED_KEYS } from '../src/itsl/policy.js';
import { jsonResponse } from './helpers.js';

const READ: ToolContext = { tier: 'read', user: 'reader@example.com' };
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

const handler = (ctx: ToolContext = READ) => new CippToolHandler(svc, new Logger('error'), ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;
const cippCalls = () =>
  fetchMock.mock.calls.map(([u]) => u).filter((u) => u.startsWith('https://cipp.example/api/') && !u.includes('/api/ListOpenApiSpec'));

describe('N1: argument value validation, centrally, before dispatch', () => {
  // The reviewer's actual payloads (probe3).
  const PAYLOADS: Array<[string, Record<string, unknown>]> = [
    ['ListUsers', { tenantFilter: 'x', UserID: '../directory/deviceLocalCredentials/abc?$select=credentials#' }],
    ['ListDeviceDetails', { tenantFilter: 'x', DeviceID: '../../informationProtection/bitlocker/recoveryKeys/abc?$select=key' }],
    ['ListGraphReports', { tenantFilter: 'x', report: '../informationProtection/bitlocker/recoveryKeys#' }],
    ['ListUserDevices', { tenantFilter: 'x', UserID: 'x/messages?$top=5#' }],
    ['ListDetectedApps', { tenantFilter: 'x', DeviceID: 'ID/getFileVaultKey#' }],
  ];

  it.each(PAYLOADS)('exec of %s with a path-injection value is refused and never reaches CIPP', async (name, args) => {
    const res = await handler().handleToolCall('cipp_exec_tool', { name, arguments: args });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/Refused: argument '(UserID|DeviceID|report)' contains/);
    expect(cippCalls()).toEqual([]);
  });

  it.each([
    ['..', 'a..b'],
    ['#', 'a#b'],
    ['backslash', 'a\\b'],
    ['?', 'a?b'],
    ['&', 'a&b'],
    ['%', 'a%2fb'],
    ['/', 'a/b'],
    ['NUL', 'a\u0000b'],
    ['LF', 'a\nb'],
    ['US', 'a\u001fb'],
    ['DEL', 'a\u007fb'],
  ])('refuses a value containing %s, naming the key', (_n, value) => {
    expect(validateArgumentValues({ UserID: value })).toMatch(/argument 'UserID'/);
  });

  it('recurses into arrays and objects (POST bodies), naming the nearest key', () => {
    expect(validateArgumentValues({ body: [{ ids: ['ok', 'bad/../x'] }] })).toMatch(/argument 'ids'/);
    expect(validateArgumentValues({ a: { b: { c: 'x#y' } } })).toMatch(/argument 'c'/);
    expect(validateArgumentValues({ a: { b: { c: 'fine' }, n: 5, t: true, z: null } })).toBeUndefined();
  });

  it('refuses unreasonable argument names and excessive nesting', () => {
    expect(validateArgumentValues({ 'a/b': 'x' })).toMatch(/argument name/);
    expect(validateArgumentValues({ 'a b': 'x' })).toMatch(/argument name/);
    let deep: unknown = 'x';
    for (let i = 0; i < 12; i++) deep = { k: deep };
    expect(validateArgumentValues(deep)).toMatch(/nested too deeply/);
  });

  it('the slash-allowed key list is exactly the agreed one', () => {
    expect([...VALUE_SLASH_ALLOWED_KEYS]).toEqual(['filter', '$filter', 'graphfilter', 'search', 'query', 'searchstring', 'url', 'siteurl', 'weburl']);
  });

  it.each(['filter', '$filter', 'Filter', 'graphFilter', 'search', 'Search', 'query', 'SearchString', 'URL', 'Url', 'SiteUrl', 'webUrl'])(
    'allows "/" in the value of %s (case-insensitive) but still refuses .., #, backslash and control characters',
    (key) => {
      expect(validateArgumentValues({ [key]: 'a/b' })).toBeUndefined();
      for (const bad of ['a/../b', 'a/b#c', 'a\\b', 'a\u0000b', 'a\nb']) {
        expect(validateArgumentValues({ [key]: bad })).toMatch(new RegExp(`argument '${key.replace('$', '\\$')}'`));
      }
    }
  );

  it('the endpoint key is exempt from "/" only when the caller says so (cipp_graph_request)', () => {
    expect(validateArgumentValues({ endpoint: 'users/abc' })).toMatch(/argument 'endpoint'/);
    expect(validateArgumentValues({ endpoint: 'users/abc' }, ['endpoint'])).toBeUndefined();
  });

  it('applies to named tools too, before the call is made', async () => {
    const res = await handler().handleToolCall('cipp_list_user_devices', { tenantFilter: 'contoso.com', userId: '../x#' });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/argument 'userId'/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('applies to cipp_graph_request arguments other than endpoint', async () => {
    const res = await handler().handleToolCall('cipp_graph_request', { tenantFilter: 'x', endpoint: 'users', $filter: 'a#b' });
    expect(res.isError).toBe(true);
    expect(cippCalls()).toEqual([]);
  });

  it('ordinary values still work: GUIDs, UPNs, domains, dates, filters with slashes', async () => {
    const ok = await handler().handleToolCall('cipp_exec_tool', {
      name: 'ListThings',
      arguments: { tenantFilter: 'contoso.com', userId: '3f2a9c1e-1111-4222-8333-444455556666', filter: "startswith(a,'x/y')" },
    });
    expect(ok.isError).toBeUndefined();
    expect(validateArgumentValues({ upn: 'jo.bloggs+tag@contoso.co.nz', date: '2026-10-10T00:00:00Z' })).toBeUndefined();
  });
});

describe('N2: new deny terms; deviceConfigurations removed from the allowlist', () => {
  it('refuses activationLockBypassCode and preSharedKey in path, $select and $expand', () => {
    expect('error' in normaliseGraphPath('deviceManagement/managedDevices/abc/activationLockBypassCode')).toBe(true);
    for (const t of ['activationLockBypassCode', 'preSharedKey']) {
      expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'devices', $select: t }).ok).toBe(false);
      expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'devices', $expand: t }).ok).toBe(false);
      expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'devices', $filter: `x eq '${t}'` }).ok).toBe(false);
    }
  });

  it('deviceManagement/deviceConfigurations is not allowlisted', () => {
    expect(GRAPH_ALLOWED_PREFIXES).not.toContain('devicemanagement/deviceconfigurations');
    expect('error' in normaliseGraphPath('deviceManagement/deviceConfigurations')).toBe(true);
    expect('error' in normaliseGraphPath('deviceManagement/deviceConfigurations/abc')).toBe(true);
    expect('error' in normaliseGraphPath('deviceManagement/deviceCompliancePolicies')).toBe(false);
  });
});

describe('N3: more content segments', () => {
  it.each([
    'groups/g/conversations',
    'groups/g/threads/t/posts',
    'sites/s/pages/p',
    'users/u/planner/tasks',
    'users/u/todo/lists/l/tasks',
    'users/u/mailboxSettings',
    'users/u/insights/used',
    'users/u/onlineMeetings',
    'teams/t/schedule/shifts',
    'teams/t/schedule',
    'users/u/notes',
    'groups/g/threads/t/attachments',
    'sites/s/webParts',
    'sites/s/pages/p/canvasLayout',
  ])('refuses %s', (p) => {
    expect('error' in normaliseGraphPath(p)).toBe(true);
  });

  it('refuses the same words as whole words in $select and $expand', () => {
    for (const w of ['canvasLayout', 'webParts', 'conversations', 'mailboxSettings', 'onlineMeetings', 'attachments', 'planner']) {
      expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'users', $expand: w }).ok).toBe(false);
    }
  });
});

describe('N4: path normalisation', () => {
  it('refuses non-ASCII paths, including fullwidth and Cyrillic homoglyphs', () => {
    expect('error' in normaliseGraphPath('users/u/ｍｅｓｓａｇｅｓ')).toBe(true);
    expect('error' in normaliseGraphPath('users/u/mеssages')).toBe(true);
    expect('error' in normaliseGraphPath('users/jé')).toBe(true);
  });

  it('function/action detection is case-insensitive', () => {
    for (const p of ['teams/x/channels/getallmessages', 'users/x/GETMEMBEROBJECTS', 'users/x/getByIds', 'users/x/getmailtips']) {
      expect('error' in normaliseGraphPath(p)).toBe(true);
    }
  });

  it('refuses "." segments', () => {
    expect('error' in normaliseGraphPath('users/./x')).toBe(true);
    expect('error' in normaliseGraphPath('users/.')).toBe(true);
  });
});

describe('N5: Version is always sent', () => {
  it.each([
    ['users', 'v1.0'],
    ['v1.0/users', 'v1.0'],
    ['beta/users', 'beta'],
  ])('%s -> Version=%s', async (endpoint, version) => {
    const res = await handler().handleToolCall('cipp_graph_request', { tenantFilter: 't', endpoint });
    expect(res.isError).toBeUndefined();
    const url = new URL(cippCalls()[0]!);
    expect(url.searchParams.get('Version')).toBe(version);
  });

  it('an explicit version argument wins and is validated', () => {
    expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'users', version: 'beta' })).toMatchObject({ ok: true, params: { Version: 'beta' } });
    expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'users', version: 'v2' }).ok).toBe(false);
  });
});

describe('N6: AllTenants is accepted', () => {
  it('tenantFilter=AllTenants builds a request', () => {
    expect(buildGraphRequest({ tenantFilter: 'AllTenants', endpoint: 'users' }).ok).toBe(true);
  });
});

describe('regression fixes: reports functions and OData casts', () => {
  it('permits exactly one report function directly under reports/ with an exact period', () => {
    for (const per of ['D7', 'D30', 'D90', 'D180', 'd30']) {
      const r = normaliseGraphPath(`reports/getEmailActivityUserDetail(period='${per}')`);
      expect(r).toEqual({ path: `reports/getEmailActivityUserDetail(period='${per.toUpperCase()}')`, version: 'v1.0' });
    }
    expect('error' in normaliseGraphPath("beta/reports/getOffice365ActiveUserDetail(period='D7')")).toBe(false);
  });

  it.each([
    "reports/getEmailActivityUserDetail(period='D31')",
    "reports/getEmailActivityUserDetail(period='D30)",
    "reports/getEmailActivityUserDetail(period=D30)",
    "reports/getEmailActivityUserDetail()",
    "reports/getEmailActivityUserDetail(period='D30')/x",
    "reports/x/getEmailActivityUserDetail(period='D30')",
    "reports/getEmailActivityUserDetail(period='D30',date=2020-01-01)",
    "users/getEmailActivityUserDetail(period='D30')",
    "reports/notAFunction(period='D30')",
    "reports/getEmail(period='D30')(period='D7')",
    "users('abc')",
    "reports/authenticationMethods/getFoo(period='D7')",
  ])('refuses %s', (p) => {
    expect('error' in normaliseGraphPath(p)).toBe(true);
  });

  it('permits a final OData cast only after the listed segments', () => {
    for (const parent of ['memberOf', 'transitiveMemberOf', 'members', 'transitiveMembers', 'owners', 'ownedObjects', 'registeredOwners', 'registeredUsers']) {
      for (const type of ['group', 'user', 'device', 'servicePrincipal', 'application', 'orgContact', 'directoryRole']) {
        expect('error' in normaliseGraphPath(`users/x/${parent}/microsoft.graph.${type}`)).toBe(false);
      }
    }
    expect(normaliseGraphPath('groups/g/members/microsoft.graph.user')).toEqual({ path: 'groups/g/members/microsoft.graph.user', version: 'v1.0' });
  });

  it.each([
    'users/x/microsoft.graph.group',
    'users/x/memberOf/microsoft.graph.message',
    'users/x/memberOf/microsoft.graph.group/extra',
    'users/x/memberOf/microsoft.graph.group.delta',
    'users/x/messages/microsoft.graph.user',
    'users/x/memberOf/microsoft.graph.group/microsoft.graph.user',
    'microsoft.graph.user',
    'users/x/members/microsoft.graph.delta',
  ])('refuses %s', (p) => {
    expect('error' in normaliseGraphPath(p)).toBe(true);
  });

  it('"authentication" is a whole-word match in $select/$expand; drives stays denied', () => {
    expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'users', $select: 'id,authenticationMethodsPolicy' }).ok).toBe(true);
    expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'users', $expand: 'authentication' }).ok).toBe(false);
    expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'users', $expand: 'authentication($select=id)' }).ok).toBe(false);
    expect('error' in normaliseGraphPath('sites/s/drives')).toBe(true);
    expect(buildGraphRequest({ tenantFilter: 't', endpoint: 'sites', $select: 'drives' }).ok).toBe(false);
  });

  it('cipp_bec_check and cipp_list_scheduled_items stay disabled', async () => {
    for (const t of ['cipp_bec_check', 'cipp_list_scheduled_items']) {
      expect((await handler().handleToolCall(t, { tenantFilter: 'x', userId: 'u' })).isError).toBe(true);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
