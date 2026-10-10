// IT Simply tier computation and catalogue projection, over a small hand-made
// fixture spec (tests/fixtures/openapi-fixture.json). The fixture is NOT CIPP's
// openapi.json; that file is AGPL-3.0 and must never be committed here.

import fixture from './fixtures/openapi-fixture.json';
import { computeTier, isCallable, mostRestrictive } from '../src/itsl/tier.js';
import { BLOCKED_NAMES, REVIEWED, WRITE_ALLOWLIST } from '../src/itsl/policy.js';
import { CatalogueStore, findEntry, projectSpec, routeArguments, searchEntries, unwrapSpec } from '../src/itsl/catalogue.js';

// Literal on purpose: the guard must not be satisfied by editing policy.ts alone.
const MUST_BE_BLOCKED = [
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
] as const;

const SYNC_TRIGGERS = [
  'ExecCIPPDBCache',
  'ExecSyncAPDevices',
  'ExecSyncDEP',
  'ExecSyncVPP',
  'ExecExtensionSync',
  'ExecTestRefresh',
  'ExecTestRun',
] as const;

const logger = { info: jest.fn(), warn: jest.fn(), debug: jest.fn() };

describe('computeTier rules (first match wins)', () => {
  it('blocklist: every literal blocked name is blocked, whatever its role', () => {
    for (const name of MUST_BE_BLOCKED) {
      for (const role of [undefined, 'CIPP.Core.Read', 'Endpoint.Device.Read', 'X.ReadWrite']) {
        expect(computeTier(name, role)).toBe('blocked');
      }
    }
  });

  it('blocklist matches case-insensitively', () => {
    expect(computeTier('execgetrecoverykey', 'Endpoint.Device.Read')).toBe('blocked');
    expect(computeTier('EXECSENDPUSH', undefined)).toBe('blocked');
  });

  it('blocklist: SuperAdmin and AppSettings roles are blocked at any suffix; Extension only for .Read', () => {
    expect(computeTier('ListWhatever', 'CIPP.SuperAdmin.Read')).toBe('blocked');
    expect(computeTier('ExecWhatever', 'CIPP.SuperAdmin.ReadWrite')).toBe('blocked');
    expect(computeTier('ListWhatever', 'CIPP.AppSettings.Read')).toBe('blocked');
    expect(computeTier('ExecWhatever', 'CIPP.AppSettings.ReadWrite')).toBe('blocked');
    expect(computeTier('ListExtensionStatus', 'CIPP.Extension.Read')).toBe('blocked');
    // ExecExtensionSync is CIPP.Extension.ReadWrite and is on the write allowlist.
    expect(computeTier('ExecExtensionSync', 'CIPP.Extension.ReadWrite')).toBe('write');
  });

  it('write allowlist: the 7 sync triggers are write', () => {
    for (const name of SYNC_TRIGGERS) expect(computeTier(name, 'X.ReadWrite')).toBe('write');
    expect([...WRITE_ALLOWLIST].sort()).toEqual([...SYNC_TRIGGERS].sort());
  });

  it('read rule: a .Read role on a non-mutating name is read', () => {
    expect(computeTier('ListUsers', 'Identity.User.Read')).toBe('read');
    expect(computeTier('ExecBECCheck', 'Identity.User.Read')).toBe('read');
  });

  it('read rule: .ReadWrite is never read', () => {
    expect(computeTier('ListSneaky', 'Identity.User.ReadWrite')).toBe('disabled');
  });

  it('read rule: mutation-named endpoints are never read even when mislabelled .Read', () => {
    for (const verb of ['Add', 'Set', 'Remove', 'Delete', 'Edit', 'New', 'Update', 'Disable', 'Enable', 'Reset', 'Revoke', 'Push', 'Clear', 'Start', 'Stop', 'Rename', 'Move', 'Copy']) {
      expect(computeTier(`${verb}Thing`, 'Tenant.Tests.Read')).toBe('disabled');
    }
  });

  it('everything else is disabled, including no role', () => {
    expect(computeTier('ListNoRole', undefined)).toBe('disabled');
    expect(computeTier('ExecBaselineRun', 'Tenant.BaselinesRun.ReadWrite')).toBe('disabled');
  });

  it('reviewed promotes a would-be-disabled endpoint, and only those placed there on purpose', () => {
    expect(computeTier('ListBPA', undefined)).toBe('read');
    expect(computeTier('PublicPing', 'Public')).toBe('read');
    expect(Object.keys(REVIEWED).sort()).toEqual(['ListBPA', 'PublicPing']);
  });

  it('blocked always wins over reviewed', () => {
    jest.isolateModules(() => {
      jest.doMock('../src/itsl/policy.js', () => ({
        ...jest.requireActual('../src/itsl/policy.js'),
        REVIEWED: { ExecGetRecoveryKey: 'read', ExecCPVRefresh: 'write', ListThing: 'read' },
      }));
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const t = require('../src/itsl/tier.js');
      expect(t.computeTier('ExecGetRecoveryKey', 'Endpoint.Device.Read')).toBe('blocked');
      expect(t.computeTier('ExecCPVRefresh', undefined)).toBe('blocked');
      expect(t.computeTier('ListThing', undefined)).toBe('read'); // control: the mock is in effect
    });
    jest.dontMock('../src/itsl/policy.js');
  });

  it('policy.ts holds every blocked name from the design', () => {
    const lower = new Set(BLOCKED_NAMES.map((n) => n.toLowerCase()));
    for (const name of MUST_BE_BLOCKED) expect(lower.has(name.toLowerCase())).toBe(true);
  });

  it('isCallable: read for everyone, write only for a write caller, blocked and disabled for no one', () => {
    expect(isCallable('read', 'read')).toBe(true);
    expect(isCallable('write', 'read')).toBe(false);
    expect(isCallable('write', 'write')).toBe(true);
    expect(isCallable('disabled', 'write')).toBe(false);
    expect(isCallable('blocked', 'write')).toBe(false);
  });

  it('mostRestrictive orders blocked > disabled > write > read', () => {
    expect(mostRestrictive(['read', 'write'])).toBe('write');
    expect(mostRestrictive(['write', 'disabled', 'read'])).toBe('disabled');
    expect(mostRestrictive(['disabled', 'blocked'])).toBe('blocked');
    expect(mostRestrictive([])).toBe('read');
  });
});

describe('projection and tiers over the fixture spec', () => {
  const cat = projectSpec(fixture, 'fixture');
  const tier = (n: string) => findEntry(cat, n)?.tier;

  it('gives the expected tier for each rule', () => {
    expect(tier('ListThings')).toBe('read');
    expect(tier('ListPairs')).toBe('read');
    expect(tier('ListGraphRequest')).toBe('read');
    expect(tier('GetVersion')).toBe('read');
    expect(tier('PublicPing')).toBe('read'); // reviewed
    expect(tier('ListMixed')).toBe('disabled');
    expect(tier('ListSneakyReadWrite')).toBe('disabled');
    expect(tier('AddTestReport')).toBe('disabled');
    expect(tier('RemoveThing')).toBe('disabled');
    expect(tier('ListNoRole')).toBe('disabled');
    expect(tier('ExecBaselineRun')).toBe('disabled');
    expect(tier('ExecDisableUser')).toBe('disabled');
    for (const n of SYNC_TRIGGERS) expect(tier(n)).toBe('write');
    for (const n of MUST_BE_BLOCKED) expect(tier(n)).toBe('blocked');
    for (const n of ['ListSuperThing', 'ListAppSettingThing', 'ListExtensionStatus', 'ExecAppSettingWrite', 'ExecBitlockerSearch', 'ListGraphBulkRequest']) {
      expect(tier(n)).toBe('blocked');
    }
  });

  it('guard: no ReadWrite endpoint computes to read', () => {
    for (const e of cat.entries.values()) {
      if (e.role && /ReadWrite$/i.test(e.role)) expect(e.tier).not.toBe('read');
    }
  });

  it('merges GET and POST into one entry: POST method, role is the most restrictive', () => {
    const pair = findEntry(cat, 'ListPairs')!;
    expect(pair.method).toBe('POST');
    expect(pair.queryParams).toEqual(['AllTenantSelector']);
    expect(Object.keys((pair.inputSchema.properties as object))).toEqual(['AllTenantSelector', 'filter']);
    expect(findEntry(cat, 'ListMixed')!.role).toBe('CIPP.Core.ReadWrite');
  });

  it('builds the input schema from parameters ($ref resolved) and request body', () => {
    const e = findEntry(cat, 'ExecCIPPDBCache')!;
    const props = e.inputSchema.properties as Record<string, { type?: string }>;
    expect(Object.keys(props).sort()).toEqual(['Name', 'Types', 'tenantFilter']);
    expect([...(e.inputSchema.required as string[])].sort()).toEqual(['Name', 'tenantFilter']);
    const things = findEntry(cat, 'ListThings')!;
    expect((things.inputSchema.properties as Record<string, { description?: string }>).userId?.description).toBe('A user id');
    expect(things.category).toBe('Identity > Administration > Users');
  });

  it('looks names up case-insensitively and returns the canonical name', () => {
    expect(findEntry(cat, 'execcippdbcache')!.name).toBe('ExecCIPPDBCache');
  });

  it('routes POST arguments: declared query params to the query, the rest to the body', () => {
    const e = findEntry(cat, 'ListPairs')!;
    expect(routeArguments(e, { AllTenantSelector: true, filter: 'x' })).toEqual({
      params: { AllTenantSelector: true },
      body: { filter: 'x' },
    });
    const g = findEntry(cat, 'ListThings')!;
    expect(routeArguments(g, { tenantFilter: 't', userId: 'u' })).toEqual({ params: { tenantFilter: 't', userId: 'u' }, body: undefined });
  });

  it('search never lists endpoints the caller cannot run', () => {
    const readView = searchEntries(cat, { limit: 100 }, (e) => isCallable(e.tier, 'read'));
    const names = readView.results.map((r) => r.name);
    expect(names).toContain('ListThings');
    for (const n of [...SYNC_TRIGGERS, ...MUST_BE_BLOCKED, 'ExecDisableUser', 'ListNoRole']) expect(names).not.toContain(n);
    const writeView = searchEntries(cat, { limit: 100 }, (e) => isCallable(e.tier, 'write'));
    const wnames = writeView.results.map((r) => r.name);
    expect(wnames).toContain('ExecCIPPDBCache');
    expect(wnames).not.toContain('ExecGetRecoveryKey');
    expect(wnames).not.toContain('ExecDisableUser');
    expect(searchEntries(cat, { query: 'things' }, () => true).results[0]!.name).toBe('ListThings');
  });

  it('unwraps a Results wrapper and a JSON string; rejects non-specs', () => {
    expect(unwrapSpec({ Results: fixture })).toBe(fixture);
    expect(unwrapSpec(JSON.stringify(fixture)).paths).toBeDefined();
    expect(() => unwrapSpec({ nope: 1 })).toThrow();
  });

  it('skips path keys that are not a bare function name', () => {
    const odd = projectSpec({ paths: { '/api/../Evil': { get: { 'x-cipp-role': 'A.Read' } }, '/api/Ok': { get: { 'x-cipp-role': 'A.Read' } } } });
    expect([...odd.entries.keys()]).toEqual(['ok']);
  });
});

describe('CatalogueStore', () => {
  const good = { name: 'good', fetch: async () => fixture };
  const bad = { name: 'bad', fetch: async () => { throw new Error('boom'); } };

  it('falls through to the next source', async () => {
    const store = new CatalogueStore();
    const cat = await store.get([bad, good], logger);
    expect(cat.source).toBe('good');
  });

  it('is lazy and caches for the TTL, then refreshes', async () => {
    let now = 1_000;
    const fetch = jest.fn(async () => fixture);
    const store = new CatalogueStore(1000, () => now);
    await store.get([{ name: 'f', fetch }], logger);
    await store.get([{ name: 'f', fetch }], logger);
    expect(fetch).toHaveBeenCalledTimes(1);
    now += 1001;
    await store.get([{ name: 'f', fetch }], logger);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('serves the last good copy when a refresh fails', async () => {
    let now = 1_000;
    const store = new CatalogueStore(1000, () => now);
    const first = await store.get([good], logger);
    now += 5000;
    const again = await store.get([bad], logger);
    expect(again).toBe(first);
  });

  it('throws a clear error when there is no copy and every source fails', async () => {
    const store = new CatalogueStore();
    await expect(store.get([bad], logger)).rejects.toThrow(/catalogue is unavailable.*Named cipp_\* tools still work/);
  });

  it('shares one in-flight fetch between concurrent callers', async () => {
    const fetch = jest.fn(async () => fixture);
    const store = new CatalogueStore();
    await Promise.all([store.get([{ name: 'f', fetch }], logger), store.get([{ name: 'f', fetch }], logger)]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('logs each endpoint new to a refresh once, with its tier', async () => {
    let now = 1_000;
    const info = jest.fn();
    const store = new CatalogueStore(1000, () => now);
    const log = { ...logger, info };
    await store.get([good], log);
    info.mockClear();
    now += 5000;
    const grown = { ...fixture, paths: { ...fixture.paths, '/api/ListBrandNew': { get: { 'x-cipp-role': 'Foo.Read' } }, '/api/ExecBrandNew': { post: { 'x-cipp-role': 'Foo.ReadWrite' } } } };
    await store.get([{ name: 'g', fetch: async () => grown }], log);
    const msgs = info.mock.calls.filter(([m]) => m === 'New CIPP endpoint').map(([, meta]) => meta);
    expect(msgs).toEqual([
      { name: 'ListBrandNew', role: 'Foo.Read', tier: 'read' },
      { name: 'ExecBrandNew', role: 'Foo.ReadWrite', tier: 'disabled' },
    ]);
  });
});
