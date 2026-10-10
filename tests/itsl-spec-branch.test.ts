// Spec source 4: a branch whose version_latest.txt equals the reported CIPP version.

import fixture from './fixtures/openapi-fixture.json';
import { CatalogueStore, defaultSpecFetchers } from '../src/itsl/catalogue.js';

const REPO = 'KelvinTegelaar/CIPP-API';
const RAW = `https://raw.githubusercontent.com/${REPO}`;

function setup(routes: Record<string, string | object | number>, reported = '11.0.2') {
  const calls: string[] = [];
  const fetchImpl = jest.fn(async (url: string) => {
    calls.push(url);
    const r = routes[url];
    if (r === undefined || typeof r === 'number') {
      return { ok: false, status: typeof r === 'number' ? r : 404, text: async () => 'nope' } as unknown as Response;
    }
    const body = typeof r === 'string' ? r : JSON.stringify(r);
    return { ok: true, status: 200, text: async () => body } as unknown as Response;
  });
  const api = {
    callEndpoint: jest.fn(async (_m: string, path: string) => {
      if (path === 'GetVersion') return { LocalCIPPAPIVersion: reported };
      throw new Error('HTTP 404 for ListOpenApiSpec');
    }),
  };
  const logs = { info: jest.fn(), warn: jest.fn(), debug: jest.fn() };
  const store = new CatalogueStore();
  const get = () => store.get(defaultSpecFetchers(api as never, fetchImpl as unknown as typeof fetch), logs);
  return { calls, get, logs };
}

describe('github-branch-matching-version', () => {
  beforeEach(() => {
    delete process.env.ITSL_SPEC_BRANCHES;
  });

  it('tag 404 -> master matches -> success, using master', async () => {
    const t = setup({
      [`${RAW}/master/version_latest.txt`]: '11.0.2\n',
      [`${RAW}/master/Config/openapi.json`]: fixture,
    });
    const cat = await t.get();
    expect(cat.source).toBe('github-branch-matching-version');
    expect(t.calls).toContain(`${RAW}/11.0.2/Config/openapi.json`); // the tag was tried first and 404ed
    expect(t.calls).not.toContain(`${RAW}/dev/version_latest.txt`); // master matched, dev not consulted
    expect(t.logs.info).toHaveBeenCalledWith('CIPP catalogue loaded', expect.objectContaining({ source: 'github-branch-matching-version', version: '11.0.2' }));
  });

  it('master differs -> dev matches -> uses dev, never master', async () => {
    const t = setup({
      [`${RAW}/master/version_latest.txt`]: '10.9.1',
      [`${RAW}/dev/version_latest.txt`]: '11.0.2',
      [`${RAW}/dev/Config/openapi.json`]: fixture,
      [`${RAW}/master/Config/openapi.json`]: { paths: { '/api/Evil': { get: { 'x-cipp-role': 'A.Read' } } } },
    });
    const cat = await t.get();
    expect(cat.source).toBe('github-branch-matching-version');
    expect(t.calls).not.toContain(`${RAW}/master/Config/openapi.json`);
    expect(cat.entries.has('evil')).toBe(false);
  });

  it('no branch matches -> clear error naming the reported version and each branch version; nothing is fetched from a differing branch', async () => {
    const t = setup({
      [`${RAW}/master/version_latest.txt`]: '10.9.1',
      [`${RAW}/dev/version_latest.txt`]: '11.1.0',
      [`${RAW}/master/Config/openapi.json`]: fixture,
      [`${RAW}/dev/Config/openapi.json`]: fixture,
    });
    await expect(t.get()).rejects.toThrow(/no branch matches the reported CIPP version 11\.0\.2 \(master: 10\.9\.1; dev: 11\.1\.0\)/);
    expect(t.calls.some((u) => u.endsWith('/Config/openapi.json') && !u.includes('/11.0.2/'))).toBe(false);
  });

  it('requires an EXACT match (no prefix or suffix tolerance)', async () => {
    const t = setup({ [`${RAW}/master/version_latest.txt`]: '11.0.20', [`${RAW}/dev/version_latest.txt`]: '11.0' });
    await expect(t.get()).rejects.toThrow(/no branch matches/);
  });

  it('ITSL_SPEC_BRANCHES overrides the branch list', async () => {
    process.env.ITSL_SPEC_BRANCHES = 'release, dev';
    const t = setup({
      [`${RAW}/release/version_latest.txt`]: 500 as never,
      [`${RAW}/dev/version_latest.txt`]: '11.0.2',
      [`${RAW}/dev/Config/openapi.json`]: fixture,
    });
    await t.get();
    expect(t.calls).toContain(`${RAW}/release/version_latest.txt`);
    expect(t.calls).not.toContain(`${RAW}/master/version_latest.txt`);
  });

  it('every failed source is logged at WARN with its name and error (not debug)', async () => {
    const t = setup({ [`${RAW}/master/version_latest.txt`]: '11.0.2', [`${RAW}/master/Config/openapi.json`]: fixture });
    await t.get();
    const sources = t.logs.warn.mock.calls.filter(([m]) => m === 'CIPP spec source failed').map(([, meta]) => (meta as { source: string }).source);
    expect(sources).toEqual(['cipp-api', 'github-release-asset', 'github-tag-file']);
    for (const [, meta] of t.logs.warn.mock.calls) expect(typeof (meta as { error: string }).error).toBe('string');
    expect(t.logs.debug).not.toHaveBeenCalledWith('CIPP spec source failed', expect.anything());
  });
});
