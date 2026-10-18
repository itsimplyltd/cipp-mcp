// IT Simply Ltd: spec source 5, the commit in history whose version_latest.txt equals the reported version.

import fixture from './fixtures/openapi-fixture.json';
import { CatalogueStore, defaultSpecFetchers } from '../src/itsl/catalogue.js';

const REPO = 'KelvinTegelaar/CIPP-API';
const RAW = `https://raw.githubusercontent.com/${REPO}`;
const API = (branch: string) =>
  `https://api.github.com/repos/${REPO}/commits?path=version_latest.txt&sha=${branch}&per_page=30`;

type Route = string | object | number;

function setup(routes: Record<string, Route>, reported = '11.2.0') {
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

const commits = (...shas: string[]) => shas.map((sha) => ({ sha }));

describe('github-history-matching-version', () => {
  beforeEach(() => {
    delete process.env.ITSL_SPEC_BRANCHES;
  });

  it('matches on the 3rd commit and fetches the spec at that sha', async () => {
    const t = setup({
      [`${RAW}/master/version_latest.txt`]: '11.2.1',
      [`${RAW}/dev/version_latest.txt`]: '11.2.1',
      [API('master')]: commits('aaaaaaa1', 'bbbbbbb2', 'ccccccc3', 'ddddddd4'),
      [`${RAW}/aaaaaaa1/version_latest.txt`]: '11.2.1\n',
      [`${RAW}/bbbbbbb2/version_latest.txt`]: '11.2.1',
      [`${RAW}/ccccccc3/version_latest.txt`]: '11.2.0\n',
      [`${RAW}/ddddddd4/version_latest.txt`]: '11.2.0',
      [`${RAW}/ccccccc3/Config/openapi.json`]: fixture,
    });
    const cat = await t.get();
    expect(cat.source).toBe('github-history-matching-version');
    expect(t.calls).toContain(`${RAW}/ccccccc3/Config/openapi.json`);
    expect(t.calls).not.toContain(`${RAW}/ddddddd4/version_latest.txt`); // newest match wins, older not read
    expect(t.calls).not.toContain(API('dev')); // master matched, dev not consulted
    expect(t.logs.info).toHaveBeenCalledWith('CIPP catalogue loaded', expect.objectContaining({ version: '11.2.0' }));
  });

  it('no match anywhere -> clear error naming the version and each branch', async () => {
    const t = setup({
      [API('master')]: commits('aaaaaaa1'),
      [API('dev')]: commits('bbbbbbb2'),
      [`${RAW}/aaaaaaa1/version_latest.txt`]: '11.2.1',
      [`${RAW}/bbbbbbb2/version_latest.txt`]: '11.2.20',
      [`${RAW}/aaaaaaa1/Config/openapi.json`]: fixture,
      [`${RAW}/bbbbbbb2/Config/openapi.json`]: fixture,
    });
    await expect(t.get()).rejects.toThrow(
      /no commit history matches the reported CIPP version 11\.2\.0 \(master: no match in the last 1.*dev: no match in the last 1/
    );
    expect(t.calls.some((u) => u.endsWith('/Config/openapi.json') && !u.includes('/11.2.0/'))).toBe(false);
  });

  it('checks at most 30 commits per branch', async () => {
    const many = Array.from({ length: 45 }, (_, i) => `c${String(i).padStart(7, '0')}`);
    const routes: Record<string, Route> = { [API('master')]: commits(...many), [API('dev')]: [] };
    for (const sha of many) routes[`${RAW}/${sha}/version_latest.txt`] = '11.2.1';
    const t = setup(routes);
    await expect(t.get()).rejects.toThrow(/no commit history matches/);
    const shaReads = t.calls.filter((u) => u.endsWith('/version_latest.txt') && !u.includes('/master/') && !u.includes('/dev/'));
    expect(shaReads).toHaveLength(30);
  });

  it.each([403, 429])('a rate-limit %i is a source failure with a clear message', async (status) => {
    const t = setup({ [API('master')]: status, [API('dev')]: status });
    await expect(t.get()).rejects.toThrow(/github-history-matching-version: no commit history matches.*GitHub API rate limit \(HTTP \d+/);
  });

  it('is not called when the branch source succeeds', async () => {
    const t = setup({
      [`${RAW}/master/version_latest.txt`]: '11.2.0',
      [`${RAW}/master/Config/openapi.json`]: fixture,
    });
    const cat = await t.get();
    expect(cat.source).toBe('github-branch-matching-version');
    expect(t.calls.some((u) => u.startsWith('https://api.github.com/'))).toBe(false);
  });
});
