// IT Simply Ltd: the catalogue loads on the request path with the CURRENT caller's fetchers (their token is
// fresh), never from a background timer, and a failed refresh keeps the current catalogue.

import fixture from './fixtures/openapi-fixture.json';
import { CatalogueStore, CATALOGUE_TTL_MS, defaultSpecFetchers, SpecFetcher } from '../src/itsl/catalogue.js';

const BACKOFF = 5 * 60 * 1000; // FAILURE_BACKOFF_MS
const logs = () => ({ info: jest.fn(), warn: jest.fn(), debug: jest.fn() });

function harness() {
  let now = 1_000_000;
  const store = new CatalogueStore(CATALOGUE_TTL_MS, () => now);
  const advance = (ms: number) => {
    now += ms;
  };
  return { store, advance };
}

const okFetcher = (name = 'src', spec: unknown = fixture) => {
  const fetch = jest.fn(async () => spec);
  return { fetcher: { name, fetch } as SpecFetcher, fetch };
};
const failFetcher = (name = 'src', message = 'down') => {
  const fetch = jest.fn(async () => {
    throw new Error(message);
  });
  return { fetcher: { name, fetch } as SpecFetcher, fetch };
};

describe('request-path refresh', () => {
  it('never schedules a timer', async () => {
    const setTimeoutSpy = jest.spyOn(global, 'setTimeout');
    const setIntervalSpy = jest.spyOn(global, 'setInterval');
    try {
      const { store } = harness();
      await store.get([okFetcher().fetcher], logs());
      await expect(new CatalogueStore().get([failFetcher().fetcher], logs())).rejects.toThrow(/unavailable/);
      expect(setTimeoutSpy).not.toHaveBeenCalled();
      expect(setIntervalSpy).not.toHaveBeenCalled();
    } finally {
      setTimeoutSpy.mockRestore();
      setIntervalSpy.mockRestore();
    }
  });

  it('serves a fresh catalogue without fetching', async () => {
    const { store, advance } = harness();
    const a = okFetcher();
    const first = await store.get([a.fetcher], logs());
    advance(CATALOGUE_TTL_MS - 1);
    const b = okFetcher();
    expect(await store.get([b.fetcher], logs())).toBe(first);
    expect(a.fetch).toHaveBeenCalledTimes(1);
    expect(b.fetch).not.toHaveBeenCalled();
  });

  it('after the TTL, reloads with the fetchers of the request that triggered it, not the first caller', async () => {
    const { store, advance } = harness();
    const first = okFetcher('first-caller');
    const cat1 = await store.get([first.fetcher], logs());
    advance(CATALOGUE_TTL_MS + 1);
    const second = okFetcher('second-caller');
    const cat2 = await store.get([second.fetcher], logs());
    expect(second.fetch).toHaveBeenCalledTimes(1);
    expect(first.fetch).toHaveBeenCalledTimes(1); // the first caller's fetchers are never reused
    expect(cat2).not.toBe(cat1);
    expect(cat2.source).toBe('second-caller');
  });

  it('shares one in-flight load between concurrent callers', async () => {
    const { store } = harness();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const fetch = jest.fn(async () => {
      await gate;
      return fixture;
    });
    const p1 = store.get([{ name: 's', fetch }], logs());
    const p2 = store.get([{ name: 's', fetch }], logs());
    release();
    expect(await p1).toBe(await p2);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('with no catalogue and a failed load, repeats the last error inside the back-off without fetching, and retries after it', async () => {
    const { store, advance } = harness();
    const down = failFetcher();
    await expect(store.get([down.fetcher], logs())).rejects.toThrow(/unavailable/);
    expect(down.fetch).toHaveBeenCalledTimes(1);

    advance(BACKOFF - 1);
    const stillDown = failFetcher();
    await expect(store.get([stillDown.fetcher], logs())).rejects.toThrow(/unavailable/);
    expect(stillDown.fetch).not.toHaveBeenCalled();

    advance(2);
    const up = okFetcher();
    const cat = await store.get([up.fetcher], logs());
    expect(up.fetch).toHaveBeenCalledTimes(1);
    expect(cat.entries.size).toBeGreaterThan(0);
  });

  it('with a stale catalogue and a failed refresh, serves the stale copy, does not fetch inside the back-off, then retries', async () => {
    const { store, advance } = harness();
    const first = await store.get([okFetcher().fetcher], logs());

    advance(CATALOGUE_TTL_MS + 1);
    const down = failFetcher();
    const l = logs();
    expect(await store.get([down.fetcher], l)).toBe(first);
    expect(down.fetch).toHaveBeenCalledTimes(1);
    expect(l.warn).toHaveBeenCalledWith('CIPP spec refresh failed; serving the last good catalogue', expect.anything());
    expect(store.peek()).toBe(first); // a failed refresh never replaces a good catalogue

    advance(BACKOFF - 1);
    const again = failFetcher();
    expect(await store.get([again.fetcher], logs())).toBe(first);
    expect(again.fetch).not.toHaveBeenCalled();

    advance(2);
    const up = okFetcher();
    const refreshed = await store.get([up.fetcher], logs());
    expect(up.fetch).toHaveBeenCalledTimes(1);
    expect(refreshed).not.toBe(first);
    expect(store.peek()).toBe(refreshed);
  });

  it('an unusable (empty) spec is a failed load and keeps the current catalogue', async () => {
    const { store, advance } = harness();
    const first = await store.get([okFetcher().fetcher], logs());
    advance(CATALOGUE_TTL_MS + 1);
    expect(await store.get([okFetcher('empty', { paths: {} }).fetcher], logs())).toBe(first);
    expect(store.peek()).toBe(first);
  });
});

describe('default spec sources', () => {
  const api = () => ({ callEndpoint: jest.fn(async () => ({ LocalCIPPAPIVersion: '11.0.2' })) });
  const okFetch = () =>
    jest.fn(async () => ({ ok: true, status: 200, text: async () => JSON.stringify(fixture) }) as unknown as Response);

  it('are the three GitHub sources only: no cipp-api, no release asset', () => {
    const names = defaultSpecFetchers(api() as never, jest.fn() as never).map((f) => f.name);
    expect(names).toEqual(['github-tag-file', 'github-branch-matching-version', 'github-history-matching-version']);
    expect(names).not.toContain('cipp-api');
    expect(names).not.toContain('github-release-asset');
  });

  it('github-tag-file names the tag it resolved in the loaded log line', async () => {
    const l = logs();
    await new CatalogueStore().get(defaultSpecFetchers(api() as never, okFetch() as never), l);
    expect(l.info).toHaveBeenCalledWith(
      'CIPP catalogue loaded',
      expect.objectContaining({ source: 'github-tag-file', version: '11.0.2' })
    );
  });

  it('GetVersion is called again by a load after the TTL (fetchers are built per request, so the memo cannot go stale)', async () => {
    const { store, advance } = harness();
    const a = api();
    await store.get(defaultSpecFetchers(a as never, okFetch() as never), logs());
    expect(a.callEndpoint).toHaveBeenCalledTimes(1);
    advance(CATALOGUE_TTL_MS + 1);
    await store.get(defaultSpecFetchers(a as never, okFetch() as never), logs());
    expect(a.callEndpoint).toHaveBeenCalledTimes(2);
  });
});
