// IT Simply Ltd: the catalogue recovers without a restart, and a failed refresh keeps the current one.

import fixture from './fixtures/openapi-fixture.json';
import { CatalogueStore, CATALOGUE_RETRY_MS, CATALOGUE_TTL_MS, SpecFetcher } from '../src/itsl/catalogue.js';

const logs = () => ({ info: jest.fn(), warn: jest.fn(), debug: jest.fn() });
const tick = async (ms: number) => {
  await jest.advanceTimersByTimeAsync(ms);
};

describe('background recovery and refresh', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('retries every 10 minutes after a failed startup load until it succeeds', async () => {
    let up = false;
    const fetchSpec = jest.fn(async () => {
      if (!up) throw new Error('down');
      return fixture;
    });
    const fetchers: SpecFetcher[] = [{ name: 'src', fetch: fetchSpec }];
    const l = logs();
    const store = new CatalogueStore();
    await expect(store.get(fetchers, l)).rejects.toThrow(/unavailable/);
    expect(fetchSpec).toHaveBeenCalledTimes(1);

    // A request inside the retry window does not re-fetch.
    await expect(store.get(fetchers, l)).rejects.toThrow(/unavailable/);
    expect(fetchSpec).toHaveBeenCalledTimes(1);

    await tick(CATALOGUE_RETRY_MS);
    expect(fetchSpec).toHaveBeenCalledTimes(2);
    expect(store.peek()).toBeUndefined();
    expect(l.warn).toHaveBeenCalledWith('CIPP catalogue background load failed', expect.objectContaining({ haveCatalogue: false }));

    up = true;
    await tick(CATALOGUE_RETRY_MS);
    expect(fetchSpec).toHaveBeenCalledTimes(3);
    expect(store.peek()?.entries.size).toBeGreaterThan(0);
    store.reset();
  });

  it('refreshes every 6 hours once loaded, and a failed refresh keeps the current catalogue', async () => {
    let mode: 'ok' | 'fail' | 'empty' = 'ok';
    const fetchSpec = jest.fn(async () => {
      if (mode === 'fail') throw new Error('down');
      if (mode === 'empty') return { paths: {} };
      return fixture;
    });
    const fetchers: SpecFetcher[] = [{ name: 'src', fetch: fetchSpec }];
    const store = new CatalogueStore();
    const first = await store.get(fetchers, logs());
    expect(fetchSpec).toHaveBeenCalledTimes(1);

    mode = 'fail';
    await tick(CATALOGUE_TTL_MS);
    expect(fetchSpec).toHaveBeenCalledTimes(2);
    expect(store.peek()).toBe(first); // kept

    mode = 'empty'; // an unusable spec is also a failed load
    await tick(CATALOGUE_RETRY_MS);
    expect(fetchSpec).toHaveBeenCalledTimes(3);
    expect(store.peek()).toBe(first);

    mode = 'ok';
    await tick(CATALOGUE_RETRY_MS);
    expect(fetchSpec).toHaveBeenCalledTimes(4);
    expect(store.peek()).not.toBe(first); // replaced on success
    expect(store.peek()?.entries.size).toBe(first.entries.size);
    store.reset();
  });
});
