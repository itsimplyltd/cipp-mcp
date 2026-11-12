/**
 * The vendored S2S v3 verifier must stay byte-identical to the canonical copy,
 * and must pass the shared vectors. Port of MCP-Gateway s2s/s2s-v3.test.ts.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { join } from 'node:path';
import {
  INGRESS_EXEMPT_HEADERS,
  NonceCache,
  RawBodyError,
  ReportRateLimiter,
  canonicalV3,
  checkGatewayRequest,
  handleGatewayRequest,
  formatUnsignedHeaderReport,
  parseV3Header,
  readRawBody,
  respondAndClose,
  stripExemptHeaders,
  verifyV3,
  assertRequireSignedHeaders,
} from '../src/itsl/s2s-v3.js';

// sha256 of itsimplyltd/MCP-Gateway s2s/s2s-v3.ts at commit f88a2e3 (branch feat/s2s-v3-cipp, PR 54).
// Changing the vendored file means re-vendoring the canonical copy, never editing it here.
const CANONICAL_S2S_V3_SHA256 = '2242015a1df00772b695dddb1a49bee4af36cf139672a40d329394fed3a95374';

describe('vendored verifier pin', () => {
  it('src/itsl/s2s-v3.ts is byte-identical to the canonical copy', () => {
    const bytes = readFileSync(join(__dirname, '..', 'src', 'itsl', 's2s-v3.ts'));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(CANONICAL_S2S_V3_SHA256);
  });
});

/* eslint-disable @typescript-eslint/no-explicit-any */
const vectors = JSON.parse(readFileSync(join(__dirname, 'fixtures', 's2s-v3-vectors.json'), 'utf8'));
const secret: string = vectors.secret;
const rejection = async (p: Promise<unknown>): Promise<unknown> => {
  try { await p; } catch (e) { return e; }
  throw new Error('expected a rejection');
};

function args(c: any, cache: NonceCache) {
  return {
    method: c.method,
    rawTarget: c.rawTarget,
    body: Buffer.from(c.body, 'utf8'),
    rawHeaders: c.rawHeaders,
    secret: c.secretOverride ?? secret,
    aud: c.aud,
    nowSeconds: c.nowSeconds,
    nonceCache: cache,
    headerRuleMode: c.headerRuleMode,
  };
}

describe('shared vectors', () => {
  for (const c of vectors.positive) {
    it(`positive: ${c.name}`, () => {
      expect(verifyV3(args(c, new NonceCache()))).toEqual({ ok: true, version: 3 });
    });
    if (!c.derivedFrom) {
      it(`positive canonical string is pinned: ${c.name}`, () => {
        const parsed = parseV3Header(c.header)!;
        const headerHashes: Record<string, string> = {};
        for (const [k, v] of Object.entries(c.signedHeaders)) headerHashes[k] = createHash('sha256').update(v as string).digest('hex');
        const canonical = canonicalV3({
          t: parsed.tRaw, n: parsed.n, aud: c.aud, method: c.method, path: c.rawTarget,
          bodySha256: createHash('sha256').update(c.body).digest('hex'), sh: parsed.sh, headerHashes,
        });
        expect(canonical).toBe(c.canonical);
        expect(canonical.endsWith('\n')).toBe(false);
        expect(canonical.split('\n')[0]).toBe('ITSL-S2S-v3');
      });
    }
  }

  for (const c of vectors.negative) {
    it(`negative: ${c.name} -> ${c.expect}`, () => {
      const cache = new NonceCache();
      if (c.replayOf) {
        const first = vectors.positive.find((p: any) => p.name === c.replayOf);
        expect(verifyV3(args(first, cache)).ok).toBe(true);
      }
      expect(verifyV3(args(c, cache))).toEqual({ ok: false, reason: c.expect });
    });
  }

  for (const c of vectors.check) {
    it(`checkGatewayRequest: ${c.name}`, () => {
      const r = checkGatewayRequest({
        ...args(c, new NonceCache()),
        floor: c.floor,
        minVersion: c.minVersion,
        verifyLegacy: () => c.legacyResult ?? 0,
      });
      expect(r.ok).toBe(c.expect.ok);
      expect(r.version).toBe(c.expect.version);
      if (!c.expect.ok) expect(r.reason).toBe(c.expect.reason);
      expect((r as { unsignedHeaderNames?: string[] }).unsignedHeaderNames).toEqual(c.expect.unsignedHeaderNames);
    });
  }

  for (const c of vectors.readRawBody) {
    it(`readRawBody: ${c.name}`, async () => {
      const req = Object.assign(Readable.from([Buffer.from(c.body)]), { headers: c.headers }) as unknown as IncomingMessage;
      if (c.expectStatus) {
        const e: any = await rejection(readRawBody(req));
        expect(e instanceof RawBodyError && e.status === c.expectStatus).toBe(true);
      } else {
        expect((await readRawBody(req)).toString()).toBe(c.body);
      }
    });
  }
});

describe('verifier behaviour', () => {
  it('readRawBody: over the limit is a 413 whether declared or streamed', async () => {
    const declared = Object.assign(Readable.from([Buffer.alloc(10)]), { headers: { 'content-length': '10' } }) as unknown as IncomingMessage;
    expect(((await rejection(readRawBody(declared, 5))) as any).status).toBe(413);
    const streamed = Object.assign(Readable.from([Buffer.alloc(4), Buffer.alloc(4)]), { headers: {} }) as unknown as IncomingMessage;
    expect(((await rejection(readRawBody(streamed, 5))) as any).status).toBe(413);
  });

  it('nonce is recorded only after the HMAC verifies', () => {
    const cache = new NonceCache();
    const c = vectors.positive[1];
    const bad = { ...c, body: c.body + ' ' };
    expect(verifyV3(args(bad, cache)).ok).toBe(false);
    expect(cache.entries.size).toBe(0);
    expect(verifyV3(args(c, cache)).ok).toBe(true);
    expect(cache.entries.size).toBe(1);
  });

  it('nonce entry lives until its own t + 30 + 5 and then the same nonce is no longer a replay', () => {
    const cache = new NonceCache();
    const n = '0'.repeat(32);
    cache.add(n, 1000, 1000);
    expect(cache.has(n, 1034)).toBe(true);
    expect(cache.has(n, 1035)).toBe(false);
  });

  it('a full nonce cache refuses new requests (fails closed) but frees expired entries', () => {
    const cache = new NonceCache(2);
    const c = vectors.positive[0];
    cache.add('a'.repeat(32), c.t, c.t);
    cache.add('b'.repeat(32), c.t, c.t);
    expect(verifyV3(args(c, cache))).toEqual({ ok: false, reason: 'nonce-cache-full' });
    expect(verifyV3({ ...args(c, cache), nowSeconds: c.t + 30 }).ok).toBe(false);
    const later = new NonceCache(2);
    later.add('a'.repeat(32), c.t - 100, c.t);
    later.add('b'.repeat(32), c.t - 100, c.t);
    expect(verifyV3(args(c, later)).ok).toBe(true);
  });

  it('the wrong secret never verifies', () => {
    const c = vectors.positive[0];
    expect(verifyV3({ ...args(c, new NonceCache()), secret: 'vector-s2s-anothersecret0123456789abcdef' })).toEqual({ ok: false, reason: 'hmac' });
  });

  it('x-request-id present and unsigned verifies, and is not in sh', () => {
    const c = vectors.positive[1];
    expect(c.rawHeaders.some((h: string) => h.toLowerCase() === 'x-request-id')).toBe(true);
    expect(c.header.includes('x-request-id')).toBe(false);
    expect(verifyV3(args(c, new NonceCache()))).toEqual({ ok: true, version: 3 });
    expect(INGRESS_EXEMPT_HEADERS).toEqual(['x-request-id']);
  });

  it('a request refused by the header rule does not consume a nonce or a slot', () => {
    const cache = new NonceCache(1);
    const c = vectors.positive[1];
    const bad = { ...c, rawHeaders: [...c.rawHeaders, 'X-Api-Url', 'https://attacker.invalid'] };
    expect(verifyV3(args(bad, cache))).toEqual({ ok: false, reason: 'unsigned-header' });
    expect(cache.entries.size).toBe(0);
    expect(verifyV3(args(c, cache)).ok).toBe(true);
  });

  it('report mode accepts and consumes the nonce, listing names; exempt names are never listed', () => {
    const cache = new NonceCache();
    const c = vectors.positive[1];
    const r = verifyV3({ ...args(c, cache), headerRuleMode: 'report', rawHeaders: [...c.rawHeaders, 'X-Forwarded-For', '1.2.3.4'] });
    expect(r).toEqual({ ok: true, version: 3, unsignedHeaderNames: ['x-forwarded-for'] });
    expect(cache.entries.size).toBe(1);
  });

  it('stripExemptHeaders removes exempt names from headers and rawHeaders, case-insensitively, and nothing else', () => {
    const req = {
      headers: { host: 'h', 'x-request-id': 'a', 'x-keep': 'k' } as Record<string, unknown>,
      rawHeaders: ['Host', 'h', 'X-Request-Id', 'a', 'X-Keep', 'k', 'x-request-id', 'b'],
    };
    const sameArray = req.rawHeaders;
    stripExemptHeaders(req);
    expect(req.headers).toEqual({ host: 'h', 'x-keep': 'k' });
    expect(req.rawHeaders).toEqual(['Host', 'h', 'X-Keep', 'k']);
    expect(req.rawHeaders).toBe(sameArray);
  });

  it('formatUnsignedHeaderReport sanitises: lower-case, max 20, bad names replaced', () => {
    expect(formatUnsignedHeaderReport(['X-Foo', 'x-bar'])).toEqual(['x-bar', 'x-foo']);
    expect(formatUnsignedHeaderReport(['x-a b', 'x'.repeat(65), 'x-é'])).toEqual(['invalid-name', 'invalid-name', 'invalid-name']);
    expect(formatUnsignedHeaderReport(Array.from({ length: 30 }, (_, i) => 'x-h' + i))).toHaveLength(20);
  });

  it('ReportRateLimiter: one emit per distinct name-set per 60 s, bounded memory', () => {
    const l = new ReportRateLimiter(3, 60);
    expect(l.shouldEmit(['b', 'a'], 100)).toBe(true);
    expect(l.shouldEmit(['a', 'b'], 120)).toBe(false);
    expect(l.shouldEmit(['a'], 120)).toBe(true);
    expect(l.shouldEmit(['a', 'b'], 160)).toBe(true);
    for (let i = 0; i < 50; i++) l.shouldEmit(['x-' + i], 200);
    expect(l.last.size).toBeLessThanOrEqual(3);
  });

  it('respondAndClose answers with Connection: close and destroys the request', async () => {
    const server = createServer((_req, res) => respondAndClose(res, 413, '{"error":"too_large"}'));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as { port: number }).port;
    const got = await new Promise<{ status: number; connection: string; body: string }>((resolve, reject) => {
      const rq = httpRequest({ host: '127.0.0.1', port, method: 'POST', agent: false }, (res) => {
        let b = '';
        res.on('data', (d) => (b += d));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, connection: String(res.headers.connection), body: b }));
      });
      rq.on('error', reject);
      rq.write('x');
      rq.end();
    });
    server.close();
    expect(got).toEqual({ status: 413, connection: 'close', body: '{"error":"too_large"}' });
  });
});

describe('handleGatewayRequest without a secret', () => {
  async function serve(allowUnauthenticated?: boolean) {
    const reached: number[] = [];
    const server = createServer((req, res) => {
      void handleGatewayRequest(
        req,
        res,
        {
          secret: undefined,
          aud: 'saas-alerts',
          floor: 1,
          minVersion: 1,
          nonceCache: new NonceCache(),
          reportLimiter: new ReportRateLimiter(),
          failureLimiter: new ReportRateLimiter(),
          logger: { warn: () => {}, error: () => {} },
          allowUnauthenticated,
        },
        (v) => {
          reached.push(v.version);
          res.end('ok');
        },
      );
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as { port: number }).port;
    const post = () =>
      new Promise<number>((resolve, reject) => {
        const rq = httpRequest({ host: '127.0.0.1', port, method: 'POST', path: '/mcp', agent: false }, (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode ?? 0));
        });
        rq.on('error', reject);
        rq.end('{}');
      });
    return { reached, post, close: () => new Promise<void>((r) => server.close(() => r())) };
  }

  it('refuses with 500 and never reaches the handler when the dev flag is absent', async () => {
    const s = await serve();
    expect(await s.post()).toBe(500);
    expect(s.reached).toEqual([]);
    await s.close();
  });

  it('serves only when allowUnauthenticated is true', async () => {
    const s = await serve(true);
    expect(await s.post()).toBe(200);
    expect(s.reached).toEqual([0]);
    await s.close();
  });
});

describe('requireSignedHeaders vectors', () => {
  for (const c of vectors.requireSigned) {
    it(`requireSigned: ${c.name}`, () => {
      const base = vectors.positive.find((p: any) => p.name === c.from);
      const rawHeaders = [...base.rawHeaders, ...(c.extraRawHeaders ?? [])];
      const r: any = verifyV3({ ...args(base, new NonceCache()), rawHeaders, headerRuleMode: c.headerRuleMode, requireSignedHeaders: c.requireSignedHeaders });
      expect(r.ok).toBe(c.expect.ok);
      if (!r.ok) expect(r.reason).toBe(c.expect.reason);
    });
  }

  it('invalid or exempt names throw at configuration time', () => {
    for (const list of vectors.requireSignedConfigErrors) expect(() => assertRequireSignedHeaders(list)).toThrow(/requireSignedHeaders/);
    expect(() => assertRequireSignedHeaders(['x-mcp-tier', 'x-user-token'])).not.toThrow();
  });
});
