// S2S v2 + v3 at the HTTP boundary of the real server: floor 2, v1 never accepted,
// identity headers bound by the v3 signature, boot checks, routing.

// tenantFilter canonicalisation has its own suite; here it is a passthrough.
jest.mock('../src/itsl/tenant.js', () => ({
  canonicaliseTenantArgs: async (args: Record<string, unknown>) => ({ ok: true, args }),
}));

import { connect } from 'node:net';
import fixture from './fixtures/openapi-fixture.json';
import { signV1, signV2, signV3, encodeUser } from './s2s-v3-signer.js';
import type { CippMcpServer as CippMcpServerType } from '../src/mcp/server.js';

const SECRET = 'test-s2s-v3-http-secret-do-not-use-in-prod';
const HOST = '127.0.0.1';
const PORT = 47534;
const TOKEN = 'eyJ.user-token-for-v3-http-tests.sig';
const BASE = 'https://cipp.example';
const ENV_KEYS = [
  'CONDUIT_S2S_SECRET', 'ITSL_REQUIRE_S2S_V2', 'ITSL_REQUIRE_USER_TOKEN', 'ITSL_S2S_MIN_VERSION',
  'AUTH_MODE', 'MCP_TRANSPORT', 'MCP_HTTP_PORT', 'MCP_HTTP_HOST',
];

describe('S2S v2 + v3 at the HTTP boundary (floor 2)', () => {
  let CippMcpServer: typeof CippMcpServerType;
  let loadEnvironmentConfig: () => never;
  let mergeWithMcpConfig: (e: never) => never;
  let server: InstanceType<typeof CippMcpServerType>;
  let realFetch: typeof fetch;
  let store: { reset(): void };
  let upstreamCalls: Array<{ url: string; init?: RequestInit }>;
  const logs: Array<{ level: string; line: string }> = [];
  const logger = {
    debug: (...a: unknown[]) => logs.push({ level: 'debug', line: JSON.stringify(a) }),
    info: (...a: unknown[]) => logs.push({ level: 'info', line: JSON.stringify(a) }),
    warn: (...a: unknown[]) => logs.push({ level: 'warn', line: JSON.stringify(a) }),
    error: (...a: unknown[]) => logs.push({ level: 'error', line: JSON.stringify(a) }),
  };

  const listTools = { jsonrpc: '2.0', method: 'tools/list', id: 1 };
  const callTool = (name: string, args: Record<string, unknown> = {}) => ({ jsonrpc: '2.0', method: 'tools/call', params: { name, arguments: args }, id: 2 });

  const rawPost = (headers: Record<string, string>, body: unknown, path = '/mcp') =>
    realFetch(`http://${HOST}:${PORT}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers },
      body: JSON.stringify(body),
    });

  /** v2 headers exactly as the gateway sends them. */
  const v2 = (tier: 'read' | 'write', upn = 'u@example.com', token = TOKEN) => ({
    'x-gateway-s2s': signV2(SECRET, { tier, upn, userToken: token }),
    'x-mcp-tier': tier,
    'x-mcp-user': encodeUser(upn),
    'x-user-token': token,
    'x-base-url': BASE,
  });

  /** v3 headers as the gateway sends them: every identity header present is signed. */
  const v3 = (
    body: unknown,
    signed: Record<string, string>,
    extra: Record<string, string> = {},
    over: { secret?: string; n?: string } = {}
  ) => ({
    'x-gateway-s2s': signV3(over.secret ?? SECRET, { aud: 'cipp', method: 'POST', path: '/mcp', body: JSON.stringify(body), headers: signed, ...(over.n ? { n: over.n } : {}) }),
    ...signed,
    ...extra,
  });
  const identity = (tier: 'read' | 'write', upn = 'u@example.com') => ({
    'x-mcp-tier': tier,
    'x-mcp-user': encodeUser(upn),
    'x-user-token': TOKEN,
    'x-base-url': BASE,
  });

  const toolNames = async (headers: Record<string, string>): Promise<string[]> => {
    const res = await rawPost(headers, listTools);
    expect(res.status).toBe(200);
    return ((await res.json()) as { result: { tools: Array<{ name: string }> } }).result.tools.map((t) => t.name);
  };

  const setMin = (v: string | undefined) => {
    if (v === undefined) delete process.env.ITSL_S2S_MIN_VERSION;
    else process.env.ITSL_S2S_MIN_VERSION = v;
  };

  const makeServer = () => {
    const envConfig = loadEnvironmentConfig();
    return new CippMcpServer(mergeWithMcpConfig(envConfig), logger as never, envConfig as never);
  };

  beforeAll(async () => {
    Object.assign(process.env, {
      CONDUIT_S2S_SECRET: SECRET,
      ITSL_REQUIRE_USER_TOKEN: 'true',
      AUTH_MODE: 'gateway',
      MCP_TRANSPORT: 'http',
      MCP_HTTP_PORT: String(PORT),
      MCP_HTTP_HOST: HOST,
    });
    realFetch = global.fetch;
    jest.resetModules();
    /* eslint-disable @typescript-eslint/no-require-imports */
    ({ CippMcpServer } = require('../src/mcp/server.js'));
    ({ catalogueStore: store } = require('../src/itsl/catalogue.js'));
    ({ loadEnvironmentConfig, mergeWithMcpConfig } = require('../src/utils/config.js'));
    /* eslint-enable @typescript-eslint/no-require-imports */
    server = makeServer();
    await server.start();
  }, 20000);

  afterAll(async () => {
    await server.stop();
    for (const k of ENV_KEYS) delete process.env[k];
  });

  beforeEach(() => {
    store.reset();
    upstreamCalls = [];
    logs.length = 0;
    setMin(undefined);
    process.env.ITSL_REQUIRE_USER_TOKEN = 'true';
    global.fetch = jest.fn((input: string, init?: RequestInit) => {
      if (String(input).startsWith(`http://${HOST}:${PORT}`)) return realFetch(input, init);
      upstreamCalls.push({ url: String(input), ...(init ? { init } : {}) });
      const payload = String(input).includes('/api/ListOpenApiSpec') ? fixture : { ok: true };
      const s = JSON.stringify(payload);
      return Promise.resolve({ ok: true, status: 200, text: async () => s, json: async () => payload } as unknown as Response);
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    global.fetch = realFetch;
  });

  describe('versions', () => {
    it('v2 is accepted at the default minimum (2)', async () => {
      expect((await rawPost(v2('read'), listTools)).status).toBe(200);
    });

    it('v1 is refused at every minimum, including ITSL_S2S_MIN_VERSION=1', async () => {
      const base = { 'x-user-token': TOKEN, 'x-base-url': BASE, 'x-mcp-tier': 'write', 'x-mcp-user': 'attacker@example.com' };
      for (const min of [undefined, '1', '2', '3', 'garbage', '0']) {
        setMin(min);
        const res = await rawPost({ ...base, 'x-gateway-s2s': signV1(SECRET) }, listTools);
        expect(res.status).toBe(401);
      }
      expect(upstreamCalls).toEqual([]);
    });

    it('v3 is accepted', async () => {
      expect((await rawPost(v3(listTools, identity('read')), listTools)).status).toBe(200);
    });

    it('v2 is refused once the minimum is 3, v3 still passes', async () => {
      setMin('3');
      expect((await rawPost(v2('write'), listTools)).status).toBe(401);
      expect((await rawPost(v3(listTools, identity('read')), listTools)).status).toBe(200);
    });

    it('a replayed v3 request is refused', async () => {
      const h = v3(listTools, identity('read'), {}, { n: 'ab'.repeat(16) });
      expect((await rawPost(h, listTools)).status).toBe(200);
      expect((await rawPost(h, listTools)).status).toBe(401);
    });

    it('a v3 signed for another audience or with the wrong secret is refused', async () => {
      expect((await rawPost(v3(listTools, identity('read'), {}, { secret: 'wrong-secret-must-not-verify-at-all-12' }), listTools)).status).toBe(401);
      const wrongAud = { 'x-gateway-s2s': signV3(SECRET, { aud: 'other', method: 'POST', path: '/mcp', body: JSON.stringify(listTools), headers: identity('read') }), ...identity('read') };
      expect((await rawPost(wrongAud, listTools)).status).toBe(401);
    });
  });

  describe('v3 binds the identity headers (report mode, minimum 2)', () => {
    it('an unsigned x-mcp-tier alongside a valid v3 is refused', async () => {
      const { 'x-mcp-tier': _tier, ...rest } = identity('read');
      void _tier;
      const h = v3(listTools, rest, { 'x-mcp-tier': 'write' });
      expect((await rawPost(h, listTools)).status).toBe(401);
      expect(upstreamCalls).toEqual([]);
      expect(logs.some((l) => l.level === 'warn' && l.line.includes('unsigned-required-header'))).toBe(true);
    });

    it.each(['x-mcp-user', 'x-user-token', 'x-base-url', 'x-api-key', 'x-tenant-id', 'x-client-id', 'x-client-secret', 'x-token-scope', 'x-token-scope-fallback', 'x-token-url'])(
      'an unsigned %s is refused',
      async (name) => {
        const signed = identity('read') as Record<string, string>;
        delete signed[name];
        const h = v3(listTools, signed, { [name]: 'injected' });
        expect((await rawPost(h, listTools)).status).toBe(401);
      }
    );

    it('a signed x-mcp-tier is honoured: write sees the write tools, read does not', async () => {
      const read = await toolNames(v3(listTools, identity('read')));
      const write = await toolNames(v3(listTools, identity('write')));
      for (const w of ['cipp_exec_write', 'cipp_disable_enterprise_app', 'cipp_enable_enterprise_app']) {
        expect(read).not.toContain(w);
        expect(write).toContain(w);
      }
    });

    it('write-tier exec over v3 reaches CIPP with the signed user token as the bearer', async () => {
      const body = callTool('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'SharePointSharingLinks', tenantFilter: 'aviva.org.nz' } });
      const res = await rawPost(v3(body, identity('write')), body);
      expect(res.status).toBe(200);
      const call = upstreamCalls.find((c) => c.url.includes('/api/ExecCIPPDBCache'))!;
      expect((call.init?.headers as Record<string, string>).Authorization).toBe(`Bearer ${TOKEN}`);
    });

    it('a tampered body is refused', async () => {
      const h = v3(listTools, identity('write'));
      expect((await rawPost(h, { ...listTools, id: 99 })).status).toBe(401);
    });
  });

  describe('absence is safe on a v3 request', () => {
    it('no x-mcp-tier means the read tier, never write', async () => {
      const { 'x-mcp-tier': _tier, ...rest } = identity('write');
      void _tier;
      const names = await toolNames(v3(listTools, rest));
      expect(names).not.toContain('cipp_exec_write');
      const body = callTool('cipp_exec_write', { name: 'ExecCIPPDBCache', arguments: { Name: 'SharePointSharingLinks', tenantFilter: 'aviva.org.nz' } });
      const res = await rawPost(v3(body, rest), body);
      const parsed = (await res.json()) as { result: { isError: boolean } };
      expect(parsed.result.isError).toBe(true);
      expect(upstreamCalls.some((c) => c.url.includes('/api/ExecCIPPDBCache'))).toBe(false);
    });

    it('an unrecognised signed tier value is read, never write', async () => {
      const names = await toolNames(v3(listTools, { ...identity('read'), 'x-mcp-tier': 'admin' }));
      expect(names).not.toContain('cipp_exec_write');
    });

    it('no x-user-token is refused while ITSL_REQUIRE_USER_TOKEN is on, even with client credentials', async () => {
      const { 'x-user-token': _t, ...rest } = identity('write');
      void _t;
      const h = v3(listTools, { ...rest, 'x-tenant-id': 'a', 'x-client-id': 'b', 'x-client-secret': 'c', 'x-api-key': 'd' });
      expect((await rawPost(h, listTools)).status).toBe(401);
      expect(upstreamCalls).toEqual([]);
    });

    it('no x-base-url is refused: no fallback exists that a caller can influence', async () => {
      const { 'x-base-url': _b, ...rest } = identity('write');
      void _b;
      expect((await rawPost(v3(listTools, rest), listTools)).status).toBe(401);
      process.env.ITSL_REQUIRE_USER_TOKEN = 'false';
      expect((await rawPost(v3(listTools, rest), listTools)).status).toBe(401);
      expect(upstreamCalls).toEqual([]);
    });
  });

  describe('v2 behaves as it did before', () => {
    it('refuses a flipped tier header, a swapped token and a forged user', async () => {
      expect((await rawPost({ ...v2('read'), 'x-mcp-tier': 'write' }, listTools)).status).toBe(401);
      expect((await rawPost({ ...v2('write'), 'x-user-token': 'attacker-token' }, listTools)).status).toBe(401);
      expect((await rawPost({ ...v2('write'), 'x-mcp-user': 'attacker@example.com' }, listTools)).status).toBe(401);
      expect(upstreamCalls).toEqual([]);
    });

    it('a signed v2 write tier is honoured', async () => {
      expect(await toolNames(v2('write'))).toContain('cipp_exec_write');
      expect(await toolNames(v2('read'))).not.toContain('cipp_exec_write');
    });

    it('a request with no S2S header, two S2S headers or garbage is refused', async () => {
      const { 'x-gateway-s2s': _s, ...noSig } = v2('write');
      void _s;
      expect((await rawPost(noSig, listTools)).status).toBe(401);
      expect((await rawPost({ ...v2('write'), 'x-gateway-s2s': 'garbage' }, listTools)).status).toBe(401);
    });
  });

  describe('routing and robustness', () => {
    it('an unknown path is a 404 before any authentication, and /mcp with a query is not /mcp', async () => {
      expect((await rawPost({}, listTools, '/nope')).status).toBe(404);
      expect((await rawPost(v2('read'), listTools, '/mcp?x=1')).status).toBe(404);
      expect((await rawPost(v2('read'), listTools, '/mcp/')).status).toBe(404);
      expect((await realFetch(`http://${HOST}:${PORT}/health`)).status).toBe(200);
    });

    it('a socket aborted mid-body does not take the server down', async () => {
      const body = JSON.stringify(listTools);
      const sig = signV3(SECRET, { aud: 'cipp', method: 'POST', path: '/mcp', body, headers: identity('read') });
      const sock = connect(PORT, HOST);
      await new Promise<void>((r) => sock.once('connect', () => r()));
      const hdrs = Object.entries(identity('read')).map(([k, v]) => `${k}: ${v}\r\n`).join('');
      sock.write(`POST /mcp HTTP/1.1\r\nHost: x\r\nX-Gateway-S2S: ${sig}\r\n${hdrs}Content-Length: 1000\r\n\r\n0123456789`);
      await new Promise((r) => setTimeout(r, 100));
      sock.destroy();
      await new Promise((r) => setTimeout(r, 100));
      expect((await realFetch(`http://${HOST}:${PORT}/health`)).status).toBe(200);
    });

    it('never logs the user token', async () => {
      await rawPost(v3(listTools, identity('write')), listTools);
      await rawPost(v2('read'), listTools);
      await rawPost({ ...v2('read'), 'x-gateway-s2s': 'bad' }, listTools);
      expect(logs.length).toBeGreaterThan(0);
      for (const l of logs) {
        expect(l.line).not.toContain(TOKEN);
        expect(l.line).not.toMatch(/Bearer\s/i);
      }
    });
  });

  describe('boot', () => {
    const withSecret = async (secret: string | undefined, fn: () => Promise<void>) => {
      const prev = { s: process.env.CONDUIT_S2S_SECRET, p: process.env.MCP_HTTP_PORT };
      if (secret === undefined) delete process.env.CONDUIT_S2S_SECRET;
      else process.env.CONDUIT_S2S_SECRET = secret;
      process.env.MCP_HTTP_PORT = String(PORT + 1);
      try {
        await fn();
      } finally {
        process.env.CONDUIT_S2S_SECRET = prev.s;
        process.env.MCP_HTTP_PORT = prev.p;
      }
    };

    it('refuses to start in HTTP mode with no secret, an empty secret or one under 32 characters', async () => {
      for (const secret of [undefined, '', 'short-secret', 'x'.repeat(31)]) {
        await withSecret(secret, async () => {
          await expect(makeServer().start()).rejects.toThrow(/Refusing to start/);
        });
      }
    });

    it('with no secret there is no listener to be served unauthenticated', async () => {
      await withSecret(undefined, async () => {
        const s = makeServer();
        await expect(s.start()).rejects.toThrow();
        await expect(realFetch(`http://${HOST}:${PORT + 1}/health`)).rejects.toThrow();
      });
    });

    it('ITSL_REQUIRE_S2S_V2 is logged as deprecated and ignored: v1 is still refused, nothing is loosened', async () => {
      process.env.ITSL_REQUIRE_S2S_V2 = 'false';
      const prev = process.env.MCP_HTTP_PORT;
      process.env.MCP_HTTP_PORT = String(PORT + 2);
      const s = makeServer();
      try {
        await s.start();
        expect(logs.some((l) => l.level === 'warn' && l.line.includes('ITSL_REQUIRE_S2S_V2 is deprecated'))).toBe(true);
        const res = await realFetch(`http://${HOST}:${PORT + 2}/mcp`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'x-gateway-s2s': signV1(SECRET), 'x-user-token': TOKEN, 'x-base-url': BASE },
          body: JSON.stringify(listTools),
        });
        expect(res.status).toBe(401);
      } finally {
        await s.stop();
        delete process.env.ITSL_REQUIRE_S2S_V2;
        process.env.MCP_HTTP_PORT = prev;
      }
    });
  });
});
