// S2S v2 (signed tier and user), the per-user token mode, and the tier that
// reaches tools/list, tested at the HTTP boundary of the real server.

import { createHmac } from 'node:crypto';
import fixture from './fixtures/openapi-fixture.json';
import { decideS2s, signS2sV2, verifyS2sV2 } from '../src/itsl/s2s-v2.js';
import { verifyS2sHeader } from '../src/s2s-verify.js';
import { parseCredentialsFromHeaders } from '../src/utils/config.js';
import type { CippMcpServer as CippMcpServerType } from '../src/mcp/server.js';

const SECRET = 'test-v2-secret-do-not-use-in-prod';
const nowS = () => Math.floor(Date.now() / 1000);
const v1 = (secret: string, t: number) => `t=${t},v1=${createHmac('sha256', secret).update(`t=${t}`).digest('hex')}`;

describe('verifyS2sV2', () => {
  it('accepts a header over exactly (t, tier, user)', () => {
    const h = signS2sV2(SECRET, 'write', 'grant@example.com', nowS());
    expect(verifyS2sV2(h, SECRET, 'write', 'grant@example.com')).toEqual({ tier: 'write', user: 'grant@example.com' });
  });

  it('format is t=<unix>,v2=<hex> over "t=<unix>\\ntier=<tier>\\nuser=<upn>"', () => {
    const t = nowS();
    const hex = createHmac('sha256', SECRET).update(`t=${t}\ntier=read\nuser=a@b.c`).digest('hex');
    expect(signS2sV2(SECRET, 'read', 'a@b.c', t)).toBe(`t=${t},v2=${hex}`);
  });

  it('a forged tier or user fails: the signature binds them', () => {
    const h = signS2sV2(SECRET, 'read', 'reader@example.com', nowS());
    expect(verifyS2sV2(h, SECRET, 'write', 'reader@example.com')).toBeUndefined();
    expect(verifyS2sV2(h, SECRET, 'read', 'admin@example.com')).toBeUndefined();
  });

  it('rejects wrong secret, stale or future timestamp, bad tier values, missing headers, v1 headers', () => {
    expect(verifyS2sV2(signS2sV2('other', 'read', 'u', nowS()), SECRET, 'read', 'u')).toBeUndefined();
    expect(verifyS2sV2(signS2sV2(SECRET, 'read', 'u', nowS() - 301), SECRET, 'read', 'u')).toBeUndefined();
    expect(verifyS2sV2(signS2sV2(SECRET, 'read', 'u', nowS() + 301), SECRET, 'read', 'u')).toBeUndefined();
    expect(verifyS2sV2(signS2sV2(SECRET, 'read', 'u', nowS() - 299), SECRET, 'read', 'u')).toBeDefined();
    expect(verifyS2sV2(signS2sV2(SECRET, 'read', 'u', nowS()), SECRET, 'admin', 'u')).toBeUndefined();
    expect(verifyS2sV2(signS2sV2(SECRET, 'read', 'u', nowS()), SECRET, undefined, 'u')).toBeUndefined();
    expect(verifyS2sV2(signS2sV2(SECRET, 'read', 'u', nowS()), SECRET, 'read', undefined)).toBeUndefined();
    expect(verifyS2sV2(v1(SECRET, nowS()), SECRET, 'read', 'u')).toBeUndefined();
    expect(verifyS2sV2(signS2sV2(SECRET, 'read', 'u', nowS()), '', 'read', 'u')).toBeUndefined();
  });

  it('rejects a user containing a newline (delimiter injection)', () => {
    const t = nowS();
    // Sign "tier=read\nuser=x\ntier=write" style content: must not verify as (write, ...).
    const user = 'x\ntier=write';
    const h = signS2sV2(SECRET, 'read', user, t);
    expect(verifyS2sV2(h, SECRET, 'read', user)).toBeUndefined();
  });
});

describe('decideS2s', () => {
  const base = { tierHeader: 'write', userHeader: 'u@example.com', verifyV1: verifyS2sHeader };

  it('requireV2: unsigned, v1-only, forged and secretless requests are refused', () => {
    const t = nowS();
    expect(decideS2s({ ...base, header: undefined, secret: SECRET, requireV2: true }).ok).toBe(false);
    expect(decideS2s({ ...base, header: v1(SECRET, t), secret: SECRET, requireV2: true }).ok).toBe(false);
    // forged x-mcp-tier with a VALID v1 signature
    expect(decideS2s({ ...base, tierHeader: 'write', header: v1(SECRET, t), secret: SECRET, requireV2: true }).ok).toBe(false);
    expect(decideS2s({ ...base, header: signS2sV2(SECRET, 'read', 'u@example.com', t), secret: SECRET, requireV2: true }).ok).toBe(false); // tier header says write
    expect(decideS2s({ ...base, header: signS2sV2(SECRET, 'write', 'u@example.com', t), secret: '', requireV2: true }).ok).toBe(false);
    expect(decideS2s({ ...base, header: 'garbage', secret: SECRET, requireV2: true }).ok).toBe(false);
  });

  it('requireV2: a valid v2 passes and yields the signed tier and user', () => {
    const out = decideS2s({ ...base, header: signS2sV2(SECRET, 'write', 'u@example.com', nowS()), secret: SECRET, requireV2: true });
    expect(out).toEqual({ ok: true, tier: 'write', user: 'u@example.com', version: 'v2' });
  });

  it('v2 not required: v1 still verifies but a forged tier header is NOT trusted (tier read)', () => {
    const out = decideS2s({ ...base, header: v1(SECRET, nowS()), secret: SECRET, requireV2: false });
    expect(out).toEqual({ ok: true, tier: 'read', user: undefined, version: 'v1' });
  });

  it('v2 not required and no secret (local dev): allowed, tier read', () => {
    const out = decideS2s({ ...base, header: undefined, secret: '', requireV2: false });
    expect(out).toEqual({ ok: true, tier: 'read', user: undefined, version: 'none' });
  });
});

describe('x-user-token parsing', () => {
  it('becomes the only credential; x-api-key and client credentials are dropped', () => {
    const c = parseCredentialsFromHeaders({
      'x-user-token': 'user-jwt',
      'x-api-key': 'shared-key',
      'x-tenant-id': 't',
      'x-client-id': 'c',
      'x-client-secret': 's',
      'x-base-url': 'https://cipp.example',
    });
    expect(c.apiKey).toBe('user-jwt');
    expect(c.userToken).toBe('user-jwt');
    expect(c.tenantId).toBeUndefined();
    expect(c.clientId).toBeUndefined();
    expect(c.clientSecret).toBeUndefined();
    expect(c.baseUrl).toBe('https://cipp.example');
  });

  it('strips a Bearer prefix and ignores blank or placeholder values', () => {
    expect(parseCredentialsFromHeaders({ 'x-user-token': 'Bearer abc' }).apiKey).toBe('abc');
    expect(parseCredentialsFromHeaders({ 'x-user-token': '   ', 'x-api-key': 'k' }).apiKey).toBe('k');
    expect(parseCredentialsFromHeaders({ 'x-user-token': '${user_config.x}', 'x-api-key': 'k' }).apiKey).toBe('k');
  });
});

// ---------------------------------------------------------------------------
// HTTP boundary
// ---------------------------------------------------------------------------

const HOST = '127.0.0.1';
const PORT = 47533;
const TOKEN = 'eyJ.user-token-that-must-never-be-logged.sig';
const ENV_KEYS = ['CONDUIT_S2S_SECRET', 'ITSL_REQUIRE_S2S_V2', 'ITSL_REQUIRE_USER_TOKEN', 'AUTH_MODE', 'MCP_TRANSPORT', 'MCP_HTTP_PORT', 'MCP_HTTP_HOST'];

describe('server HTTP boundary', () => {
  let server: InstanceType<typeof CippMcpServerType>;
  let realFetch: typeof fetch;
  let store: { reset(): void };
  let upstreamCalls: Array<{ url: string; init?: RequestInit }>;
  const logged: string[] = [];

  const post = (headers: Record<string, string>, body: unknown) =>
    realFetch(`http://${HOST}:${PORT}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers },
      body: JSON.stringify(body),
    });
  const listTools = { jsonrpc: '2.0', method: 'tools/list', id: 1 };
  const callTool = (name: string, args: Record<string, unknown> = {}) => ({
    jsonrpc: '2.0',
    method: 'tools/call',
    params: { name, arguments: args },
    id: 2,
  });
  const v2 = (tier: 'read' | 'write', user = 'u@example.com') => ({
    'x-gateway-s2s': signS2sV2(SECRET, tier, user, nowS()),
    'x-mcp-tier': tier,
    'x-mcp-user': user,
    'x-user-token': TOKEN,
    'x-base-url': 'https://cipp.example',
  });
  const toolNames = async (headers: Record<string, string>): Promise<string[]> => {
    const res = await post(headers, listTools);
    expect(res.status).toBe(200);
    return ((await res.json()) as { result: { tools: Array<{ name: string }> } }).result.tools.map((t) => t.name);
  };

  beforeAll(async () => {
    Object.assign(process.env, {
      CONDUIT_S2S_SECRET: SECRET,
      ITSL_REQUIRE_S2S_V2: 'true',
      ITSL_REQUIRE_USER_TOKEN: 'true',
      AUTH_MODE: 'gateway',
      MCP_TRANSPORT: 'http',
      MCP_HTTP_PORT: String(PORT),
      MCP_HTTP_HOST: HOST,
    });
    realFetch = global.fetch;
    jest.resetModules();
    /* eslint-disable @typescript-eslint/no-require-imports */
    const { CippMcpServer } = require('../src/mcp/server.js');
    ({ catalogueStore: store } = require('../src/itsl/catalogue.js'));
    const { loadEnvironmentConfig, mergeWithMcpConfig } = require('../src/utils/config.js');
    /* eslint-enable @typescript-eslint/no-require-imports */
    const capture = (...a: unknown[]) => logged.push(JSON.stringify(a));
    const logger = { debug: capture, info: capture, warn: capture, error: capture };
    const envConfig = loadEnvironmentConfig();
    server = new CippMcpServer(mergeWithMcpConfig(envConfig), logger, envConfig);
    await server.start();
  }, 20000);

  afterAll(async () => {
    await server.stop();
    for (const k of ENV_KEYS) delete process.env[k];
  });

  beforeEach(() => {
    store.reset();
    upstreamCalls = [];
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

  it('refuses an unsigned request, a v1-only request and a forged tier with a valid v1 signature (all 401)', async () => {
    const base = { 'x-user-token': TOKEN, 'x-base-url': 'https://cipp.example' };
    expect((await post(base, listTools)).status).toBe(401);
    expect((await post({ ...base, 'x-gateway-s2s': v1(SECRET, nowS()) }, listTools)).status).toBe(401);
    expect(
      (await post({ ...base, 'x-gateway-s2s': v1(SECRET, nowS()), 'x-mcp-tier': 'write', 'x-mcp-user': 'attacker@example.com' }, listTools)).status
    ).toBe(401);
    // a v2 whose signature covers 'read' but whose tier header was flipped to 'write'
    expect((await post({ ...v2('read'), 'x-mcp-tier': 'write' }, listTools)).status).toBe(401);
    expect(upstreamCalls).toEqual([]);
  });

  it('with ITSL_REQUIRE_USER_TOKEN, a request carrying client credentials but no x-user-token is 401', async () => {
    const headers: Record<string, string> = {
      ...v2('write'),
      'x-tenant-id': '00000000-0000-0000-0000-000000000001',
      'x-client-id': '00000000-0000-0000-0000-000000000002',
      'x-client-secret': 'shh',
      'x-api-key': 'shared',
    };
    delete headers['x-user-token'];
    const res = await post(headers, listTools);
    expect(res.status).toBe(401);
    expect(upstreamCalls).toEqual([]);
  });

  it('tools/list follows the SIGNED tier: read callers see no write tools', async () => {
    const read = await toolNames(v2('read'));
    const write = await toolNames(v2('write'));
    for (const names of [read, write]) {
      expect(names).toContain('cipp_exec_tool');
      expect(names).not.toContain('cipp_create_user');
      expect(names).not.toContain('cipp_run_standards_check');
    }
    expect(read).toHaveLength(write.length); // 14 write tools are disabled at BOTH tiers
  });

  it('write-tier exec runs through the real server; read-tier exec is refused and CIPP never sees it', async () => {
    const args = { name: 'ExecCIPPDBCache', arguments: { Name: 'SharePointSharingLinks', tenantFilter: 'aviva.org.nz' } };
    const denied = await post(v2('read'), callTool('cipp_exec_tool', args));
    const deniedBody = (await denied.json()) as { result: { isError: boolean; content: Array<{ text: string }> } };
    expect(deniedBody.result.isError).toBe(true);
    expect(deniedBody.result.content[0]!.text).toMatch(/write-tier/);
    expect(upstreamCalls.some((c) => c.url.includes('/api/ExecCIPPDBCache'))).toBe(false);

    const ok = await post(v2('write'), callTool('cipp_exec_tool', args));
    expect(((await ok.json()) as { result: { isError?: boolean } }).result.isError).toBeUndefined();
    const call = upstreamCalls.find((c) => c.url.includes('/api/ExecCIPPDBCache'))!;
    expect(call.init?.method).toBe('POST');
    // The user's own token is the Bearer CIPP receives; a shared key header would have been ignored.
    expect((call.init?.headers as Record<string, string>).Authorization).toBe(`Bearer ${TOKEN}`);
  });

  it('never logs the user token or any Authorization value', async () => {
    await post(v2('write'), callTool('cipp_exec_tool', { name: 'ExecGetRecoveryKey' }));
    await post(v2('read'), callTool('cipp_list_users', { tenantFilter: 't' }));
    await post({ ...v2('read'), 'x-gateway-s2s': 'bad' }, listTools);
    expect(logged.length).toBeGreaterThan(0);
    for (const line of logged) {
      expect(line).not.toContain(TOKEN);
      expect(line).not.toMatch(/Bearer\s/i);
    }
  });
});
