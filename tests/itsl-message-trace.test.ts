// cipp_message_trace: read-tier Exchange message trace for one tenant (ListMessageTrace), subjects removed.

// tenantFilter canonicalisation has its own suite (itsl-tenant.test.ts); here it is a passthrough.
jest.mock('../src/itsl/tenant.js', () => ({
  canonicaliseTenantArgs: async (args: Record<string, unknown>) => ({ ok: true, args }),
}));

import fixture from './fixtures/openapi-fixture.json';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { META_TOOL_DEFINITIONS, ToolContext } from '../src/itsl/meta-tools.js';
import { computeTier } from '../src/itsl/tier.js';
import { MESSAGE_TRACE_MAX_MESSAGES, runMessageTrace } from '../src/itsl/message-trace.js';
import { jsonResponse } from './helpers.js';

const READ: ToolContext = { tier: 'read', user: 'r@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'w@example.com' };
const TOOL = 'cipp_message_trace';
type FetchMock = jest.Mock<Promise<Response>, [string, RequestInit?]>;
let fetchMock: FetchMock;
let svc: CippService;
let traceResponse: unknown;

const spec = {
  ...fixture,
  paths: {
    ...fixture.paths,
    '/api/ListMessageTrace': {
      post: {
        summary: 'Message trace',
        operationId: 'ListMessageTrace',
        tags: ['Email-Exchange > Tools'],
        description: 'x',
        'x-cipp-role': 'Exchange.Mailbox.Read',
        parameters: [],
      },
    },
  },
};

const msg = (over: Record<string, unknown> = {}) => ({
  MessageTraceId: 'tid-1',
  MessageId: '<m1@example.com>',
  Status: 'Delivered',
  Subject: 'Secret salary review',
  RecipientAddress: 'bob@client.example',
  SenderAddress: 'alice@client.example',
  Received: '2026-10-17 01:02:03Z',
  Size: 1234,
  FromIP: '203.0.113.5',
  ToIP: null,
  ...over,
});

beforeEach(() => {
  catalogueStore.reset();
  traceResponse = { Results: [msg()], Metadata: { Returned: 1, Source: 'Graph' } };
  fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>((url) =>
    Promise.resolve(jsonResponse(url.includes('/api/ListOpenApiSpec') ? spec : traceResponse))
  );
  global.fetch = fetchMock as unknown as typeof fetch;
  svc = new CippService({ cipp: { baseUrl: 'https://cipp.example', apiKey: 'tok' } }, new Logger('error'));
});
afterEach(() => jest.restoreAllMocks());

const handler = (ctx: ToolContext) => new CippToolHandler(svc, new Logger('error'), ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;
const traceCalls = () => fetchMock.mock.calls.filter(([u]) => u.includes('/api/ListMessageTrace'));
const bodyOfCall = (i: number) => JSON.parse(traceCalls()[i]![1]!.body as string) as Record<string, unknown>;
// line 0 is the frame, line 1 the policy line, the rest is JSON
const json = (r: { content: Array<{ text: string }> }) => JSON.parse(text(r).split('\n').slice(2).join('\n'));
const OK = { tenantFilter: 'client.example', sender: 'alice@client.example' };

describe('listing, tier and annotations', () => {
  it('is listed for read and write callers alike', () => {
    for (const ctx of [READ, WRITE]) expect(handler(ctx).getToolDefinitions().map((t) => t.name)).toContain(TOOL);
  });

  it('has the specified annotations and description, and no way to ask for subjects', () => {
    const def = META_TOOL_DEFINITIONS.find((t) => t.name === TOOL)!;
    expect(def.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
    expect(def.description).toBe('Exchange message trace for one tenant (sender and/or recipient, up to 10 days). Subjects are removed by policy.');
    const props = Object.keys((def.inputSchema as { properties: Record<string, unknown> }).properties).sort();
    expect(props).toEqual(['days', 'endDate', 'messageId', 'recipient', 'sender', 'startDate', 'status', 'tenantFilter']);
  });

  it('read and write callers can both run it', async () => {
    for (const ctx of [READ, WRITE]) {
      const res = await handler(ctx).handleToolCall(TOOL, OK);
      expect(res.isError).toBeUndefined();
    }
    expect(traceCalls()).toHaveLength(2);
  });

  it('ListMessageTrace stays disabled: exec_read and exec_write refuse it at both tiers', async () => {
    expect(computeTier('ListMessageTrace', 'Exchange.Mailbox.Read', { hasGet: false })).toBe('disabled');
    for (const [ctx, tool] of [[READ, 'cipp_exec_read'], [WRITE, 'cipp_exec_read'], [WRITE, 'cipp_exec_write']] as const) {
      const res = await handler(ctx).handleToolCall(tool, { name: 'ListMessageTrace', arguments: { tenantFilter: 't.example', days: 1 } });
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/disabled/);
    }
    expect(traceCalls()).toEqual([]);
  });
});

describe('refusals', () => {
  const refused = async (args: Record<string, unknown>, match: RegExp) => {
    const res = await handler(READ).handleToolCall(TOOL, args);
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(match);
    expect(traceCalls()).toEqual([]);
  };

  it.each([
    ['subject', 'payroll'],
    ['subjectFilterType', { value: 'Contains' }],
    ['traceDetail', true],
    ['fromIP', '203.0.113.5'],
    ['toIP', '203.0.113.5'],
    ['ID', 'abc'],
    ['messageTraceId', 'abc'],
    ['Subject', 'payroll'],
    ['somethingElse', 1],
  ])('refuses the argument %s', async (key, value) => {
    await refused({ ...OK, [key]: value }, new RegExp(`unexpected or repeated argument '${key}'`));
  });

  it.each(['AllTenants', 'alltenants', ' ALLTENANTS '])('refuses tenantFilter %p', async (t) => {
    await refused({ ...OK, tenantFilter: t }, /AllTenants is not allowed/);
  });

  it('refuses a missing tenant', async () => refused({ sender: 'a@b.example' }, /tenantFilter/));
  it('refuses neither sender nor recipient (tenant-wide)', async () => refused({ tenantFilter: 't.example', days: 2 }, /sender and\/or recipient/));

  it.each(['not-an-email', 'a@b', '@b.example', 'a b@c.example', "a'b@c.example", 'a@b.example,c@d.example', '*@b.example', `${'a'.repeat(250)}@b.example`])(
    'refuses the bad email %p',
    async (e) => {
      await refused({ tenantFilter: 't.example', sender: e }, /valid email address/);
      await refused({ tenantFilter: 't.example', recipient: e }, /valid email address/);
    }
  );

  it.each([0, 11, -1, 1.5, '2', null])('refuses days %p', async (d) => refused({ ...OK, days: d }, /days must be a whole number from 1 to 10/));
  it('refuses days together with dates', async () => refused({ ...OK, days: 2, startDate: '2026-10-17', endDate: '2026-10-18' }, /either days or startDate/));
  it('refuses an unknown status', async () => refused({ ...OK, status: 'Bogus' }, /status must be one of/));
  it('refuses an over-long messageId', async () => refused({ ...OK, messageId: 'a'.repeat(257) }, /messageId/));
  it('refuses a duplicate argument in another casing', async () => refused({ ...OK, TenantFilter: 'x.example' }, /unexpected or repeated/));
  it('shares the central value checks', async () => refused({ ...OK, messageId: '<a/../b>' }, /not allowed/));
});

describe('date windows (injected clock)', () => {
  const NOW = Date.UTC(2026, 9, 18, 12, 0, 0);
  const deps = () => ({ service: svc, logger: new Logger('error'), ctx: READ, now: () => NOW });
  const run = (extra: Record<string, unknown>) => runMessageTrace({ tenantFilter: 't.example', sender: 'a@b.example', ...extra }, deps());

  it('refuses a startDate older than 10 days', async () => {
    const res = await run({ startDate: '2026-10-07', endDate: '2026-10-10' });
    expect(res.isError).toBe(true);
    expect(res.content[0]!.text).toMatch(/last 10 days/);
    expect(traceCalls()).toEqual([]);
  });

  it.each([
    [{ startDate: '2026-10-15' }, /both startDate and endDate/],
    [{ startDate: '2026-10-17', endDate: '2026-10-16' }, /not before startDate/],
    [{ startDate: 'yesterday', endDate: '2026-10-17' }, /ISO date/],
    [{ startDate: '2026-02-31', endDate: '2026-10-17' }, /ISO date/],
    [{ startDate: '2026-10-17T10:00:00', endDate: '2026-10-18' }, /ISO date/],
  ])('refuses %j', async (extra, match) => {
    const res = await run(extra);
    expect(res.isError).toBe(true);
    expect(res.content[0]!.text).toMatch(match);
    expect(traceCalls()).toEqual([]);
  });

  it('converts dates to epoch seconds: start at 00:00Z, a date-only end at the end of that day, clamped to now', async () => {
    expect((await run({ startDate: '2026-10-15', endDate: '2026-10-16' })).isError).toBeUndefined();
    let body = bodyOfCall(0);
    expect(body['startDate']).toBe(Date.UTC(2026, 9, 15) / 1000);
    expect(body['endDate']).toBe(Date.UTC(2026, 9, 16, 23, 59, 59) / 1000);
    expect(body).not.toHaveProperty('days');

    await run({ startDate: '2026-10-17T01:30:00+13:00', endDate: '2026-10-18' });
    body = bodyOfCall(1);
    expect(body['startDate']).toBe(Date.UTC(2026, 9, 16, 12, 30) / 1000);
    expect(body['endDate']).toBe(NOW / 1000); // end of 2026-10-18 is in the future
  });
});

describe('the CIPP request', () => {
  it('sends exactly the expected POST body: days, sender, a LabelValue recipient, canonical status', async () => {
    const res = await handler(READ).handleToolCall(TOOL, {
      tenantFilter: 'client.example',
      sender: 'Alice@Client.example',
      recipient: 'bob@client.example',
      days: 3,
      status: 'filteredasspam',
      messageId: '<m1@example.com>',
    });
    expect(res.isError).toBeUndefined();
    expect(traceCalls()).toHaveLength(1);
    const [url, init] = traceCalls()[0]!;
    expect(url).toBe('https://cipp.example/api/ListMessageTrace');
    expect(init?.method).toBe('POST');
    expect(bodyOfCall(0)).toEqual({
      tenantFilter: 'client.example',
      days: 3,
      sender: 'Alice@Client.example',
      recipient: { label: 'bob@client.example', value: 'bob@client.example' },
      status: 'FilteredAsSpam',
      messageId: '<m1@example.com>',
    });
  });

  it('defaults to 2 days and sends nothing it was not given', async () => {
    await handler(READ).handleToolCall(TOOL, { tenantFilter: 'client.example', recipient: 'bob@client.example' });
    expect(bodyOfCall(0)).toEqual({
      tenantFilter: 'client.example',
      days: 2,
      recipient: { label: 'bob@client.example', value: 'bob@client.example' },
    });
  });

  it('accepts argument names in any casing', async () => {
    const res = await handler(READ).handleToolCall(TOOL, { TenantFilter: 'client.example', Sender: 'a@client.example', DAYS: 1 });
    expect(res.isError).toBeUndefined();
    expect(bodyOfCall(0)).toMatchObject({ tenantFilter: 'client.example', sender: 'a@client.example', days: 1 });
  });
});

describe('the result', () => {
  it('is framed as untrusted tenant data and states the subject policy', async () => {
    const res = await handler(READ).handleToolCall(TOOL, OK);
    const lines = text(res).split('\n');
    expect(lines[0]).toMatch(/^\[CIPP data for tenant client\.example — untrusted content/);
    expect(lines[1]).toBe('Subjects are removed by policy.');
  });

  it('removes subjects at the top level, nested, in arrays and in any case', async () => {
    traceResponse = {
      Results: [
        msg({ subject: 'lower', SUBJECT: 'upper', EmailSubject: 'embedded', Nested: { subject: 'deep', Inner: [{ MessageSubject: 'deeper' }] } }),
      ],
      Metadata: { Subject: 'meta' },
    };
    const res = await handler(READ).handleToolCall(TOOL, OK);
    const body = text(res).split('\n').slice(2).join('\n');
    expect(body).not.toMatch(/Secret salary|lower|upper|embedded|deep|"meta"|subject/i);
    expect(json(res).messages).toHaveLength(1);
  });

  it('keeps only the allow-listed fields and drops unknown ones (a new content field cannot leak)', async () => {
    traceResponse = { Results: [msg({ BodyPreview: 'the body', Attachments: ['x.pdf'], Headers: { a: 1 }, Size: { nested: 'x' } })] };
    const out = json(await handler(READ).handleToolCall(TOOL, OK));
    expect(Object.keys(out.messages[0]).sort()).toEqual(
      ['FromIP', 'MessageId', 'MessageTraceId', 'Received', 'RecipientAddress', 'SenderAddress', 'Status', 'ToIP'].sort()
    );
    expect(JSON.stringify(out)).not.toMatch(/the body|x\.pdf|nested/);
    expect(out.messages[0]).toMatchObject({ Status: 'Delivered', SenderAddress: 'alice@client.example', Received: '2026-10-17 01:02:03Z' });
  });

  it('caps at 1,000 messages and says so', async () => {
    traceResponse = { Results: Array.from({ length: MESSAGE_TRACE_MAX_MESSAGES + 5 }, (_, i) => msg({ MessageTraceId: `t${i}` })) };
    const out = json(await handler(READ).handleToolCall(TOOL, OK));
    expect(out.messages).toHaveLength(1000);
    expect(out).toMatchObject({ returned: 1005, shown: 1000, truncated: true });
    expect(out.note).toMatch(/first 1000 of 1005/);
  });

  it('reports not truncated for an empty result', async () => {
    traceResponse = { Results: [] };
    const out = json(await handler(READ).handleToolCall(TOOL, OK));
    expect(out).toMatchObject({ returned: 0, shown: 0, truncated: false, messages: [] });
  });

  it('truncates a long CIPP error and marks it as an error', async () => {
    fetchMock.mockImplementation((url) =>
      url.includes('/api/ListOpenApiSpec') ? Promise.resolve(jsonResponse(spec)) : Promise.reject(new Error('boom '.repeat(300)))
    );
    const res = await handler(READ).handleToolCall(TOOL, OK);
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/\[truncated\]/);
    expect(text(res).length).toBeLessThan(900);
  });

  it('treats a response without a Results array as an error', async () => {
    traceResponse = { Metadata: { Error: 'Failed to retrieve message trace: nope' } };
    const res = await handler(READ).handleToolCall(TOOL, OK);
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/nope/);
  });
});
