// IT Simply Ltd: read-tier Exchange message trace with subjects removed (new file).
//
// ListMessageTrace is a POST endpoint, so it is DISABLED for cipp_exec_read and cipp_exec_write
// and stays that way. This tool is the one narrow route to it (Grant, 2026-10-18: "Read tier
// with subjects removed"): one tenant, sender and/or recipient required (never tenant-wide),
// a window of at most 10 days, and exactly one request shape, built here and nowhere else.
//
// Subjects are removed on BOTH sides: a subject filter would let a caller guess subjects, so
// subject, subjectFilterType and traceDetail are never accepted; and in the response every
// property whose name contains "subject" is stripped at any depth, after which only an
// allow-list of fields is returned, so a field CIPP adds later cannot carry content out.
//
// What CIPP's Invoke-ListMessageTrace returns (Graph, or Get-MessageTraceV2 as a fallback):
//   { Results: [ { MessageTraceId, MessageId, Status, Subject, RecipientAddress, SenderAddress,
//                  Received, Size, FromIP, ToIP } ], Metadata: { Returned, Source, Note?, Error? } }
// CIPP answers 500 with Metadata.Error when it fails.

import type { CatalogueLogger } from './catalogue.js';
import type { ToolContext } from './meta-tools.js';
import { truncateError } from './frame.js';

export const MESSAGE_TRACE_TOOL_NAME = 'cipp_message_trace';
export const MESSAGE_TRACE_MAX_MESSAGES = 1000;
export const MESSAGE_TRACE_POLICY_LINE = 'Subjects are removed by policy.';

/** Exchange trace statuses (the Graph enum, PascalCase as CIPP's UI sends them). */
export const MESSAGE_TRACE_STATUSES = ['Delivered', 'Failed', 'Pending', 'Expanded', 'Quarantined', 'FilteredAsSpam', 'GettingStatus'] as const;

/** The only fields returned per message, as CIPP names them. Everything else is dropped. */
export const MESSAGE_TRACE_FIELDS = ['Received', 'SenderAddress', 'RecipientAddress', 'Status', 'Size', 'MessageId', 'MessageTraceId', 'FromIP', 'ToIP'] as const;

const ALLOWED_ARGS = ['tenantfilter', 'sender', 'recipient', 'days', 'startdate', 'enddate', 'status', 'messageid'];
const TENANT = /^[A-Za-z0-9._-]{1,255}$/;
const EMAIL = /^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}$/;
const MAX_EMAIL = 254;
const MAX_MESSAGE_ID = 256;
const MAX_FIELD_CHARS = 512;
const DAY_MS = 24 * 60 * 60 * 1000;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;
const SUBJECT_KEY = /subject/i;

export const MESSAGE_TRACE_TOOL_DEFINITION = {
  name: MESSAGE_TRACE_TOOL_NAME,
  description: 'Exchange message trace for one tenant (sender and/or recipient, up to 10 days). Subjects are removed by policy.',
  inputSchema: {
    type: 'object',
    properties: {
      tenantFilter: { type: 'string', description: "The tenant's default domain or tenant ID. AllTenants is not allowed." },
      sender: { type: 'string', description: 'Sender email address. At least one of sender and recipient is required.' },
      recipient: { type: 'string', description: 'Recipient email address. At least one of sender and recipient is required.' },
      days: { type: 'number', description: 'Look back this many days, a whole number from 1 to 10 (default 2). Not with startDate/endDate.' },
      startDate: { type: 'string', description: 'ISO date or datetime (UTC unless an offset is given), within the last 10 days. Needs endDate.' },
      endDate: { type: 'string', description: 'ISO date or datetime. A date alone means the end of that day. Needs startDate.' },
      status: { type: 'string', description: `Optional delivery status: ${MESSAGE_TRACE_STATUSES.join(', ')}.` },
      messageId: { type: 'string', description: 'Optional internet Message-ID, up to 256 characters.' },
    },
    required: ['tenantFilter'],
    additionalProperties: false,
  },
  annotations: {
    title: 'Message trace (subjects removed)',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

export interface MessageTraceDeps {
  service: {
    callEndpoint(
      method: 'GET' | 'POST',
      path: string,
      params?: Record<string, unknown>,
      body?: Record<string, unknown> | unknown[]
    ): Promise<unknown>;
  };
  logger: CatalogueLogger & { error(message: string, meta?: unknown): void };
  ctx: ToolContext;
  /** Injectable clock (tests). */
  now?: () => number;
}

export interface MessageTraceResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

const out = (value: string, isError = false): MessageTraceResult => ({
  content: [{ type: 'text', text: value }],
  ...(isError ? { isError: true } : {}),
});

/** Parse an ISO date or datetime to epoch ms; a date-only end means the end of that UTC day. undefined when invalid. */
function parseIso(value: string, endOfDay: boolean): number | undefined {
  const d = ISO_DATE.exec(value);
  if (d) {
    const y = Number(d[1]);
    const m = Number(d[2]);
    const day = Number(d[3]);
    const start = Date.UTC(y, m - 1, day);
    const check = new Date(start);
    if (check.getUTCFullYear() !== y || check.getUTCMonth() !== m - 1 || check.getUTCDate() !== day) return undefined;
    return endOfDay ? start + DAY_MS - 1000 : start;
  }
  if (!ISO_DATETIME.test(value)) return undefined;
  const t = Date.parse(value);
  return Number.isNaN(t) ? undefined : Math.floor(t / 1000) * 1000;
}

/** Copy of the value with every property named like /subject/i removed, at any depth. */
export function stripSubjects(node: unknown, depth = 0): unknown {
  if (depth > 12) return undefined;
  if (Array.isArray(node)) return node.map((n) => stripSubjects(n, depth + 1));
  if (node !== null && typeof node === 'object') {
    const clean: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (!SUBJECT_KEY.test(k)) clean[k] = stripSubjects(v, depth + 1);
    }
    return clean;
  }
  return node;
}

/** Only the allow-listed fields, only primitive values. */
function pickFields(row: unknown): Record<string, unknown> {
  const picked: Record<string, unknown> = {};
  if (row === null || typeof row !== 'object' || Array.isArray(row)) return picked;
  const lower = new Map(Object.entries(row as Record<string, unknown>).map(([k, v]) => [k.toLowerCase(), v]));
  for (const field of MESSAGE_TRACE_FIELDS) {
    const v = lower.get(field.toLowerCase());
    if (typeof v === 'string') picked[field] = v.length > MAX_FIELD_CHARS ? v.slice(0, MAX_FIELD_CHARS) : v;
    else if (typeof v === 'number' || typeof v === 'boolean' || v === null) picked[field] = v;
  }
  return picked;
}

export async function runMessageTrace(args: Record<string, unknown>, deps: MessageTraceDeps): Promise<MessageTraceResult> {
  const now = (deps.now ?? Date.now)();
  const refuse = (reason: string) => {
    deps.logger.warn('CIPP tool call refused', { tool: MESSAGE_TRACE_TOOL_NAME, reason: reason.slice(0, 120), user: deps.ctx.user });
    return out(`Refused: ${reason}`, true);
  };

  // Allow-list of argument names, compared case-insensitively, no duplicates.
  const seen = new Map<string, unknown>();
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (!ALLOWED_ARGS.includes(lk) || seen.has(lk)) {
      return refuse(
        `unexpected or repeated argument '${k.slice(0, 40)}'; only tenantFilter, sender, recipient, days, startDate, endDate, status and messageId are accepted. Subjects are removed by policy, so subject filters and trace details are not available.`
      );
    }
    seen.set(lk, v);
  }

  const rawTenant = seen.get('tenantfilter');
  if (typeof rawTenant !== 'string' || rawTenant.trim() === '') return refuse("provide tenantFilter: one tenant's default domain or tenant ID.");
  const tenant = rawTenant.trim();
  if (tenant.toLowerCase() === 'alltenants') return refuse('AllTenants is not allowed - trace one tenant at a time.');
  if (!TENANT.test(tenant)) return refuse("tenantFilter must be one tenant's default domain or tenant ID.");

  const address = (name: 'sender' | 'recipient'): string | undefined | { error: string } => {
    const v = seen.get(name);
    if (v === undefined) return undefined;
    if (typeof v !== 'string' || v.length > MAX_EMAIL || !EMAIL.test(v.trim())) return { error: `${name} must be a valid email address (up to ${MAX_EMAIL} characters).` };
    return v.trim();
  };
  const sender = address('sender');
  if (typeof sender === 'object') return refuse(sender.error);
  const recipient = address('recipient');
  if (typeof recipient === 'object') return refuse(recipient.error);
  if (sender === undefined && recipient === undefined) {
    return refuse('give sender and/or recipient (an email address); a tenant-wide message trace is not available.');
  }

  // Window: days, or startDate and endDate.
  const rawDays = seen.get('days');
  const hasDates = seen.has('startdate') || seen.has('enddate');
  if (rawDays !== undefined && hasDates) return refuse('give either days or startDate/endDate, not both.');
  const body: Record<string, unknown> = { tenantFilter: tenant };
  if (!hasDates) {
    const days = rawDays === undefined ? 2 : rawDays;
    if (typeof days !== 'number' || !Number.isInteger(days) || days < 1 || days > 10) return refuse('days must be a whole number from 1 to 10.');
    body['days'] = days;
  } else {
    const rawStart = seen.get('startdate');
    const rawEnd = seen.get('enddate');
    if (rawStart === undefined || rawEnd === undefined) return refuse('give both startDate and endDate.');
    const start = typeof rawStart === 'string' ? parseIso(rawStart.trim(), false) : undefined;
    let end = typeof rawEnd === 'string' ? parseIso(rawEnd.trim(), true) : undefined;
    if (start === undefined || end === undefined) return refuse('startDate and endDate must be ISO dates such as 2026-10-17 or datetimes such as 2026-10-17T09:00:00Z (a datetime needs Z or an offset).');
    if (start < now - 10 * DAY_MS) return refuse('startDate must be within the last 10 days.');
    if (start > now) return refuse('startDate is in the future.');
    if (end > now) end = Math.floor(now / 1000) * 1000;
    if (end <= start) return refuse('endDate must be after, not before startDate.');
    // CIPP reads epoch seconds as digits.
    body['startDate'] = start / 1000;
    body['endDate'] = end / 1000;
  }

  if (sender !== undefined) body['sender'] = sender;
  // CIPP's recipient is a LabelValue.
  if (recipient !== undefined) body['recipient'] = { label: recipient, value: recipient };

  const rawStatus = seen.get('status');
  if (rawStatus !== undefined) {
    const canonical = typeof rawStatus === 'string' ? MESSAGE_TRACE_STATUSES.find((s) => s.toLowerCase() === rawStatus.trim().toLowerCase()) : undefined;
    if (!canonical) return refuse(`status must be one of ${MESSAGE_TRACE_STATUSES.join(', ')}.`);
    body['status'] = canonical;
  }
  const rawMessageId = seen.get('messageid');
  if (rawMessageId !== undefined) {
    if (typeof rawMessageId !== 'string' || rawMessageId.trim() === '' || rawMessageId.length > MAX_MESSAGE_ID) {
      return refuse(`messageId must be a non-empty string of at most ${MAX_MESSAGE_ID} characters.`);
    }
    body['messageId'] = rawMessageId.trim();
  }

  deps.logger.info('CIPP message trace', {
    tenant,
    bySender: sender !== undefined,
    byRecipient: recipient !== undefined,
    callerTier: deps.ctx.tier,
    user: deps.ctx.user,
  });

  let raw: unknown;
  try {
    raw = await deps.service.callEndpoint('POST', 'ListMessageTrace', undefined, body);
  } catch (err) {
    return out(truncateError(err instanceof Error ? err.message : String(err)), true);
  }

  const cleaned = stripSubjects(raw);
  const obj = cleaned !== null && typeof cleaned === 'object' && !Array.isArray(cleaned) ? (cleaned as Record<string, unknown>) : undefined;
  const results = obj?.['Results'];
  if (!Array.isArray(results)) {
    const meta = obj?.['Metadata'];
    const metaError = meta !== null && typeof meta === 'object' ? (meta as Record<string, unknown>)['Error'] : undefined;
    const reason = typeof metaError === 'string' ? metaError : typeof results === 'string' ? results : 'CIPP returned no Results array for the message trace.';
    return out(truncateError(reason), true);
  }

  const shown = results.slice(0, MESSAGE_TRACE_MAX_MESSAGES).map(pickFields);
  const truncated = results.length > MESSAGE_TRACE_MAX_MESSAGES;
  const meta = obj?.['Metadata'];
  const source = meta !== null && typeof meta === 'object' ? (meta as Record<string, unknown>)['Source'] : undefined;
  const result = {
    tenant,
    ...(typeof source === 'string' ? { source: source.slice(0, 40) } : {}),
    returned: results.length,
    shown: shown.length,
    truncated,
    ...(truncated
      ? { note: `Showing the first ${MESSAGE_TRACE_MAX_MESSAGES} of ${results.length} messages. Narrow the window or add a status or recipient filter to see the rest.` }
      : {}),
    messages: shown,
  };
  return out(`${MESSAGE_TRACE_POLICY_LINE}\n${JSON.stringify(result, null, 2)}`);
}
