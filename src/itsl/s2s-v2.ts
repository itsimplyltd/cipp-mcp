// IT Simply Ltd: S2S v2, the gateway signature that binds tier and user (new file).
//
// Upstream's v1 header signs only `t=<unix>`, so a forged x-mcp-tier header
// would pass. v2 signs the tier and user too:
//
//   x-gateway-s2s: t=<unix>,v2=<64 hex>
//   v2 = HMAC-SHA256(secret, "t=<unix>\ntier=<read|write>\nuser=<upn>")
//
// where tier and user are the values of the x-mcp-tier and x-mcp-user headers
// of the same request. Clock skew allowance is 300 seconds, as in v1.

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { CallerTier } from './tier.js';

const V2_RE = /^t=(\d{1,15}),v2=([0-9a-f]{64})$/;
const V1_RE = /^t=(\d{1,15}),v1=([0-9a-f]{64})$/;

export const TIER_HEADER = 'x-mcp-tier';
export const USER_HEADER = 'x-mcp-user';

/** The exact string that is signed. */
export function s2sV2Message(t: number, tier: string, user: string): string {
  return `t=${t}\ntier=${tier}\nuser=${user}`;
}

/** Produce a v2 header value (used by tests; the gateway has its own implementation). */
export function signS2sV2(secret: string, tier: CallerTier, user: string, unixSeconds: number): string {
  const hex = createHmac('sha256', secret).update(s2sV2Message(unixSeconds, tier, user)).digest('hex');
  return `t=${unixSeconds},v2=${hex}`;
}

export interface VerifiedIdentity {
  tier: CallerTier;
  user: string;
}

/**
 * Verify a v2 header against the tier and user headers. Returns the identity
 * only when the HMAC over exactly those values verifies; otherwise undefined.
 * The tier and user headers are NEVER trusted on any other basis.
 */
export function verifyS2sV2(
  headerValue: string | undefined,
  secret: string,
  tierHeader: string | undefined,
  userHeader: string | undefined,
  maxSkewSeconds = 300
): VerifiedIdentity | undefined {
  if (!secret || !headerValue || !tierHeader || !userHeader) return undefined;
  if (tierHeader !== 'read' && tierHeader !== 'write') return undefined;
  // The message is newline-delimited, so a newline in the user would let one
  // signature cover several (tier, user) readings. Reject control characters.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(userHeader)) return undefined;
  const match = V2_RE.exec(headerValue);
  if (!match) return undefined;
  const t = Number(match[1]);
  if (!Number.isSafeInteger(t)) return undefined;
  if (Math.abs(Math.floor(Date.now() / 1000) - t) > maxSkewSeconds) return undefined;
  const expected = createHmac('sha256', secret).update(s2sV2Message(t, tierHeader, userHeader)).digest();
  const provided = Buffer.from(match[2] as string, 'hex');
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return undefined;
  return { tier: tierHeader, user: userHeader };
}

export function isV1Header(headerValue: string | undefined): boolean {
  return !!headerValue && V1_RE.test(headerValue);
}

export function isV2Header(headerValue: string | undefined): boolean {
  return !!headerValue && V2_RE.test(headerValue);
}

export type S2sOutcome =
  | { ok: true; tier: CallerTier; user: string | undefined; version: 'v2' | 'v1' | 'none' }
  | { ok: false; reason: string };

/**
 * The whole request-level S2S decision.
 *
 * - `requireV2` (ITSL_REQUIRE_S2S_V2=true): only a verified v2 header passes;
 *   v1, missing, malformed or forged headers are refused. A missing secret is
 *   a misconfiguration and also refuses (fail closed).
 * - otherwise, with a secret set: v2 or v1 verifies the request; the tier is
 *   trusted only from v2, and is `read` after a v1 pass.
 * - with no secret and v2 not required: enforcement is off (local dev); `read`.
 */
export function decideS2s(opts: {
  header: string | undefined;
  secret: string;
  requireV2: boolean;
  tierHeader: string | undefined;
  userHeader: string | undefined;
  verifyV1: (header: string | undefined, secret: string) => boolean;
}): S2sOutcome {
  const { header, secret, requireV2, tierHeader, userHeader, verifyV1 } = opts;
  if (requireV2 && !secret) {
    return { ok: false, reason: 'S2S v2 is required but no CONDUIT_S2S_SECRET is configured.' };
  }
  if (!secret) return { ok: true, tier: 'read', user: undefined, version: 'none' };
  const id = verifyS2sV2(header, secret, tierHeader, userHeader);
  if (id) return { ok: true, tier: id.tier, user: id.user, version: 'v2' };
  if (requireV2) {
    return { ok: false, reason: 'Missing or invalid X-Gateway-S2S v2 header.' };
  }
  if (verifyV1(header, secret)) return { ok: true, tier: 'read', user: undefined, version: 'v1' };
  return { ok: false, reason: 'Missing or invalid X-Gateway-S2S header.' };
}
