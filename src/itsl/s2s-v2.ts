// IT Simply Ltd: S2S v2, the gateway signature that binds tier, user and token (new file).
//
// Upstream's v1 header signs only `t=<unix>`, so a forged x-mcp-tier header
// would pass. v2 signs the tier, user and a hash of the user token too:
//
//   x-gateway-s2s: t=<unix>,v2=<64 lower-case hex>
//   v2 = HMAC-SHA256(secret, "t=<unix>" LF "tier=<read|write>" LF
//                            "user=<x-mcp-user as received>" LF "tok=<sha256 hex of x-user-token>")
//
// LF separators, no trailing newline, UTF-8. x-mcp-user is the UPN with every
// byte outside printable ASCII 0x21-0x7E, plus '%', percent-encoded over its
// UTF-8 bytes ('@' stays raw). It is signed exactly as received and only then
// decoded for display. Clock skew allowance is 300 seconds, as in v1.
// Independent vectors (openssl, not this code) are in tests/itsl-s2s-v2.test.ts.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { CallerTier } from './tier.js';

const V2_RE = /^t=(\d{1,15}),v2=([0-9a-f]{64})$/;
const V1_RE = /^t=(\d{1,15}),v1=([0-9a-f]{64})$/;
const PRINTABLE_ASCII_RE = /^[\x21-\x7e]+$/;

export const TIER_HEADER = 'x-mcp-tier';
export const USER_HEADER = 'x-mcp-user';
export const TOKEN_HEADER = 'x-user-token';

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** The exact string that is signed. `userHeader` is the x-mcp-user value as sent (already encoded). */
export function s2sV2Message(t: number, tier: string, userHeader: string, userToken: string): string {
  return ['t=' + t, 'tier=' + tier, 'user=' + userHeader, 'tok=' + sha256Hex(userToken)].join('\n');
}

/** Encode a UPN the way the gateway does for x-mcp-user (used by tests). */
export function encodeMcpUser(upn: string): string {
  let out = '';
  for (const ch of upn) {
    const cp = ch.codePointAt(0) as number;
    if (cp >= 0x21 && cp <= 0x7e && ch !== '%') out += ch;
    else for (const b of Buffer.from(ch, 'utf8')) out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

/** Produce a v2 header value (used by tests; the gateway has its own implementation). */
export function signS2sV2(
  secret: string,
  tier: CallerTier,
  userHeader: string,
  userToken: string,
  unixSeconds: number
): string {
  const hex = createHmac('sha256', secret)
    .update(s2sV2Message(unixSeconds, tier, userHeader, userToken), 'utf8')
    .digest('hex');
  return `t=${unixSeconds},v2=${hex}`;
}

export interface VerifiedIdentity {
  tier: CallerTier;
  /** Decoded UPN, for display and logging only. */
  user: string;
}

/**
 * Verify a v2 header against the tier, user and token headers. Returns the
 * identity only when the HMAC over exactly the received values verifies;
 * otherwise undefined. The tier and user headers are NEVER trusted otherwise.
 */
export function verifyS2sV2(
  headerValue: string | undefined,
  secret: string,
  tierHeader: string | undefined,
  userHeader: string | undefined,
  tokenHeader: string | undefined,
  opts: { maxSkewSeconds?: number; nowSeconds?: number } = {}
): VerifiedIdentity | undefined {
  if (!secret || !headerValue || !tierHeader || !userHeader || !tokenHeader) return undefined;
  if (tierHeader !== 'read' && tierHeader !== 'write') return undefined;
  // The gateway sends printable ASCII only (everything else is percent-encoded).
  // Anything else (raw Latin-1 or control bytes) cannot be genuine: refuse, never throw.
  if (!PRINTABLE_ASCII_RE.test(userHeader)) return undefined;
  const match = V2_RE.exec(headerValue);
  if (!match) return undefined;
  const t = Number(match[1]);
  if (!Number.isSafeInteger(t)) return undefined;
  const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - t) > (opts.maxSkewSeconds ?? 300)) return undefined;
  const expected = createHmac('sha256', secret)
    .update(s2sV2Message(t, tierHeader, userHeader, tokenHeader), 'utf8')
    .digest();
  const provided = Buffer.from(match[2] as string, 'hex');
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return undefined;
  let user: string;
  try {
    user = decodeURIComponent(userHeader);
  } catch {
    return undefined; // malformed percent-encoding
  }
  return { tier: tierHeader, user };
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
  tokenHeader: string | undefined;
  verifyV1: (header: string | undefined, secret: string) => boolean;
}): S2sOutcome {
  const { header, secret, requireV2, tierHeader, userHeader, tokenHeader, verifyV1 } = opts;
  if (requireV2 && !secret) {
    return { ok: false, reason: 'S2S v2 is required but no CONDUIT_S2S_SECRET is configured.' };
  }
  if (!secret) return { ok: true, tier: 'read', user: undefined, version: 'none' };
  const id = verifyS2sV2(header, secret, tierHeader, userHeader, tokenHeader);
  if (id) return { ok: true, tier: id.tier, user: id.user, version: 'v2' };
  if (requireV2) {
    return { ok: false, reason: 'Missing or invalid X-Gateway-S2S v2 header.' };
  }
  if (verifyV1(header, secret)) return { ok: true, tier: 'read', user: undefined, version: 'v1' };
  return { ok: false, reason: 'Missing or invalid X-Gateway-S2S header.' };
}
