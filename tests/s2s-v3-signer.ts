/**
 * TEST HELPER ONLY. A port of the gateway signers (MCP-Gateway
 *  cred-router/src/s2sV3.js s2sHeaderV3 + canonicalV3, and cred-router/src/cippRoute.js s2sHeaderV2), kept
 * independent of the vendored verifier so the two cannot share a bug.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';

const INGRESS_EXEMPT_HEADERS = ['x-request-id'];
const sha256hex = (v: string | Buffer): string => createHash('sha256').update(v).digest('hex');

export function signV3(
  secret: string,
  p: { aud: string; method: string; path: string; body?: string; headers?: Record<string, string>; t?: number; n?: string },
): string {
  const t = p.t ?? Math.floor(Date.now() / 1000);
  const n = p.n ?? randomBytes(16).toString('hex');
  const entries = Object.entries(p.headers ?? {}).filter(([k]) => !INGRESS_EXEMPT_HEADERS.includes(k.toLowerCase()));
  const names = entries.map(([k]) => k.toLowerCase()).sort();
  const sh = names.join(';');
  const hashes: Record<string, string> = {};
  for (const [k, v] of entries) hashes[k.toLowerCase()] = sha256hex(Buffer.from(v, 'utf8'));
  const lines = [
    'ITSL-S2S-v3',
    `t=${t}`,
    `n=${n}`,
    `aud=${p.aud}`,
    `m=${p.method.toUpperCase()}`,
    `p=${p.path}`,
    `b=${sha256hex(Buffer.from(p.body ?? '', 'utf8'))}`,
    `sh=${sh}`,
    ...names.map((name) => `${name}:${hashes[name]}`),
  ];
  const v3 = createHmac('sha256', secret).update(lines.join('\n'), 'utf8').digest('hex');
  return `t=${t},n=${n},sh=${sh},v3=${v3}`;
}

/** x-mcp-user encoding: printable ASCII 0x21-0x7E stays (except '%'), everything else is %XX over UTF-8. */
export function encodeUser(upn: string): string {
  let out = '';
  for (const ch of upn) {
    const cp = ch.codePointAt(0) as number;
    if (cp >= 0x21 && cp <= 0x7e && ch !== '%') out += ch;
    else for (const b of Buffer.from(ch, 'utf8')) out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

/** v2: HMAC over t, tier, the encoded user and sha256(token). */
export function signV2(secret: string, p: { tier: 'read' | 'write'; upn: string; userToken: string; t?: number }): string {
  const t = p.t ?? Math.floor(Date.now() / 1000);
  const tok = sha256hex(p.userToken);
  const v2 = createHmac('sha256', secret).update(`t=${t}\ntier=${p.tier}\nuser=${encodeUser(p.upn)}\ntok=${tok}`, 'utf8').digest('hex');
  return `t=${t},v2=${v2}`;
}

/** v1: only a timestamp is signed. Used to prove it is refused. */
export function signV1(secret: string, t: number = Math.floor(Date.now() / 1000)): string {
  return `t=${t},v1=${createHmac('sha256', secret).update(`t=${t}`).digest('hex')}`;
}
