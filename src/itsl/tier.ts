// IT Simply Ltd: tier computation (new file, not derived from upstream).

import {
  BLOCKED_NAME_PATTERNS,
  BLOCKED_NAMES,
  FORCE_DISABLED,
  BLOCKED_ROLE_PATTERNS,
  MUTATION_NAME_PATTERN,
  READ_ROLE_PATTERN,
  REVIEWED,
  WRITE_ALLOWLIST,
} from './policy.js';

export type Tier = 'read' | 'write' | 'blocked' | 'disabled';

/** The tier a caller is entitled to, taken only from verified S2S v2 headers. */
export type CallerTier = 'read' | 'write';

const BLOCKED_SET = new Set(BLOCKED_NAMES.map((n) => n.toLowerCase()));
const WRITE_SET = new Set(WRITE_ALLOWLIST.map((n) => n.toLowerCase()));
const FORCE_DISABLED_SET = new Set(FORCE_DISABLED.map((n) => n.toLowerCase()));
const REVIEWED_MAP = new Map(Object.entries(REVIEWED).map(([k, v]) => [k.toLowerCase(), v]));

/**
 * Compute the tier of one CIPP endpoint. First match wins:
 *  1. blocklist (name or role pattern)  -> blocked
 *  2. write allowlist                   -> write
 *  3. read rule                         -> read
 *  4. reviewed promotion                -> read | write
 *  5. everything else                   -> disabled
 *
 * (Design order is blocklist, write allowlist, read rule, disabled; the
 * `reviewed` map sits between the read rule and disabled because it only ever
 * promotes a would-be-disabled endpoint, and blocked has already won.)
 *
 * @param name CIPP endpoint name (path segment after /api/).
 * @param role The operation's x-cipp-role, or undefined if the spec has none.
 * @param opts.hasGet Whether the endpoint has a GET operation (default true). Read requires it.
 */
export function computeTier(name: string, role: string | undefined, opts: { hasGet?: boolean } = {}): Tier {
  const hasGet = opts.hasGet ?? true;
  const lower = name.toLowerCase();
  if (BLOCKED_SET.has(lower) || BLOCKED_NAME_PATTERNS.some((p) => p.test(name))) return 'blocked';
  if (role && BLOCKED_ROLE_PATTERNS.some((p) => p.test(role))) return 'blocked';
  if (FORCE_DISABLED_SET.has(lower)) return 'disabled';
  if (WRITE_SET.has(lower)) return 'write';
  if (hasGet && role && READ_ROLE_PATTERN.test(role) && !MUTATION_NAME_PATTERN.test(name)) return 'read';
  const reviewed = REVIEWED_MAP.get(lower);
  if (reviewed) return reviewed;
  return 'disabled';
}

const RESTRICTIVENESS: Record<Tier, number> = { read: 0, write: 1, disabled: 2, blocked: 3 };

/** The most restrictive of several tiers (a tool that calls several endpoints). */
export function mostRestrictive(tiers: readonly Tier[]): Tier {
  let worst: Tier = 'read';
  for (const t of tiers) if (RESTRICTIVENESS[t] > RESTRICTIVENESS[worst]) worst = t;
  return worst;
}

/** Whether a caller with `caller` tier may run something of tier `target`. */
export function isCallable(target: Tier, caller: CallerTier): boolean {
  return target === 'read' || (target === 'write' && caller === 'write');
}

/** Why a target is refused. Never says "not found": the model must not retry another spelling. */
export function refusalReason(name: string, target: Tier, caller: CallerTier): string {
  switch (target) {
    case 'blocked':
      return `Refused: '${name}' is blocked by IT Simply policy for every user and tier (sensitive or dangerous operation).`;
    case 'disabled':
      return `Refused: '${name}' is disabled. It can change data or has not yet been reviewed by IT Simply for use through this server.`;
    case 'write':
      return `Refused: '${name}' is a write-tier operation and your gateway tier is '${caller}'. Ask IT Simply to grant the CIPP.Write role.`;
    default:
      return `Refused: '${name}' is not callable.`;
  }
}
