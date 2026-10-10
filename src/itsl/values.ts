// IT Simply Ltd: argument VALUE validation (new file).
//
// Many CIPP read endpoints paste argument values into Graph URLs by string
// interpolation, where `..` collapses path segments and `#` truncates the rest.
// A crafted ID value could therefore walk out of the intended Graph path (to
// BitLocker keys, LAPS passwords, mail). Every argument value of every tool call
// is checked here, centrally, before dispatch.

import { VALUE_SLASH_ALLOWED_KEYS } from './policy.js';

// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const KEY_RE = /^[A-Za-z0-9_$.\-]{1,100}$/;
const MAX_DEPTH = 8;

const SLASH_KEYS = new Set(VALUE_SLASH_ALLOWED_KEYS.map((k) => k.toLowerCase()));

/**
 * Returns an error message naming the offending key, or undefined when every
 * value is acceptable.
 *  - everywhere: no `..`, `#`, `\`, control characters
 *  - everywhere except VALUE_SLASH_ALLOWED_KEYS: no `/`, `?`, `&`, `%`
 * Recurses into arrays and objects (POST bodies); nested values take the
 * nearest key. `extraSlashKeys` lets one tool (cipp_graph_request's `endpoint`)
 * carry a path that it validates itself.
 */
export function validateArgumentValues(
  args: unknown,
  extraSlashKeys: readonly string[] = [],
  key = '(root)',
  depth = 0
): string | undefined {
  if (depth > MAX_DEPTH) return `argument '${key}' is nested too deeply.`;
  if (typeof args === 'string') return checkString(args, key, extraSlashKeys);
  if (Array.isArray(args)) {
    for (const item of args) {
      const err = validateArgumentValues(item, extraSlashKeys, key, depth + 1);
      if (err) return err;
    }
    return undefined;
  }
  if (args !== null && typeof args === 'object') {
    for (const [k, v] of Object.entries(args as Record<string, unknown>)) {
      if (!KEY_RE.test(k)) return `argument name '${k.slice(0, 40)}' contains characters that are not allowed.`;
      const err = validateArgumentValues(v, extraSlashKeys, k, depth + 1);
      if (err) return err;
    }
  }
  return undefined;
}

function checkString(value: string, key: string, extraSlashKeys: readonly string[]): string | undefined {
  const bad = (what: string) => `argument '${key}' contains ${what}, which is not allowed.`;
  if (value.includes('..')) return bad("'..'");
  if (value.includes('#')) return bad("'#'");
  if (value.includes('\\')) return bad('a backslash');
  if (CONTROL_RE.test(value)) return bad('a control character');
  const lk = key.toLowerCase();
  const slashOk = SLASH_KEYS.has(lk) || extraSlashKeys.some((k) => k.toLowerCase() === lk);
  if (!slashOk && value.includes('/')) return bad("'/'");
  if (value.includes('?')) return bad("'?'");
  if (value.includes('&')) return bad("'&'");
  if (value.includes('%')) return bad("'%'");
  return undefined;
}
