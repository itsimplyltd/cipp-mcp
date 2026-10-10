// IT Simply Ltd: argument VALUE validation (new file).
//
// Many CIPP read endpoints paste argument values into Graph URLs by string
// interpolation, where `..` collapses path segments and `#` truncates the rest.
// A crafted ID value could therefore walk out of the intended Graph path (to
// BitLocker keys, LAPS passwords, mail). Every argument value of every tool call
// is checked here, centrally, before dispatch.

import { VALUE_FILTER_KEYS, VALUE_SLASH_ALLOWED_KEYS } from './policy.js';

// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const KEY_RE = /^[A-Za-z0-9_$.-]{1,100}$/;
const MAX_DEPTH = 8;

/** Keys whose value must be a SharePoint https URL (R1): any key ending in "url". */
const URL_KEY_RE = /url$/i;
/** In filter/search keys, an `&` that starts a query-option shape (`&$select=`, `&x=`) is refused. */
const QUERY_OPTION_AFTER_AMP = /&\s*[$A-Za-z0-9_.-]+\s*=/;
const SHAREPOINT_URL_RE = /^https:\/\/[a-z0-9-]+(-my|-admin)?\.sharepoint\.com(\/[A-Za-z0-9._~\-/ ]*)?$/i;

const SLASH_KEYS = new Set(VALUE_SLASH_ALLOWED_KEYS.map((k) => k.toLowerCase()));
const FILTER_KEYS = new Set(VALUE_FILTER_KEYS.map((k) => k.toLowerCase()));

/**
 * Returns an error message naming the offending key, or undefined when every
 * value is acceptable.
 *  - everywhere: no `..`, backslash, control characters, `?`, `%`
 *  - `#`: refused, except the exact token `#EXT#` (case-insensitive) in filter/search keys only
 *  - `&`: only in filter/search keys, and not when it starts a query-option shape (`&name=`)
 *  - `/`: only in filter/search keys (VALUE_SLASH_ALLOWED_KEYS) and `extraSlashKeys`
 *  - keys ending "url": the value must be an https SharePoint URL
 * The `&`, `/` and `#EXT#` allowances apply ONLY to top-level string values (the
 * tool's own arguments, or the `arguments` of cipp_exec_read / cipp_exec_write), never to anything
 * nested beneath a key. Recurses into arrays and objects (POST bodies).
 *
 * NOTE: these rules assume the read-only tool set. They must be revisited
 * (passwords, out-of-office text, templates) before any write tool is enabled.
 */
export function validateArgumentValues(args: unknown, extraSlashKeys: readonly string[] = []): string | undefined {
  const tops = new Set<unknown>();
  if (args !== null && typeof args === 'object' && !Array.isArray(args)) {
    tops.add(args);
    const inner = (args as Record<string, unknown>)['arguments'];
    if (inner !== null && typeof inner === 'object' && !Array.isArray(inner)) tops.add(inner);
  }
  return walk(args, '(root)', false, 0, tops, extraSlashKeys);
}

function walk(
  node: unknown,
  key: string,
  top: boolean,
  depth: number,
  tops: Set<unknown>,
  extra: readonly string[]
): string | undefined {
  if (depth > MAX_DEPTH) return `argument '${key}' is nested too deeply.`;
  if (typeof node === 'string') return checkString(node, key, top, extra);
  if (Array.isArray(node)) {
    for (const item of node) {
      const err = walk(item, key, false, depth + 1, tops, extra);
      if (err) return err;
    }
    return undefined;
  }
  if (node !== null && typeof node === 'object') {
    const isTop = tops.has(node);
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (!KEY_RE.test(k)) return `argument name '${k.slice(0, 40)}' contains characters that are not allowed.`;
      const err = walk(v, k, isTop, depth + 1, tops, extra);
      if (err) return err;
    }
  }
  return undefined;
}

function checkString(value: string, key: string, top: boolean, extra: readonly string[]): string | undefined {
  const bad = (what: string) => `argument '${key}' contains ${what}, which is not allowed.`;
  const lk = key.toLowerCase();

  if (URL_KEY_RE.test(key)) {
    if (!SHAREPOINT_URL_RE.test(value) || value.includes('..')) {
      return `argument '${key}' must be an https SharePoint URL (https://<tenant>.sharepoint.com/...), with no query, fragment, port or credentials.`;
    }
    return undefined; // the regex excludes every character the checks below look for
  }

  if (value.includes('..')) return bad("'..'");
  if (value.includes('\\')) return bad('a backslash');
  if (CONTROL_RE.test(value)) return bad('a control character');

  const isFilter = top && FILTER_KEYS.has(lk);
  const rest = isFilter ? value.replace(/#EXT#/gi, '') : value;
  if (rest.includes('#')) return bad("'#'");

  const slashOk = top && (SLASH_KEYS.has(lk) || extra.some((k) => k.toLowerCase() === lk));
  if (!slashOk && value.includes('/')) return bad("'/'");
  if (value.includes('?')) return bad("'?'");
  if (value.includes('&') && (!isFilter || QUERY_OPTION_AFTER_AMP.test(value))) return bad("'&'");
  if (value.includes('%')) return bad("'%'");
  return undefined;
}
