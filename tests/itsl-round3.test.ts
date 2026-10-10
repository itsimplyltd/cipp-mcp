// Guard tests for fix round 3: SharePoint-only URL keys (R1), top-level-only
// allowances, "&" and #EXT# scoping, and the $format parameter.

import { validateArgumentValues } from '../src/itsl/values.js';
import { buildGraphRequest } from '../src/itsl/graph.js';

const v = (args: Record<string, unknown>) => validateArgumentValues(args);

describe('R1: keys ending "url" must be an https SharePoint URL', () => {
  const OK = [
    'https://contoso.sharepoint.com',
    'https://contoso.sharepoint.com/sites/Team Site',
    'https://contoso-my.sharepoint.com/personal/jane_contoso_com',
    'https://contoso-admin.sharepoint.com/',
    'HTTPS://Contoso.SharePoint.com/sites/a_b-c.d~e',
  ];
  const BAD = [
    'https://evil.example/exfil',
    'https://sharepoint.com.evil.example/x',
    'https://evil.example/sharepoint.com',
    'https://user@contoso.sharepoint.com/x',
    'https://contoso.sharepoint.com:443/x',
    'https://contoso.sharepoint.com/x?a=b',
    'https://contoso.sharepoint.com/x#frag',
    'https://contoso.sharepoint.com/../x',
    'https://contoso.sharepoint.com/a..b',
    'http://contoso.sharepoint.com/x',
    'https://contoso.sharepoint.com.evil.example',
    'https://contoso.sharepoint.com\@evil.example',
    '//contoso.sharepoint.com/x',
    'contoso.sharepoint.com',
    'https://a.b.sharepoint.com/x',
    'https://contoso.sharepoint.com/%2e%2e/x',
    'https://contoso.sharepoint.com/x\n',
    'https://169.254.169.254/latest/meta-data',
    '../directory',
  ];
  it.each(['siteUrl', 'SiteUrl', 'url', 'URL', 'webUrl', 'someOtherUrl'])('key %s accepts SharePoint URLs and refuses everything else', (key) => {
    for (const ok of OK) expect(v({ [key]: ok })).toBeUndefined();
    for (const bad of BAD) expect(v({ [key]: bad })).toMatch(new RegExp(`argument '${key}' must be an https SharePoint URL`));
  });

  it('applies to nested values under a url key and inside arguments of cipp_exec_tool', () => {
    expect(v({ name: 'X', arguments: { siteUrl: 'https://evil.example/x' } })).toMatch(/siteUrl/);
    expect(v({ name: 'X', arguments: { siteUrl: 'https://contoso.sharepoint.com/sites/a' } })).toBeUndefined();
    expect(v({ body: [{ webUrl: 'https://evil.example' }] })).toMatch(/webUrl/);
  });
});

describe('allowances are top-level only', () => {
  it('"/" in a filter key is fine at top level and in exec arguments, refused when nested', () => {
    expect(v({ filter: 'a/b' })).toBeUndefined();
    expect(v({ name: 'X', arguments: { $filter: 'a/b' } })).toBeUndefined();
    expect(v({ UserID: { siteurl: 'x/y' } })).toMatch(/siteurl/);
    expect(v({ UserID: { filter: 'x/y' } })).toMatch(/filter/);
    expect(v({ name: 'X', arguments: { q: { filter: 'a/b' } } })).toMatch(/filter/);
    expect(v({ filter: ['a/b'] })).toMatch(/filter/);
    expect(v({ filter: { x: 'a/b' } })).toMatch(/argument 'x'/);
  });

  it('"&" and #EXT# do not leak to nested values either', () => {
    expect(v({ filter: { x: 'a&b' } })).toMatch(/'&'/);
    expect(v({ userId: { x: 'a#EXT#b' } })).toMatch(/'#'/);
  });
});

describe('"&" is allowed in filter/search-type keys only', () => {
  it.each(['filter', '$filter', 'graphFilter', 'search', 'query', 'searchString', 'Filter', 'SEARCH'])('%s allows &', (k) => {
    expect(v({ [k]: 'AT&T' })).toBeUndefined();
  });
  it.each(['userId', 'DeviceID', 'tenantFilter', 'name', 'report', 'upn', 'Type'])('%s refuses &', (k) => {
    expect(v({ [k]: 'a&b' })).toMatch(/'&'/);
  });
});

describe('#EXT# is allowed for filter/search keys and keys ending user/upn/id; any other # is refused', () => {
  const GUEST = 'jane_contoso.com#EXT#@itsimply.onmicrosoft.com';
  it('a guest UPN passes in those keys, case-insensitively', () => {
    for (const k of ['UserID', 'userId', 'upn', 'DeviceID', 'user', 'filter', '$filter', 'search', 'graphFilter']) {
      expect(v({ [k]: GUEST })).toBeUndefined();
    }
    expect(v({ UserID: GUEST.replace('#EXT#', '#ext#') })).toBeUndefined();
  });
  it('any other # fails, even beside #EXT#', () => {
    for (const k of ['UserID', 'filter', 'upn']) {
      expect(v({ [k]: 'abc#x' })).toMatch(/'#'/);
      expect(v({ [k]: GUEST + '#' })).toMatch(/'#'/);
      expect(v({ [k]: '#EXT' })).toMatch(/'#'/);
    }
  });
  it('#EXT# is refused in other keys', () => {
    for (const k of ['tenantFilter', 'name', 'report', 'Type']) expect(v({ [k]: GUEST })).toMatch(/'#'/);
  });
  it('#EXT# does not rescue other bad characters', () => {
    expect(v({ UserID: '../x#EXT#' })).toMatch(/'\.\.'/);
    expect(v({ UserID: 'a/b#EXT#' })).toMatch(/'\/'/);
  });
});

describe('cipp_graph_request $format', () => {
  const base = { tenantFilter: 't', endpoint: 'users' };
  it('accepts exactly application/json and forwards it', () => {
    expect(buildGraphRequest({ ...base, $format: 'application/json' })).toMatchObject({ ok: true, params: { $format: 'application/json' } });
  });
  it.each(['application/xml', 'application/JSON', 'json', '', 'application/json;x=1', 5, null])('refuses %j', (f) => {
    expect(buildGraphRequest({ ...base, $format: f }).ok).toBe(false);
  });
});
