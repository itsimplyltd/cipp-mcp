// Read-tier audit tools (cipp_get_authorization_policy and six more) and the ListDBCache type allow-list.

// tenantFilter canonicalisation has its own suite (itsl-tenant.test.ts); here it is a passthrough.
jest.mock('../src/itsl/tenant.js', () => ({
  canonicaliseTenantArgs: async (args: Record<string, unknown>) => ({ ok: true, args }),
}));

import { readFileSync } from 'fs';
import { join } from 'path';
import fixture from './fixtures/openapi-fixture.json';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { Logger } from '../src/utils/logger.js';
import { catalogueStore } from '../src/itsl/catalogue.js';
import { META_TOOL_DEFINITIONS, namedToolEndpointsMissingRoles, ToolContext } from '../src/itsl/meta-tools.js';
import { AUDIT_TOOL_ENDPOINTS, KNOWN_ENDPOINT_ROLES, namedToolTier } from '../src/itsl/named-tools.js';
import { DBCACHE_ALLOWED_TYPES } from '../src/itsl/policy.js';
import { AUDIT_MAX_ROWS, AUDIT_TOOL_NAMES, restrictDbCache } from '../src/itsl/audit-tools.js';
import { buildGraphRequest } from '../src/itsl/graph.js';
import { errorResponse, jsonResponse } from './helpers.js';

const READ: ToolContext = { tier: 'read', user: 'r@example.com' };
const WRITE: ToolContext = { tier: 'write', user: 'w@example.com' };
type FetchMock = jest.Mock<Promise<Response>, [string, RequestInit?]>;
let fetchMock: FetchMock;
let svc: CippService;
let graph: Record<string, unknown>; // by Endpoint (lower case) -> Results rows, or an Error
let cache: Record<string, unknown[]>; // by type
let cacheCounts: Record<string, unknown[]>;

const role = (r: string, method: 'get' | 'post' = 'get') => ({
  [method]: { summary: 'x', operationId: 'x', tags: ['CIPP > Core'], description: 'x', 'x-cipp-role': r, parameters: [] },
});
const withParams = (r: Record<string, any>, names: string[]) => {
  r['get'].parameters = names.map((name) => ({ name, in: 'query', required: false, schema: { type: 'string' }, description: name }));
  return r;
};
const spec = {
  ...fixture,
  paths: {
    ...fixture.paths,
    '/api/ListDBCache': withParams(role('CIPP.Core.Read'), ['tenantFilter', 'type', 'countsOnly', 'select', 'top', 'groupBy', 'latestOnly', 'dateField']),
    '/api/ListGraphRequest': role('CIPP.Core.Read'),
    '/api/ListExoRequest': role('CIPP.Core.Read', 'post'),
  },
};

const SP = '11111111-2222-3333-4444-555555555555';
const OK = { tenantFilter: 'client.example' };

const graphCalls = () => fetchMock.mock.calls.filter(([u]) => u.includes('/api/ListGraphRequest'));
const dbCalls = () => fetchMock.mock.calls.filter(([u]) => u.includes('/api/ListDBCache'));
const dataCalls = () => [...graphCalls(), ...dbCalls()];
const q = (call: [string, RequestInit?]) => new URL(call[0]).searchParams;

beforeEach(() => {
  catalogueStore.reset();
  graph = {};
  cache = {};
  cacheCounts = {};
  fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>((url) => {
    if (url.includes('/api/ListOpenApiSpec')) return Promise.resolve(jsonResponse(spec));
    const params = new URL(url).searchParams;
    if (url.includes('/api/ListGraphRequest')) {
      const r = graph[(params.get('Endpoint') ?? '').toLowerCase()];
      if (r instanceof Error) return Promise.resolve(errorResponse(500, r.message));
      return Promise.resolve(jsonResponse({ Results: r ?? [], Metadata: {} }));
    }
    if (url.includes('/api/ListDBCache')) {
      const type = params.get('type') ?? '';
      if (params.get('countsOnly') === 'true') return Promise.resolve(jsonResponse({ Results: cacheCounts[type] ?? [] }));
      return Promise.resolve(jsonResponse({ Results: cache[type] ?? [] }));
    }
    return Promise.resolve(jsonResponse({}));
  });
  global.fetch = fetchMock as unknown as typeof fetch;
  svc = new CippService({ cipp: { baseUrl: 'https://cipp.example', apiKey: 'tok' } }, new Logger('error'));
});
afterEach(() => jest.restoreAllMocks());

const handler = (ctx: ToolContext) => new CippToolHandler(svc, new Logger('error'), ctx);
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;
const json = (r: { content: Array<{ text: string }> }) => JSON.parse(text(r).split('\n').slice(1).join('\n'));
const run = (tool: string, args: Record<string, unknown> = OK, ctx = READ) => handler(ctx).handleToolCall(tool, args);

const AUTHZ = 'cipp_get_authorization_policy';
const GRANTS = 'cipp_list_delegated_grants';
const ROLES = 'cipp_list_app_role_assignments';
const APPS = 'cipp_list_app_registrations';
const CONSENT = 'cipp_get_consent_policies';
const XT = 'cipp_get_cross_tenant_policy';
const SPAM = 'cipp_get_outbound_spam_policy';
const ARGS: Record<string, Record<string, unknown>> = {
  [AUTHZ]: OK,
  [GRANTS]: OK,
  [ROLES]: { ...OK, servicePrincipalId: SP },
  [APPS]: OK,
  [CONSENT]: OK,
  [XT]: OK,
  [SPAM]: OK,
};

describe('listing, annotations and schema', () => {
  it('the seven tools are exactly the audit tools', () => {
    expect([...AUDIT_TOOL_NAMES].sort()).toEqual([AUTHZ, GRANTS, ROLES, APPS, CONSENT, XT, SPAM].sort());
  });

  it.each(AUDIT_TOOL_NAMES)('%s is listed for read and write callers, read-only annotated', (tool) => {
    for (const ctx of [READ, WRITE]) {
      const def = handler(ctx).getToolDefinitions().find((t) => t.name === tool);
      expect(def).toBeDefined();
      expect(def!.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
    }
  });

  it.each(AUDIT_TOOL_NAMES)('%s takes tenantFilter only (plus servicePrincipalId for the app role tool) and nothing else', (tool) => {
    const def = META_TOOL_DEFINITIONS.find((t) => t.name === tool)!;
    const schema = def.inputSchema as { properties: Record<string, unknown>; required: string[]; additionalProperties: boolean };
    const expected = tool === ROLES ? ['servicePrincipalId', 'tenantFilter'] : ['tenantFilter'];
    expect(Object.keys(schema.properties).sort()).toEqual(expected);
    expect([...schema.required].sort()).toEqual(expected);
    expect(schema.additionalProperties).toBe(false);
  });

  it('the spam tool says its data is CIPP\'s cached copy, about 24 hours old, refreshed by the write-tier sync', () => {
    const d = META_TOOL_DEFINITIONS.find((t) => t.name === SPAM)!.description;
    expect(d).toMatch(/CACHED/);
    expect(d).toMatch(/24 hours/);
    expect(d).toMatch(/write-tier/);
  });

  it('every tool is mentioned once in the server instructions', () => {
    const server = readFileSync(join(__dirname, '..', 'src', 'mcp', 'server.ts'), 'utf8');
    for (const t of AUDIT_TOOL_NAMES) expect(server.split(`- ${t}:`).length - 1).toBe(1);
  });
});

describe('tier and CIPP role mapping', () => {
  it.each(AUDIT_TOOL_NAMES)('%s is read tier and maps to read-role GET endpoints only', (tool) => {
    expect(namedToolTier(tool)).toBe('read');
    for (const ep of AUDIT_TOOL_ENDPOINTS[tool]!) {
      expect(KNOWN_ENDPOINT_ROLES[ep]).toBe('CIPP.Core.Read');
      expect(KNOWN_ENDPOINT_ROLES[ep]).toMatch(/\.Read$/);
      expect(ep).not.toMatch(/^Exec/);
    }
  });

  it('the role table covers every audit endpoint', () => {
    expect(namedToolEndpointsMissingRoles()).toEqual([]);
  });

  it('the live spec can only make it more restrictive: a ReadWrite role there makes the tool unavailable', async () => {
    const strict = { ...spec, paths: { ...spec.paths, '/api/ListDBCache': role('CIPP.Core.ReadWrite') } };
    fetchMock.mockImplementation((url) => Promise.resolve(jsonResponse(url.includes('/api/ListOpenApiSpec') ? strict : { Results: [] })));
    await handler(READ).handleToolCall('cipp_search_tools', {}); // loads the live spec
    const res = await run(SPAM);
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/Refused/);
  });

  it('ListGraphRequest and ListExoRequest are still blocked for cipp_exec_read and cipp_exec_write, both tiers', async () => {
    for (const [ctx, tool] of [[READ, 'cipp_exec_read'], [WRITE, 'cipp_exec_read'], [WRITE, 'cipp_exec_write']] as const) {
      for (const name of ['ListGraphRequest', 'ListExoRequest', 'listgraphrequest', 'LISTEXOREQUEST']) {
        const res = await handler(ctx).handleToolCall(tool, { name, arguments: { tenantFilter: 't.example', Endpoint: 'servicePrincipals' } });
        expect(res.isError).toBe(true);
        expect(text(res)).toMatch(/blocked/);
      }
    }
    expect(dataCalls()).toEqual([]);
  });

  it('cipp_graph_request still refuses oauth2PermissionGrants and content subpaths (allow-list unchanged)', () => {
    for (const endpoint of ['oauth2PermissionGrants', 'users/x/messages', 'users/x/mailFolders', 'sites/x/drive', 'users/x/calendar/events']) {
      expect(buildGraphRequest({ tenantFilter: 't.example', endpoint }).ok).toBe(false);
    }
  });
});

describe('the exact CIPP request of each tool', () => {
  it('authorization policy: one fixed beta Graph GET', async () => {
    graph['policies/authorizationpolicy'] = [{ id: 'authorizationPolicy' }];
    const res = await run(AUTHZ);
    expect(res.isError).toBeUndefined();
    expect(graphCalls()).toHaveLength(1);
    const p = q(graphCalls()[0]!);
    expect(Object.fromEntries(p)).toEqual({ tenantFilter: 'client.example', Endpoint: 'policies/authorizationPolicy', Version: 'beta' });
  });

  it('delegated grants: beta oauth2PermissionGrants with $top=999 only, as CIPP own cache read does', async () => {
    await run(GRANTS);
    expect(Object.fromEntries(q(graphCalls()[0]!))).toEqual({
      tenantFilter: 'client.example',
      Endpoint: 'oauth2PermissionGrants',
      Version: 'beta',
      $top: '999',
    });
  });

  it('app role assignments: the GUID in the fixed path, lower-cased', async () => {
    await run(ROLES, { ...OK, servicePrincipalId: SP.toUpperCase() });
    expect(Object.fromEntries(q(graphCalls()[0]!))).toEqual({
      tenantFilter: 'client.example',
      Endpoint: `servicePrincipals/${SP}/appRoleAssignments`,
      Version: 'beta',
    });
  });

  it('app registrations: applications with a fixed select and owners limited to id and userPrincipalName', async () => {
    await run(APPS);
    expect(Object.fromEntries(q(graphCalls()[0]!))).toEqual({
      tenantFilter: 'client.example',
      Endpoint: 'applications',
      Version: 'beta',
      $top: '999',
      $select: 'id,appId,displayName,createdDateTime,signInAudience,publisherDomain,passwordCredentials,keyCredentials',
      $expand: 'owners($select=id,userPrincipalName)',
    });
  });

  it('consent policies: two fixed v1.0 Graph GETs', async () => {
    await run(CONSENT);
    expect(graphCalls().map((c) => q(c).get('Endpoint'))).toEqual(['policies/permissionGrantPolicies', 'policies/adminConsentRequestPolicy']);
    for (const c of graphCalls()) {
      expect(q(c).get('Version')).toBe('beta');
      expect([...q(c).keys()].sort()).toEqual(['Endpoint', 'Version', 'tenantFilter']);
    }
  });

  it('cross-tenant policy: the default policy only', async () => {
    graph['policies/crosstenantaccesspolicy/default'] = [{ isServiceDefault: true }];
    await run(XT);
    expect(Object.fromEntries(q(graphCalls()[0]!))).toEqual({
      tenantFilter: 'client.example',
      Endpoint: 'policies/crossTenantAccessPolicy/default',
      Version: 'beta',
    });
  });

  it('$top is sent only on grants and applications: never on singletons or other collections', async () => {
    graph['policies/authorizationpolicy'] = [{ id: 'a' }];
    graph['policies/crosstenantaccesspolicy/default'] = [{ isServiceDefault: true }];
    for (const tool of AUDIT_TOOL_NAMES) await run(tool, ARGS[tool]!);
    const withTop = graphCalls().filter((c) => q(c).has('$top')).map((c) => q(c).get('Endpoint'));
    expect(withTop.sort()).toEqual(['applications', 'oauth2PermissionGrants']);
    const withSelect = graphCalls().filter((c) => q(c).has('$select')).map((c) => q(c).get('Endpoint'));
    expect(withSelect).toEqual(['applications']);
    for (const c of graphCalls()) expect(q(c).get('Version')).toBe('beta');
  });

  it('outbound spam policy: ListDBCache with the fixed type, then the same type for the timestamp; never ListExoRequest', async () => {
    await run(SPAM);
    expect(dbCalls().map((c) => Object.fromEntries(q(c)))).toEqual([
      { tenantFilter: 'client.example', type: 'ExoHostedOutboundSpamFilterPolicy' },
      { tenantFilter: 'client.example', type: 'ExoHostedOutboundSpamFilterPolicy', countsOnly: 'true' },
    ]);
    expect(fetchMock.mock.calls.some(([u]) => u.includes('ListExoRequest'))).toBe(false);
  });

  it('read and write callers can both run each tool; the result is framed', async () => {
    graph['policies/authorizationpolicy'] = [{ id: 'authorizationPolicy' }];
    graph['policies/crosstenantaccesspolicy/default'] = [{ isServiceDefault: true }];
    for (const tool of AUDIT_TOOL_NAMES) {
      for (const ctx of [READ, WRITE]) {
        const res = await run(tool, ARGS[tool]!, ctx);
        expect(res.isError).toBeUndefined();
        expect(text(res)).toMatch(/^\[CIPP data for tenant client\.example/);
      }
    }
  });
});

describe('projection: unknown fields are dropped, credential values never appear', () => {
  const TRAPS = {
    secretText: 'SECRET-VALUE-1',
    key: 'KEY-VALUE-2',
    customKeyIdentifier: 'CKI-3',
    passwordProfile: { password: 'PW-4' },
    clientSecret: 'CS-5',
    extraField: 'EXTRA',
  };

  it('authorization policy keeps the named fields, scalar permissions and nothing else', async () => {
    graph['policies/authorizationpolicy'] = [
      {
        '@odata.context': 'x',
        id: 'authorizationPolicy',
        displayName: 'Authorization Policy',
        description: 'dropped',
        allowInvitesFrom: 'everyone',
        allowedToSignUpEmailBasedSubscriptions: true,
        allowedToUseSSPR: true,
        allowEmailVerifiedUsersToJoinOrganization: true,
        allowUserConsentForRiskyApps: false,
        blockMsolPowerShell: false,
        guestUserRoleId: 'g-1',
        enabledPreviewFeatures: ['a'],
        permissionGrantPolicyIdsAssignedToDefaultUserRole: ['p1', 'p2'],
        defaultUserRolePermissions: {
          allowedToCreateApps: true,
          allowedToCreateAgentIdentityBlueprints: true,
          allowedToCreateSecurityGroups: true,
          allowedToCreateTenants: true,
          allowedToReadBitlockerKeysForOwnedDevice: true,
          allowedToReadOtherUsers: true,
          nested: { x: 1 },
          someFutureFlag: 'new-value',
          anotherNewBoolean: true,
        },
        ...TRAPS,
      },
    ];
    const body = json(await run(AUTHZ));
    expect(body.policy).toEqual({
      id: 'authorizationPolicy',
      displayName: 'Authorization Policy',
      allowInvitesFrom: 'everyone',
      allowedToSignUpEmailBasedSubscriptions: true,
      allowedToUseSSPR: true,
      allowEmailVerifiedUsersToJoinOrganization: true,
      allowUserConsentForRiskyApps: false,
      blockMsolPowerShell: false,
      guestUserRoleId: 'g-1',
      enabledPreviewFeatures: ['a'],
      permissionGrantPolicyIdsAssignedToDefaultUserRole: ['p1', 'p2'],
      defaultUserRolePermissions: {
        allowedToCreateApps: true,
        allowedToCreateAgentIdentityBlueprints: true,
        allowedToCreateSecurityGroups: true,
        allowedToCreateTenants: true,
        allowedToReadBitlockerKeysForOwnedDevice: true,
        allowedToReadOtherUsers: true,
      },
    });
  });

  it('delegated grants keep six fields', async () => {
    graph['oauth2permissiongrants'] = [{ id: 'g1', clientId: 'c', resourceId: 'r', consentType: 'AllPrincipals', principalId: null, scope: 'User.Read', expiryTime: 'x', ...TRAPS }];
    const body = json(await run(GRANTS));
    expect(body.grants).toEqual([{ id: 'g1', clientId: 'c', resourceId: 'r', consentType: 'AllPrincipals', principalId: null, scope: 'User.Read' }]);
    expect(body.returned).toBe(1);
    expect(body.truncated).toBe(false);
  });

  it('a grant scope is NEVER cut, however long (the last scope is the finding)', async () => {
    const scope = Array.from({ length: 300 }, (_, i) => `Scope.Number${i}`).join(' ') + ' Mail.ReadWrite';
    expect(scope.length).toBeGreaterThan(4096);
    graph['oauth2permissiongrants'] = [{ id: 'g1', clientId: 'c', resourceId: 'r', consentType: 'AllPrincipals', principalId: null, scope }];
    const body = json(await run(GRANTS));
    expect(body.grants[0].scope).toBe(scope);
    expect(body.grants[0].scope.endsWith('Mail.ReadWrite')).toBe(true);
    expect(body.truncated).toBe(false);
  });

  it('app role assignments keep six fields', async () => {
    graph[`serviceprincipals/${SP}/approleassignments`] = [
      { resourceId: 'r', resourceDisplayName: 'Graph', appRoleId: 'a', principalId: 'p', principalDisplayName: 'App', createdDateTime: 'd', id: 'dropped', ...TRAPS },
    ];
    const body = json(await run(ROLES, ARGS[ROLES]!));
    expect(body.assignments).toEqual([{ resourceId: 'r', resourceDisplayName: 'Graph', appRoleId: 'a', principalId: 'p', principalDisplayName: 'App', createdDateTime: 'd' }]);
    expect(body.servicePrincipalId).toBe(SP);
  });

  it('app registrations: credentials keep five fields, owners keep id and userPrincipalName, no value ever appears', async () => {
    graph['applications'] = [
      {
        id: 'o1',
        appId: 'a1',
        displayName: 'App',
        createdDateTime: 'c',
        signInAudience: 'AzureADMyOrg',
        publisherDomain: 'client.example',
        tags: ['dropped'],
        web: { redirectUris: ['https://x'] },
        passwordCredentials: [
          { keyId: 'k1', displayName: 'secret', startDateTime: 's', endDateTime: 'e', hint: 'HNT-ZZ', secretText: 'SECRET-VALUE-1', customKeyIdentifier: 'CKI-3', key: 'KEY-VALUE-2' },
        ],
        keyCredentials: [
          { keyId: 'k2', displayName: 'cert', startDateTime: 's', endDateTime: 'e', hint: 'HNT-YY', key: 'KEY-VALUE-2', customKeyIdentifier: 'CKI-3', type: 'AsymmetricX509Cert', usage: 'Verify' },
        ],
        owners: [{ '@odata.type': 'x', id: 'u1', userPrincipalName: 'a@client.example', mail: 'dropped@x', passwordProfile: { password: 'PW-4' } }],
        ...TRAPS,
      },
    ];
    const res = await run(APPS);
    const body = json(res);
    expect(body.applications).toEqual([
      {
        id: 'o1',
        appId: 'a1',
        displayName: 'App',
        createdDateTime: 'c',
        signInAudience: 'AzureADMyOrg',
        publisherDomain: 'client.example',
        passwordCredentials: [{ keyId: 'k1', displayName: 'secret', startDateTime: 's', endDateTime: 'e' }],
        keyCredentials: [{ keyId: 'k2', displayName: 'cert', startDateTime: 's', endDateTime: 'e' }],
        owners: [{ id: 'u1', userPrincipalName: 'a@client.example' }],
      },
    ]);
    for (const v of ['SECRET-VALUE-1', 'KEY-VALUE-2', 'CKI-3', 'PW-4', 'CS-5', 'EXTRA', 'dropped', 'HNT-ZZ', 'HNT-YY', 'hint']) expect(text(res)).not.toContain(v);
  });

  it('consent policies keep conditions and the admin consent workflow fields', async () => {
    graph['policies/permissiongrantpolicies'] = [
      {
        id: 'microsoft-user-default-low',
        displayName: 'Low',
        description: 'd',
        deletedDateTime: 'dropped',
        includeAllPreApprovedApplications: false,
        resourceScopeType: 'tenant',
        includes: [{ id: 'i1', permissionType: 'delegated', permissionClassification: 'low', resourceApplication: 'any', permissions: ['all'], clientApplicationIds: ['a'], clientApplicationTenantIds: ['t'], clientApplicationPublisherIds: ['p'], clientApplicationsFromVerifiedPublisherOnly: true, certifiedClientApplicationsOnly: true, scopeSensitivityLabels: { labelKind: 'dropped' }, other: 'dropped' }],
        excludes: [],
      },
    ];
    graph['policies/adminconsentrequestpolicy'] = [
      { '@odata.context': 'x', isEnabled: true, notifyReviewers: true, remindersEnabled: false, requestDurationInDays: 30, version: 2, reviewers: [{ query: '/users/u1', queryType: 'MicrosoftGraph', queryRoot: null, junk: 'dropped' }], ...TRAPS },
    ];
    const res = await run(CONSENT);
    const body = json(res);
    expect(body.permissionGrantPolicies).toEqual([
      {
        id: 'microsoft-user-default-low',
        displayName: 'Low',
        description: 'd',
        includeAllPreApprovedApplications: false,
        resourceScopeType: 'tenant',
        includes: [{ id: 'i1', permissionType: 'delegated', permissionClassification: 'low', resourceApplication: 'any', permissions: ['all'], clientApplicationIds: ['a'], clientApplicationTenantIds: ['t'], clientApplicationPublisherIds: ['p'], clientApplicationsFromVerifiedPublisherOnly: true, certifiedClientApplicationsOnly: true }],
        excludes: [],
      },
    ]);
    expect(body.adminConsentRequestPolicy).toEqual({
      isEnabled: true,
      notifyReviewers: true,
      remindersEnabled: false,
      requestDurationInDays: 30,
      version: 2,
      reviewers: [{ query: '/users/u1', queryType: 'MicrosoftGraph', queryRoot: null }],
    });
    expect(text(res)).not.toContain('dropped');
    expect(text(res)).not.toContain('SECRET-VALUE-1');
  });

  it('consent policies report one half failing without hiding the other', async () => {
    graph['policies/permissiongrantpolicies'] = new Error('Forbidden by CIPP');
    graph['policies/adminconsentrequestpolicy'] = [{ isEnabled: false }];
    const res = await run(CONSENT);
    expect(res.isError).toBeUndefined();
    const body = json(res);
    expect(body.permissionGrantPoliciesError).toMatch(/Forbidden/);
    expect(body.adminConsentRequestPolicy).toEqual({ isEnabled: false });
  });

  it('cross-tenant policy: an explicit nested field list; unknown keys at any level are dropped', async () => {
    const access = (type: string) => ({
      usersAndGroups: { accessType: type, targets: [{ target: 'AllUsers', targetType: 'user', secretThing: 'dropped' }], anyNewField: 'dropped' },
      applications: { accessType: type, targets: [{ target: 'AllApplications', targetType: 'application' }] },
      newBlock: { x: 'dropped' },
    });
    graph['policies/crosstenantaccesspolicy/default'] = [
      {
        '@odata.context': 'x',
        id: 'dropped-id',
        isServiceDefault: true,
        blockServiceProviderOutboundAccess: false,
        inboundTrust: { isMfaAccepted: true, isCompliantDeviceAccepted: false, isHybridAzureADJoinedDeviceAccepted: false, isCompliantNetworkAccepted: false, futureFlag: 'dropped' },
        b2bCollaborationInbound: access('allowed'),
        b2bCollaborationOutbound: access('allowed'),
        b2bDirectConnectInbound: access('blocked'),
        b2bDirectConnectOutbound: access('blocked'),
        automaticUserConsentSettings: { inboundAllowed: true, outboundAllowed: null, extra: 'dropped' },
        tenantRestrictions: { devices: null, usersAndGroups: { accessType: 'blocked', targets: [{ target: 'AllUsers', targetType: 'user' }] }, applications: { accessType: 'blocked', targets: [] } },
        invitationRedemptionIdentityProviderConfiguration: { secret: 'dropped' },
        crossCloudMeetingConfiguration: { inboundAllowed: true },
        ...TRAPS,
      },
    ];
    const res = await run(XT);
    const body = json(res);
    expect(Object.keys(body.policy).sort()).toEqual(
      ['automaticUserConsentSettings', 'b2bCollaborationInbound', 'b2bCollaborationOutbound', 'b2bDirectConnectInbound', 'b2bDirectConnectOutbound', 'inboundTrust', 'isServiceDefault', 'tenantRestrictions'].sort()
    );
    expect(body.policy.inboundTrust).toEqual({ isMfaAccepted: true, isCompliantDeviceAccepted: false, isHybridAzureADJoinedDeviceAccepted: false, isCompliantNetworkAccepted: false });
    expect(body.policy.b2bCollaborationInbound).toEqual({
      usersAndGroups: { accessType: 'allowed', targets: [{ target: 'AllUsers', targetType: 'user' }] },
      applications: { accessType: 'allowed', targets: [{ target: 'AllApplications', targetType: 'application' }] },
    });
    expect(body.policy.automaticUserConsentSettings).toEqual({ inboundAllowed: true, outboundAllowed: null });
    expect(body.policy.tenantRestrictions).toEqual({
      usersAndGroups: { accessType: 'blocked', targets: [{ target: 'AllUsers', targetType: 'user' }] },
      applications: { accessType: 'blocked', targets: [] },
      devices: null,
    });
    expect(text(res)).not.toContain('dropped');
  });

  it('outbound spam policy keeps seven fields and the cache timestamp', async () => {
    cache['ExoHostedOutboundSpamFilterPolicy'] = [
      {
        Name: 'Default',
        IsDefault: true,
        AutoForwardingMode: 'Automatic',
        RecipientLimitExternalPerHour: 500,
        RecipientLimitInternalPerHour: 1000,
        RecipientLimitPerDay: 1000,
        ActionWhenThresholdReached: 'BlockUser',
        NotifyOutboundSpamRecipients: ['dropped@x'],
        DistinguishedName: 'dropped',
        'RecipientLimitPerDay@odata.type': '#Decimal',
      },
    ];
    cacheCounts['ExoHostedOutboundSpamFilterPolicy'] = [{ Tenant: 'client.example', Type: 'ExoHostedOutboundSpamFilterPolicy', Count: 1, LastRefresh: '2026-10-17T15:15:59Z' }];
    const res = await run(SPAM);
    const body = json(res);
    expect(body.cachedAt).toBe('2026-10-17T15:15:59Z');
    expect(body.policies).toEqual([
      { Name: 'Default', IsDefault: true, AutoForwardingMode: 'Automatic', RecipientLimitExternalPerHour: 500, RecipientLimitInternalPerHour: 1000, RecipientLimitPerDay: 1000, ActionWhenThresholdReached: 'BlockUser' },
    ]);
    expect(text(res)).not.toContain('dropped');
    expect(body.source).toMatch(/24 hours/);
  });

  it('outbound spam policy: an empty cache is said so and cachedAt is null', async () => {
    const body = json(await run(SPAM));
    expect(body.policies).toEqual([]);
    expect(body.cachedAt).toBeNull();
    expect(body.note).toMatch(/cache holds no outbound spam policy/);
  });

  it('a long string other than scope is cut, flagged in truncatedFields, and the text says so', async () => {
    graph['oauth2permissiongrants'] = [{ id: 'g1', clientId: 'c'.repeat(5000), scope: 's' }];
    const res = await run(GRANTS);
    const body = json(res);
    expect(body.grants[0].clientId).toHaveLength(4096);
    expect(body.truncated).toBe(true);
    expect(body.truncatedFields).toEqual(['clientId']);
    expect(body.note).toMatch(/TRUNCATED: some values were cut \(clientId\)/);
  });

  it('a long array is cut, flagged and named', async () => {
    graph['policies/permissiongrantpolicies'] = [
      { id: 'p1', displayName: 'x', includes: [{ id: 'i', permissions: Array.from({ length: 600 }, (_, i) => `perm${i}`) }], excludes: [] },
    ];
    graph['policies/adminconsentrequestpolicy'] = [{ isEnabled: false }];
    const body = json(await run(CONSENT));
    expect(body.permissionGrantPolicies[0].includes[0].permissions).toHaveLength(500);
    expect(body.truncated).toBe(true);
    expect(body.truncatedFields).toEqual(['conditions.permissions']);
  });

  it('an app with 20 owners (the Graph expand limit) is flagged ownersTruncated', async () => {
    const owners = Array.from({ length: 20 }, (_, i) => ({ id: `u${i}`, userPrincipalName: `u${i}@client.example` }));
    graph['applications'] = [
      { id: 'a1', displayName: 'Many owners', owners },
      { id: 'a2', displayName: 'Few owners', owners: owners.slice(0, 3) },
    ];
    const body = json(await run(APPS));
    expect(body.applications[0].ownersTruncated).toBe(true);
    expect(body.applications[1].ownersTruncated).toBeUndefined();
    expect(body.truncated).toBe(true);
    expect(body.truncatedFields).toEqual(['owners']);
  });

  it('a long list is truncated and says so', async () => {
    graph['oauth2permissiongrants'] = Array.from({ length: AUDIT_MAX_ROWS + 5 }, (_, i) => ({ id: `g${i}`, scope: 's' }));
    const body = json(await run(GRANTS));
    expect(body.returned).toBe(AUDIT_MAX_ROWS + 5);
    expect(body.shown).toBe(AUDIT_MAX_ROWS);
    expect(body.truncated).toBe(true);
    expect(body.truncatedFields).toEqual(['grants (rows)']);
    expect(body.note).toMatch(/TRUNCATED/);
    expect(body.grants).toHaveLength(AUDIT_MAX_ROWS);
  });

  it('a CIPP error is returned truncated and framed', async () => {
    graph['oauth2permissiongrants'] = new Error('x'.repeat(2000));
    const res = await run(GRANTS);
    expect(res.isError).toBe(true);
    expect(text(res).length).toBeLessThan(700);
  });
});

describe('refusals', () => {
  const refused = async (tool: string, args: Record<string, unknown>, match: RegExp) => {
    const res = await run(tool, args);
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(match);
    expect(dataCalls()).toEqual([]);
  };

  describe.each(AUDIT_TOOL_NAMES)('%s', (tool) => {
    const base = ARGS[tool]!;
    it.each(['AllTenants', 'alltenants', ' ALLTENANTS '])('refuses tenantFilter %p', async (t) => {
      await refused(tool, { ...base, tenantFilter: t }, /AllTenants is not allowed/);
    });
    it.each(['Endpoint', 'endpoint', 'select', '$select', 'filter', 'expand', 'top', 'type', 'Version', 'cmdlet', 'days', 'somethingElse'])('refuses the extra argument %s', async (k) => {
      await refused(tool, { ...base, [k]: 'x' }, new RegExp(`unexpected or repeated argument '${k.replace('$', '\\$')}'`));
    });
    it('refuses a missing tenant', async () => refused(tool, { ...base, tenantFilter: undefined }, /tenantFilter/));
    it('refuses a malformed tenant', async () => refused(tool, { ...base, tenantFilter: 'a b' }, /tenantFilter must be/));
    it('refuses a duplicate tenantFilter in another casing', async () => refused(tool, { ...base, TenantFilter: 'x.example' }, /unexpected or repeated/));
  });

  it('only the app role tool accepts servicePrincipalId', async () => {
    for (const tool of AUDIT_TOOL_NAMES.filter((t) => t !== ROLES)) {
      await refused(tool, { ...OK, servicePrincipalId: SP }, /unexpected or repeated argument 'servicePrincipalId'/);
    }
  });

  it.each([
    'not-a-guid',
    '',
    `${SP}/appRoleAssignments`,
    `${SP}/../x`,
    `${SP}?x=1`,
    '../' + SP,
    `{${SP}}`,
    ` x${SP}`,
    SP.slice(1),
    `${SP},${SP}`,
    '*',
    'me',
  ])('refuses the bad servicePrincipalId %p', async (id) => {
    await refused(ROLES, { ...OK, servicePrincipalId: id }, /servicePrincipalId|not allowed/);
  });

  it('refuses a non-string servicePrincipalId and a missing one', async () => {
    await refused(ROLES, { ...OK, servicePrincipalId: 5 }, /GUID/);
    await refused(ROLES, OK, /GUID/);
  });
});

describe('ListDBCache type allow-list through cipp_exec_read', () => {
  const exec = (args: Record<string, unknown>, ctx = READ, tool = 'cipp_exec_read') =>
    handler(ctx).handleToolCall(tool, { name: 'ListDBCache', arguments: { tenantFilter: 'client.example', ...args } });

  it('the allow-list is exactly the seven reviewed types', () => {
    expect([...DBCACHE_ALLOWED_TYPES].sort()).toEqual(
      ['AdminConsentRequestPolicy', 'AppRoleAssignments', 'AuthorizationPolicy', 'CrossTenantAccessPolicy', 'ExoHostedOutboundSpamFilterPolicy', 'OAuth2PermissionGrants', 'PermissionGrantPolicies'].sort()
    );
  });

  it.each(DBCACHE_ALLOWED_TYPES)('allows %s, for read and write callers', async (type) => {
    for (const ctx of [READ, WRITE]) {
      fetchMock.mockClear();
      const res = await exec({ type }, ctx);
      expect(res.isError).toBeUndefined();
      expect(dbCalls()).toHaveLength(1);
      expect(q(dbCalls()[0]!).get('type')).toBe(type);
    }
  });

  it.each(['Apps', 'BitlockerKeys', 'MailboxRules', 'MailboxPermissions', 'CalendarPermissions', 'Users', 'Groups', 'ServicePrincipals', 'Mailboxes', '_availableTypes', '_shape', 'SomethingNew', ''])(
    'refuses the type %p by name',
    async (type) => {
      const res = await exec({ type });
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/Refused: ListDBCache/);
      expect(text(res)).toMatch(/Allowed cache types|only these cache types|needs a 'type'/);
      expect(dbCalls()).toEqual([]);
    }
  );

  it('names the refused type in the message', async () => {
    const res = await exec({ type: 'BitlockerKeys' });
    expect(text(res)).toMatch(/type 'BitlockerKeys' is not allowed/);
  });

  it('refuses a missing type, including countsOnly and select-only calls', async () => {
    for (const args of [{}, { countsOnly: 'true' }, { select: 'id' }, { groupBy: 'Tenant' }, { type: undefined }]) {
      const res = await exec(args);
      expect(res.isError).toBe(true);
      expect(text(res)).toMatch(/needs a 'type'|must be a single string|accepts only/);
    }
    expect(dbCalls()).toEqual([]);
  });

  it.each([['authorizationpolicy'], ['AUTHORIZATIONPOLICY'], [' AuthorizationPolicy '], ['oauth2permissiongrants']])('accepts the odd-case type %p and sends the canonical spelling', async (type) => {
    const res = await exec({ type });
    expect(res.isError).toBeUndefined();
    expect(q(dbCalls()[0]!).get('type')).toBe(DBCACHE_ALLOWED_TYPES.find((t) => t.toLowerCase() === type.trim().toLowerCase()));
  });

  it('accepts the argument key in another casing and sends the declared one', async () => {
    const res = await exec({ TYPE: 'authorizationpolicy' });
    expect(res.isError).toBeUndefined();
    expect(q(dbCalls()[0]!).get('type')).toBe('AuthorizationPolicy');
  });

  it('refuses the type given twice in different casings', async () => {
    const res = await exec({ type: 'AuthorizationPolicy', Type: 'Apps' });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/duplicate argument/);
    expect(dbCalls()).toEqual([]);
  });

  it.each([
    ['AuthorizationPolicy,Apps'],
    ['AuthorizationPolicy;Apps'],
    ['Authorization*'],
    ['*'],
    ['AuthоrizationPolicy'], // Cyrillic o
    ['AuthorizationPolicy\u0000'],
    ['AuthorizationPolicy Apps'],
  ])('refuses the odd type %p', async (type) => {
    const res = await exec({ type });
    expect(res.isError).toBe(true);
    expect(dbCalls()).toEqual([]);
  });

  it('refuses non-string types (array, object, number, null)', async () => {
    for (const type of [['AuthorizationPolicy'], { a: 1 }, 5, null]) {
      const res = await exec({ type });
      expect(res.isError).toBe(true);
    }
    expect(dbCalls()).toEqual([]);
  });

  it.each([
    'AllTenants',
    'alltenants',
    'ALLTENANTS',
    ' AllTenants ',
    '\uFF21\uFF4C\uFF4C\uFF34\uFF45\uFF4E\uFF41\uFF4E\uFF54\uFF53', // fullwidth
    'All\u200bTenants', // zero-width space
    'AllTenants\u00a0', // no-break space
    'All\u00adTenants', // soft hyphen
    'AllTenants\u200d',
    'ALL\u2060TENANTS',
    'allTenants\ufeff',
  ])('refuses tenantFilter %j through cipp_exec_read, for every allowed type and both tiers', async (tenant) => {
    for (const ctx of [READ, WRITE]) {
      for (const type of DBCACHE_ALLOWED_TYPES) {
        const res = await exec({ type, tenantFilter: tenant }, ctx);
        expect(res.isError).toBe(true);
      }
    }
    expect(dbCalls()).toEqual([]);
  });

  it('restrictDbCache refuses every AllTenants variant itself, not only through the handler checks', () => {
    for (const t of ['AllTenants', 'alltenants', ' ALLTENANTS ', '\uFF21llTenants', 'All\u200bTenants', 'AllTenants\u00a0', 'All\u00adTenants', 'ALL\u2060TENANTS', 'allTenants\ufeff', 'AllTenants\t']) {
      const r = restrictDbCache({ tenantFilter: t, type: 'AuthorizationPolicy' });
      expect(r.ok).toBe(false);
    }
    expect(restrictDbCache({ tenantFilter: 'client.example', type: 'AuthorizationPolicy' }).ok).toBe(true);
  });

  it('AllTenants is refused with the single-tenant message in the plain cases', async () => {
    for (const t of ['AllTenants', 'alltenants', ' ALLTENANTS ']) {
      const res = await exec({ type: 'OAuth2PermissionGrants', tenantFilter: t });
      expect(text(res)).toMatch(/AllTenants is not allowed/);
    }
  });

  it('refuses a missing tenantFilter and AllTenants hidden in a duplicate key casing', async () => {
    const noTenant = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListDBCache', arguments: { type: 'AuthorizationPolicy' } });
    expect(noTenant.isError).toBe(true);
    const dup = await exec({ type: 'AuthorizationPolicy', TenantFilter: 'AllTenants' });
    expect(dup.isError).toBe(true);
    expect(dbCalls()).toEqual([]);
  });

  it.each([
    ['groupBy', 'Tenant'],
    ['select', 'id'],
    ['top', 5],
    ['latestOnly', 'true'],
    ['dateField', 'createdDateTime'],
    ['GroupBy', 'Tenant'],
    ['UseReportDB', 'true'],
    ['somethingElse', 'x'],
  ])('refuses the extra argument %s: only tenantFilter, type and countsOnly are accepted', async (key, value) => {
    const res = await exec({ type: 'AuthorizationPolicy', [key]: value });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/accepts only tenantFilter, type and countsOnly/);
    expect(dbCalls()).toEqual([]);
  });

  it('accepts countsOnly true or false and refuses anything else', async () => {
    for (const countsOnly of ['true', true, 'false', false]) {
      expect((await exec({ type: 'AuthorizationPolicy', countsOnly })).isError).toBeUndefined();
    }
    for (const countsOnly of ['yes', 1, null, 'TRUE ', ['true']]) {
      const res = await exec({ type: 'AuthorizationPolicy', countsOnly });
      expect(res.isError).toBe(true);
    }
  });

  describe('rows come back projected, never raw', () => {
    const TRAP = { secretText: 'SECRET-VALUE-1', passwordProfile: { password: 'PW-4' }, extraField: 'EXTRA-FIELD', ObjectClass: ['EXTRA-FIELD'] };
    const results = async (type: string, rows: unknown[]) => {
      cache[type] = rows;
      const res = await exec({ type });
      expect(res.isError).toBeUndefined();
      expect(text(res)).not.toMatch(/SECRET-VALUE-1|PW-4|EXTRA-FIELD/);
      return json(res);
    };

    it('AuthorizationPolicy', async () => {
      const body = await results('AuthorizationPolicy', [{ id: 'authorizationPolicy', allowedToUseSSPR: true, defaultUserRolePermissions: { allowedToCreateApps: true, someFutureFlag: 'x' }, ...TRAP }]);
      expect(body.Results).toEqual([{ id: 'authorizationPolicy', allowedToUseSSPR: true, defaultUserRolePermissions: { allowedToCreateApps: true } }]);
    });
    it('OAuth2PermissionGrants (scope uncut)', async () => {
      const scope = 'a '.repeat(3000) + 'Mail.ReadWrite';
      const body = await results('OAuth2PermissionGrants', [{ id: 'g', clientId: 'c', scope, Tenant: 'client.example', ...TRAP }]);
      expect(body.Results).toEqual([{ Tenant: 'client.example', id: 'g', clientId: 'c', scope }]);
      expect(body.truncated).toBe(false);
    });
    it('AppRoleAssignments', async () => {
      const body = await results('AppRoleAssignments', [{ resourceId: 'r', appRoleId: 'a', principalId: 'p', ...TRAP }]);
      expect(body.Results).toEqual([{ resourceId: 'r', appRoleId: 'a', principalId: 'p' }]);
    });
    it('PermissionGrantPolicies', async () => {
      const body = await results('PermissionGrantPolicies', [{ id: 'p', displayName: 'd', includes: [{ id: 'i', permissions: ['all'], ...TRAP }], ...TRAP }]);
      expect(body.Results).toEqual([{ id: 'p', displayName: 'd', includes: [{ id: 'i', permissions: ['all'] }] }]);
    });
    it('AdminConsentRequestPolicy', async () => {
      const body = await results('AdminConsentRequestPolicy', [{ isEnabled: true, reviewers: [{ query: '/users/u', ...TRAP }], ...TRAP }]);
      expect(body.Results).toEqual([{ isEnabled: true, reviewers: [{ query: '/users/u' }] }]);
    });
    it('CrossTenantAccessPolicy', async () => {
      const body = await results('CrossTenantAccessPolicy', [{ isServiceDefault: true, inboundTrust: { isMfaAccepted: true, ...TRAP }, ...TRAP }]);
      expect(body.Results).toEqual([{ isServiceDefault: true, inboundTrust: { isMfaAccepted: true } }]);
    });
    it('ExoHostedOutboundSpamFilterPolicy', async () => {
      const body = await results('ExoHostedOutboundSpamFilterPolicy', [
        { Name: 'Default', IsDefault: true, AutoForwardingMode: 'Automatic', RecipientLimitPerDay: 1000, NotifyOutboundSpamRecipients: ['EXTRA-FIELD@x'], DistinguishedName: 'EXTRA-FIELD', ...TRAP },
      ]);
      expect(body.Results).toEqual([{ Name: 'Default', IsDefault: true, AutoForwardingMode: 'Automatic', RecipientLimitPerDay: 1000 }]);
    });
    it('countsOnly rows keep four fields', async () => {
      cacheCounts['AuthorizationPolicy'] = [{ Tenant: 'client.example', Type: 'AuthorizationPolicy', Count: 1, LastRefresh: '2026-10-17T15:00:00Z', ...TRAP }];
      const res = await exec({ type: 'AuthorizationPolicy', countsOnly: true });
      expect(json(res).Results).toEqual([{ Tenant: 'client.example', Type: 'AuthorizationPolicy', Count: 1, LastRefresh: '2026-10-17T15:00:00Z' }]);
      expect(text(res)).not.toMatch(/SECRET-VALUE-1|EXTRA-FIELD/);
    });
    it('a long result is cut at the row cap and says so', async () => {
      const body = await results('OAuth2PermissionGrants', Array.from({ length: AUDIT_MAX_ROWS + 3 }, (_, i) => ({ id: `g${i}` })));
      expect(body.Results).toHaveLength(AUDIT_MAX_ROWS);
      expect(body.returned).toBe(AUDIT_MAX_ROWS + 3);
      expect(body.truncated).toBe(true);
      expect(body.truncatedFields).toEqual(['Results (rows)']);
    });
    it('a non-list answer from CIPP is an error, never passed through raw', async () => {
      fetchMock.mockImplementation((url) =>
        Promise.resolve(jsonResponse(url.includes('/api/ListOpenApiSpec') ? spec : { Results: 'CIPP says no', secretText: 'SECRET-VALUE-1' }))
      );
      catalogueStore.reset();
      const res = await exec({ type: 'AuthorizationPolicy' });
      expect(res.isError).toBe(true);
      expect(text(res)).not.toContain('SECRET-VALUE-1');
    });
  });

  it('cipp_exec_write cannot run ListDBCache at all (read tier)', async () => {
    const res = await exec({ type: 'AuthorizationPolicy' }, WRITE, 'cipp_exec_write');
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/read-tier endpoint|cipp_exec_read/);
    expect(dbCalls()).toEqual([]);
  });

  it('other endpoints are unaffected by the check', async () => {
    const res = await handler(READ).handleToolCall('cipp_exec_read', { name: 'ListThings', arguments: { tenantFilter: 't.example', type: 'Apps' } });
    expect(res.isError).toBeUndefined();
  });

  it('restrictDbCache is a pure check on the arguments', () => {
    expect(restrictDbCache({ tenantFilter: 't', type: 'oauth2permissiongrants' })).toEqual({
      ok: true,
      args: { tenantFilter: 't', type: 'OAuth2PermissionGrants' },
      type: 'OAuth2PermissionGrants',
      countsOnly: false,
    });
    expect(restrictDbCache({ tenantFilter: 't' }).ok).toBe(false);
    expect(restrictDbCache({ type: 'AuthorizationPolicy' }).ok).toBe(false);
  });
});

describe('the policy.ts cache type table', () => {
  const policy = readFileSync(join(__dirname, '..', 'src', 'itsl', 'policy.ts'), 'utf8').replace(/\r\n/g, '\n');
  const rows = [...policy.matchAll(/^ \*   (\S+)\s+(allowed|refused): (.+)$/gm)].map((m) => ({ type: m[1]!, status: m[2]!, reason: m[3]! }));

  it('lists every CIPP cache type with a reason, and the allowed rows are exactly the allow-list', () => {
    expect(rows.length).toBeGreaterThan(150);
    expect(new Set(rows.map((r) => r.type)).size).toBe(rows.length);
    for (const r of rows) expect(r.reason.length).toBeGreaterThan(10);
    expect(rows.filter((r) => r.status === 'allowed').map((r) => r.type).sort()).toEqual([...DBCACHE_ALLOWED_TYPES].sort());
  });

  it.each(['Apps', 'BitlockerKeys', 'MailboxRules', 'MailboxPermissions', 'CalendarPermissions', 'Users'])('marks %s refused', (t) => {
    expect(rows.find((r) => r.type === t)?.status).toBe('refused');
  });
});
