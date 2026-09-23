// Invoke-ListUserSigninLogs reads tenantFilter, UserID and top, then calls
// Graph /beta/auditLogs/signIns with `userId eq '<UserID>'`. UserID is the
// Entra object id; a UPN is not a value that filter accepts.
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import { CippService } from '../src/services/cipp.service.js';
import { CippToolHandler } from '../src/handlers/tool.handler.js';
import { TOOL_CATEGORIES, TOOL_DEFINITIONS } from '../src/mcp/tool.definitions.js';
import { Logger } from '../src/utils/logger.js';
import { calledEndpoint, errorResponse, jsonResponse, queryOf } from './helpers.js';

const logger = new Logger('error');
const OBJECT_ID = '11111111-1111-1111-1111-111111111111';

describe('CippService listUserSigninLogs', () => {
  let svc: CippService;
  let fetchMock: jest.Mock<Promise<Response>, [string, RequestInit]>;

  beforeEach(() => {
    svc = new CippService(
      { cipp: { baseUrl: 'https://cipp.example', apiKey: 'test-key' } },
      logger
    );
    fetchMock = jest.fn<Promise<Response>, [string, RequestInit]>(() =>
      Promise.resolve(jsonResponse([]))
    );
    global.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('GETs ListUserSigninLogs with tenantFilter and UserID, and omits top so CIPP defaults to 50', async () => {
    const signIns = [{ id: 'signin-1', userId: OBJECT_ID, createdDateTime: '2026-09-01T00:00:00Z' }];
    fetchMock.mockResolvedValueOnce(jsonResponse(signIns));

    const result = await svc.listUserSigninLogs('contoso.com', OBJECT_ID);

    expect(result).toEqual(signIns);
    const [url, init] = fetchMock.mock.calls[0];
    const parsed = new URL(url);
    expect(parsed.pathname).toMatch(/\/api\/ListUserSigninLogs$/);
    expect(init.method).toBe('GET');
    expect(init.headers).toMatchObject({ Authorization: 'Bearer test-key' });
    expect(parsed.searchParams.get('tenantFilter')).toBe('contoso.com');
    // Invoke-ListUserSigninLogs reads `$Request.Query.UserID`, not `userId`.
    expect(parsed.searchParams.get('UserID')).toBe(OBJECT_ID);
    expect(parsed.searchParams.has('userId')).toBe(false);
    expect(parsed.searchParams.has('top')).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('forwards an explicit top and does not look the object id up', async () => {
    await svc.listUserSigninLogs('contoso.com', `  ${OBJECT_ID}  `, 25);

    const query = queryOf(fetchMock, '/api/ListUserSigninLogs');
    expect(query.get('UserID')).toBe(OBJECT_ID);
    expect(query.get('top')).toBe('25');
    expect(calledEndpoint(fetchMock, '/api/ListUsers')).toBe(false);
  });

  it('resolves a UPN to the Entra object id before calling ListUserSigninLogs', async () => {
    fetchMock.mockImplementation((url: string) => {
      if (url.includes('/api/ListUsers')) {
        return Promise.resolve(
          jsonResponse([{ id: OBJECT_ID, userPrincipalName: 'alice@contoso.com' }])
        );
      }
      return Promise.resolve(jsonResponse([{ id: 'signin-1', userId: OBJECT_ID }]));
    });

    const result = await svc.listUserSigninLogs('contoso.com', 'alice@contoso.com', 10);

    expect(result).toEqual([{ id: 'signin-1', userId: OBJECT_ID }]);
    const users = queryOf(fetchMock, '/api/ListUsers');
    expect(users.get('tenantFilter')).toBe('contoso.com');
    expect(users.get('graphFilter')).toBe("userPrincipalName eq 'alice@contoso.com'");
    expect(users.get('UserID')).toBeNull();
    expect(queryOf(fetchMock, '/api/ListUserSigninLogs').get('UserID')).toBe(OBJECT_ID);
  });

  it('does not call ListUserSigninLogs when the UPN cannot be resolved', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));

    await expect(svc.listUserSigninLogs('contoso.com', 'missing@contoso.com')).rejects.toBeInstanceOf(
      McpError
    );
    expect(calledEndpoint(fetchMock, '/api/ListUserSigninLogs')).toBe(false);
  });

  it.each(['allTenants', 'AllTenants', ' ALLTENANTS '])(
    'rejects %j without calling CIPP',
    async (tenantFilter) => {
      await expect(svc.listUserSigninLogs(tenantFilter, OBJECT_ID)).rejects.toThrow(/allTenants/);
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each([
    ['empty', '   '],
    ['display name', 'Alice Smith'],
  ])('rejects a %s userId without calling CIPP', async (_label, userId) => {
    await expect(svc.listUserSigninLogs('contoso.com', userId)).rejects.toBeInstanceOf(McpError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([0, -1, 1.5, 1001, Number.NaN])('rejects top=%p without calling CIPP', async (top) => {
    await expect(svc.listUserSigninLogs('contoso.com', OBJECT_ID, top)).rejects.toThrow(/top must be an integer/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('accepts the Graph page-size maximum', async () => {
    await svc.listUserSigninLogs('contoso.com', OBJECT_ID, 1000);
    expect(queryOf(fetchMock, '/api/ListUserSigninLogs').get('top')).toBe('1000');
  });

  it('surfaces CIPP HTTP 500 failure text instead of an empty success', async () => {
    fetchMock.mockResolvedValueOnce(
      errorResponse(
        500,
        JSON.stringify(["Failed to retrieve Sign In report for user 11111111-1111-1111-1111-111111111111 : Error: access denied"])
      )
    );

    await expect(svc.listUserSigninLogs('contoso.com', OBJECT_ID)).rejects.toThrow(
      /HTTP 500[\s\S]*Failed to retrieve Sign In report/
    );
  });
});

describe('cipp_list_user_signin_logs wiring', () => {
  it('is registered as a read-only user tool requiring tenantFilter and userId', () => {
    const tool = TOOL_DEFINITIONS.find((t) => t.name === 'cipp_list_user_signin_logs');
    expect(tool).toBeDefined();
    expect(tool?.inputSchema.required).toEqual(['tenantFilter', 'userId']);
    expect(tool?.inputSchema.properties).toHaveProperty('top');
    expect(tool?.annotations?.readOnlyHint).toBe(true);
    expect(TOOL_CATEGORIES.users).toContain('cipp_list_user_signin_logs');
  });

  it('dispatches the tool call with tenantFilter, userId and top', async () => {
    const svc = new CippService(
      { cipp: { baseUrl: 'https://cipp.example', apiKey: 'test-key' } },
      logger
    );
    const signIns = [{ id: 'signin-1' }];
    const spy = jest.spyOn(svc, 'listUserSigninLogs').mockResolvedValue(signIns);
    const handler = new CippToolHandler(svc, logger);

    const result = await handler.handleToolCall('cipp_list_user_signin_logs', {
      tenantFilter: 'contoso.com',
      userId: OBJECT_ID,
      top: 10,
    });

    expect(spy).toHaveBeenCalledWith('contoso.com', OBJECT_ID, 10);
    expect(JSON.parse(result.content[0].text)).toEqual(signIns);
  });
});
