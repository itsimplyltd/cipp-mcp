// Modified by IT Simply Ltd, 2026: S2S v2 (signed tier/user), x-user-token mode, per-request tier context, tiered server instructions
// CIPP MCP Server
// Handles the Model Context Protocol server setup and integration with CIPP.
// Supports both local (env-based) and gateway (header-based) credential modes.

import { createServer, IncomingMessage, ServerResponse, Server as HttpServer } from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { CippService } from '../services/cipp.service.js';
import { Logger } from '../utils/logger.js';
import { McpServerConfig } from '../types/index.js';
import { EnvironmentConfig, parseCredentialsFromHeaders } from '../utils/config.js';
import { CippToolHandler } from '../handlers/tool.handler.js';
import { verifyS2sV2, TIER_HEADER, TOKEN_HEADER, USER_HEADER } from '../itsl/s2s-v2.js';
import {
  NonceCache,
  ReportRateLimiter,
  assertRequireSignedHeaders,
  handleGatewayRequest,
  type GatewayOptions,
} from '../itsl/s2s-v3.js';
import type { CallerTier } from '../itsl/tier.js';
import { ToolContext } from '../itsl/meta-tools.js';

// Gateway service-to-service auth. IT Simply: S2S v2 and v3 only, floor 2. The
// v1 verifier (src/s2s-verify.ts) is deliberately NOT wired: v1 signs only a
// timestamp, so it can never bind tier, user or token. HTTP mode refuses to
// start without a secret of at least 32 characters, and there is no
// unauthenticated escape hatch.
const S2S_AUDIENCE = 'cipp';
const S2S_FLOOR = 2;
const MIN_S2S_SECRET_LENGTH = 32;
// Every header the backend trusts for identity or credentials. Whenever one is
// present on a v3 request it must be covered by the signature (so a header
// injected past the gateway can never be honoured). The gateway never sends
// the last seven today; they are listed so the whole configuration surface is
// closed from the start. Absence is safe (see tierFromHeader and the tests).
export const REQUIRE_SIGNED_HEADERS = [
  'x-mcp-tier',
  'x-mcp-user',
  'x-user-token',
  'x-base-url',
  'x-api-key',
  'x-tenant-id',
  'x-client-id',
  'x-client-secret',
  'x-token-scope',
  'x-token-scope-fallback',
  'x-token-url',
];
const envFlag = (name: string): boolean => (process.env[name] || '').trim().toLowerCase() === 'true';

const headerValue = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);

// v3 identity: the headers are guaranteed signed when present (REQUIRE_SIGNED_HEADERS).
// An absent or unexpected tier is read, never write.
const tierFromHeader = (v: string | undefined): CallerTier => (v === 'write' ? 'write' : 'read');
const userFromHeader = (v: string | undefined): string | undefined => {
  if (!v) return undefined;
  try {
    return decodeURIComponent(v);
  } catch {
    return undefined;
  }
};

export class CippMcpServer {
  private server: Server;
  private config: McpServerConfig;
  private cippService: CippService;
  private toolHandler: CippToolHandler;
  private logger: Logger;
  private envConfig: EnvironmentConfig | undefined;
  private httpServer?: HttpServer;

  constructor(config: McpServerConfig, logger: Logger, envConfig?: EnvironmentConfig) {
    this.logger = logger;
    this.config = config;
    this.envConfig = envConfig;

    this.cippService = new CippService(config, logger);
    this.toolHandler = new CippToolHandler(this.cippService, logger);

    this.server = this.createFreshServer();
  }

  /**
   * Create a fresh MCP Server with all handlers registered.
   * Called per-request in HTTP (stateless) mode so each initialise gets a clean server.
   */
  private createFreshServer(): Server {
    const server = new Server(
      {
        name: this.config.name,
        version: this.config.version,
      },
      {
        capabilities: {
          tools: {
            listChanged: true,
          },
        },
        instructions: this.getServerInstructions(),
      }
    );

    server.onerror = (error) => {
      this.logger.error('MCP Server error:', error);
    };

    server.oninitialized = () => {
      this.logger.info('MCP Server initialized and ready to serve requests');
    };

    this.setupHandlers(server);
    this.toolHandler.setServer(server);

    return server;
  }

  /**
   * Returns instructions that help MCP clients understand how to use this server.
   */
  private getServerInstructions(): string {
    return `
CIPP MCP Server — M365 multi-tenant management platform for MSPs.

Use tenantFilter to scope operations to a specific tenant domain (e.g. "contoso.com").
Most listing tools accept 'allTenants' as tenantFilter to query across every managed tenant.

Access is tiered. Every CIPP endpoint is read, write, disabled or blocked:
- read: callable by everyone. This is almost all of CIPP's read surface.
- write: callable only with the CIPP.Write gateway role. At launch this is only the cache and sync
  triggers (ExecCIPPDBCache, ExecSyncAPDevices, ExecSyncDEP, ExecSyncVPP, ExecExtensionSync,
  ExecTestRefresh, ExecTestRun).
  Also cipp_disable_enterprise_app / cipp_enable_enterprise_app: switch one third-party enterprise app (service principal) off or on in one tenant; Microsoft and IT Simply apps are refused.
- disabled: everything else that can change data, until IT Simply reviews it. Refused for everyone.
- blocked: sensitive or dangerous endpoints (LAPS passwords, BitLocker keys, MFA push, secrets and
  settings). Refused for everyone.
CIPP also applies your own CIPP role on top, so a write-tier call can still be refused by CIPP.
A refusal names its reason; do not retry with a different spelling. tools/list only shows tools
your tier can call.

To reach any CIPP endpoint, use the catalogue tools:
- cipp_search_tools: find endpoints you can call (search by keyword or browse a category)
- cipp_get_tool_info: input schema for named endpoints
- cipp_exec_read: run a read-tier endpoint by name with 'arguments' (listed for everyone)
- cipp_exec_write: run a write-tier endpoint (cache/sync triggers); listed only with the CIPP.Write role
  Search and tool-info results say which exec tool runs each entry (run_with).
  cipp_exec_write refuses tenantFilter=AllTenants: run write calls per tenant.
  tenantFilter accepts the tenant's defaultDomainName, tenant ID (GUID), initial .onmicrosoft.com domain
  or any other domain CIPP lists for the tenant, and is normalised to the defaultDomainName (see
  cipp_list_tenants) before the call. An unknown value is refused, never passed through: another of a
  tenant's domains can otherwise make some endpoints return a clean but EMPTY result instead of an error.
- cipp_graph_request: read-only Microsoft Graph query for a tenant through CIPP
- cipp_sync_sharepoint_sharing: refresh the SharePoint/OneDrive sharing caches behind ListSharePointSharing
  for ONE tenant (listed for everyone). The one write-type action open to the read tier: fixed caches only,
  no AllTenants, at most once per tenant every 15 minutes. Use it when linksSynced is false or the data is old.
- cipp_sync_sharepoint_permissions: refresh the SharePoint permissions scan (SharePointPermissions cache) behind
  ListSharePointPermissions for ONE tenant (listed for everyone). Same limits as the sharing sync, but at most
  once per tenant every 60 minutes (the scan walks every site). It runs in the background; wait before heavy per-site reads.
- cipp_message_trace: Exchange message trace for ONE tenant (listed for everyone). Needs a sender and/or
  recipient address and covers up to 10 days; subjects are removed by policy.
- cipp_get_authorization_policy: live Entra authorization policy for ONE tenant (default user permissions incl. agent-identity-blueprint creation, guest invites, SSPR), projected.
- cipp_list_delegated_grants: live delegated OAuth2 permission grants for ONE tenant (clientId, resourceId, consentType, principalId, scope).
- cipp_list_app_role_assignments: live app role assignments of ONE service principal (GUID) in ONE tenant.
- cipp_list_app_registrations: live app registrations for ONE tenant with credential lifetimes (never secret values or hints) and owners (id, UPN).
- cipp_get_consent_policies: live user app-consent policies and the admin consent request workflow for ONE tenant.
- cipp_get_cross_tenant_policy: live default cross-tenant access policy (inbound trust, B2B collaboration and direct connect) for ONE tenant.
- cipp_get_outbound_spam_policy: Exchange outbound spam policy for ONE tenant; CIPP's CACHED copy (up to ~24 h old, cachedAt says when), refreshed by the write-tier sync.
  These seven take one tenant (never AllTenants) and no other arguments, and return only a fixed set of fields.
  cipp_exec_read can run ListDBCache only for one tenant (never AllTenants), with only tenantFilter, type and countsOnly,
  for a short list of reviewed cache types; other types and arguments are refused, and the rows come back projected.

Named tools (cipp_list_users, cipp_list_mailboxes, ...) are shortcuts for common endpoints.
Named tools that can change data are listed only when your tier allows them, and are disabled at launch.

Tool categories:
- Tenants: list and inspect managed tenants
- Users: list users, sign-in logs, MFA status, BEC check
- Groups: list Azure AD groups
- Mailboxes: list mailboxes, permissions, sizes, trusted and blocked senders
- Security: Conditional Access policies, named locations
- Standards: compliance standards, BPA results, domain health
- Licenses: per-tenant and CSP-level license reporting
- Alerts: audit logs and alert queue
- GDAP: roles and relationship invites
- Scheduler: list scheduled tasks
- Core: ping, version, logs
`.trim();
  }

  /**
   * Register all MCP request handlers on the given server instance.
   */
  private setupHandlers(server: Server): void {
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      this.logger.debug('Handling list tools request');
      return { tools: this.toolHandler.getToolDefinitions() };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      this.logger.debug(`Handling tool call: ${request.params.name}`);
      try {
        const result = await this.toolHandler.handleToolCall(
          request.params.name,
          (request.params.arguments as Record<string, unknown>) || {}
        );
        return {
          content: result.content,
          isError: result.isError,
        };
      } catch (error) {
        this.logger.error(`Failed to call tool ${request.params.name}:`, error);
        const message = error instanceof Error ? error.message : 'Unknown error';
        return {
          content: [{ type: 'text', text: message }],
          isError: true,
        };
      }
    });

  }

  /**
   * Start the server using the configured transport type.
   */
  async start(): Promise<void> {
    const transportType = this.envConfig?.transport?.type || 'stdio';
    this.logger.info(`Starting CIPP MCP Server with ${transportType} transport...`);

    if (transportType === 'http') {
      await this.startHttpTransport();
    } else {
      await this.startStdioTransport();
    }
  }

  private async startStdioTransport(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    this.logger.info('CIPP MCP Server started on stdio transport');
  }

  private async startHttpTransport(): Promise<void> {
    const port = this.envConfig?.transport?.port || 8080;
    const host = this.envConfig?.transport?.host || '0.0.0.0';
    const isGatewayMode = this.envConfig?.auth?.mode === 'gateway';

    const secret = process.env.CONDUIT_S2S_SECRET || '';
    if (secret.length < MIN_S2S_SECRET_LENGTH) {
      const msg =
        'Refusing to start HTTP server: CONDUIT_S2S_SECRET is missing or shorter than 32 characters. ' +
        'This server only accepts requests signed by the gateway.';
      this.logger.error(msg);
      throw new Error(msg);
    }
    if (process.env.ITSL_REQUIRE_S2S_V2 !== undefined) {
      this.logger.warn(
        'ITSL_REQUIRE_S2S_V2 is deprecated and ignored: S2S v2 is now the floor (v1 is never accepted).'
      );
    }
    assertRequireSignedHeaders(REQUIRE_SIGNED_HEADERS);

    // One nonce cache and one set of limiters for the life of the process.
    const shared = {
      nonceCache: new NonceCache(),
      reportLimiter: new ReportRateLimiter(),
      failureLimiter: new ReportRateLimiter(),
    };
    const gatewayLogger = {
      warn: (msg: string, meta?: Record<string, unknown>) => this.logger.warn(msg, meta),
      error: (msg: string, meta?: Record<string, unknown>) => this.logger.error(msg, meta),
      debug: (msg: string, meta?: Record<string, unknown>) => this.logger.debug(msg, meta),
    };

    this.httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      const path = (req.url || '/').split('?')[0];

      if (path === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
      }

      // Exactly /mcp: S2S v3 binds the raw request target, and anything else is
      // a 404 before any authentication work.
      if (req.url === '/mcp') {
        // Service-to-service auth runs FIRST, before any credential extraction.
        // The ITSL_S2S_MIN_VERSION operator switch is read per request (it can only
        // tighten: the floor is 2 in code, and an invalid value counts as 3).
        let legacyIdentity: { tier: CallerTier; user: string } | undefined;
        const opts: GatewayOptions = {
          secret,
          aud: S2S_AUDIENCE,
          floor: S2S_FLOOR,
          minVersion: Number(process.env.ITSL_S2S_MIN_VERSION ?? '2'),
          // v2 binds tier, user and a hash of the token to the headers actually received.
          // v1 is never offered.
          verifyLegacy: (hv: string) => {
            const id = verifyS2sV2(
              hv,
              secret,
              headerValue(req.headers[TIER_HEADER]),
              headerValue(req.headers[USER_HEADER]),
              headerValue(req.headers[TOKEN_HEADER])
            );
            if (!id) return 0;
            legacyIdentity = id;
            return 2;
          },
          requireSignedHeaders: REQUIRE_SIGNED_HEADERS,
          logger: gatewayLogger,
          ...shared,
        };
        void handleGatewayRequest(req, res, opts, ({ version, parsedBody }) => {
          const fromV2 = version === 2 ? legacyIdentity : undefined;
          const tier: CallerTier = fromV2 ? fromV2.tier : tierFromHeader(headerValue(req.headers[TIER_HEADER]));
          const user = fromV2 ? fromV2.user : userFromHeader(headerValue(req.headers[USER_HEADER]));
          // v3 only: never serve an anonymous write. (v2 already binds the user.)
          if (version === 3 && tier === 'write' && !user) {
            if (shared.failureLimiter.shouldEmit('write-without-user')) {
              this.logger.warn('S2S verification failed', { reason: 'write-without-user' });
            }
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end('{"error":"Missing or invalid X-Gateway-S2S header"}');
            return;
          }
          const toolContext: ToolContext = { tier, user };
          this.handleMcpRequest(req, res, parsedBody, toolContext, isGatewayMode);
        });
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health'] }));
    });

    await new Promise<void>((resolve) => {
      this.httpServer!.listen(port, host, () => {
        this.logger.info(`CIPP MCP Server listening on http://${host}:${port}/mcp`);
        this.logger.info(`Health check available at http://${host}:${port}/health`);
        this.logger.info(
          `Authentication mode: ${isGatewayMode ? 'gateway (header-based)' : 'env (environment variables)'}`
        );
        resolve();
      });
    });
  }

  /**
   * Handle one verified /mcp request. Runs only from handleGatewayRequest's
   * onVerified, so S2S has already passed and the body has been read and parsed.
   */
  private handleMcpRequest(
    req: IncomingMessage,
    res: ServerResponse,
    parsedBody: unknown,
    toolContext: ToolContext,
    isGatewayMode: boolean
  ): void {

    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Method not allowed' },
          id: null,
        })
      );
      return;
    }

    // IT Simply: with ITSL_REQUIRE_USER_TOKEN=true the per-user token is the
    // only accepted credential. Checked before any credential parsing, so a
    // request carrying client credentials but no x-user-token is refused.
    if (envFlag('ITSL_REQUIRE_USER_TOKEN')) {
      const hasUserToken = !!headerValue(req.headers['x-user-token'])?.trim();
      if (!hasUserToken || !isGatewayMode) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Missing credentials',
            message: isGatewayMode
              ? 'This server only accepts a per-user token in x-user-token.'
              : 'ITSL_REQUIRE_USER_TOKEN requires AUTH_MODE=gateway.',
          })
        );
        return;
      }
    }

    // Per-request handler so the caller's verified tier travels with the call.
    let cippService = this.cippService;
    let toolHandler = new CippToolHandler(cippService, this.logger, toolContext);

    if (isGatewayMode) {
      const credentials = parseCredentialsFromHeaders(
        req.headers as Record<string, string | string[] | undefined>
      );

      const hasOAuth =
        !!credentials.tenantId && !!credentials.clientId && !!credentials.clientSecret;
      const hasStatic = !!credentials.apiKey;

      if (!credentials.baseUrl || (!hasStatic && !hasOAuth)) {
        this.logger.warn('Gateway mode: Missing required credentials in request headers', {
          hasBaseUrl: !!credentials.baseUrl,
          hasApiKey: hasStatic,
          hasOAuthCreds: hasOAuth,
        });
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Missing credentials',
            message:
              'Gateway mode requires x-base-url plus either x-user-token, x-api-key or (x-tenant-id + x-client-id + x-client-secret)',
            required: ['x-base-url', 'x-user-token OR x-api-key OR (x-tenant-id + x-client-id + x-client-secret)'],
          })
        );
        return;
      }

      // Header wins; otherwise the process env (default on). `??` keeps an explicit false.
      const tokenScopeFallback =
        credentials.tokenScopeFallback ?? this.envConfig?.cipp.tokenScopeFallback;

      const requestConfig: McpServerConfig = {
        name: this.config.name,
        version: this.config.version,
        cipp: {
          baseUrl: credentials.baseUrl,
          ...(credentials.apiKey !== undefined ? { apiKey: credentials.apiKey } : {}),
          ...(credentials.tenantId !== undefined ? { tenantId: credentials.tenantId } : {}),
          ...(credentials.clientId !== undefined ? { clientId: credentials.clientId } : {}),
          ...(credentials.clientSecret !== undefined ? { clientSecret: credentials.clientSecret } : {}),
          ...(credentials.tokenScope !== undefined ? { tokenScope: credentials.tokenScope } : {}),
          ...(credentials.tokenUrl !== undefined ? { tokenUrl: credentials.tokenUrl } : {}),
          ...(tokenScopeFallback !== undefined ? { tokenScopeFallback } : {}),
        },
      };

      cippService = new CippService(requestConfig, this.logger);
      toolHandler = new CippToolHandler(cippService, this.logger, toolContext);
    }

    const server = new Server(
      { name: this.config.name, version: this.config.version },
      {
        capabilities: { tools: { listChanged: true } },
        instructions: this.getServerInstructions(),
      }
    );

    server.onerror = (error) => this.logger.error('MCP request server error:', error);

    // Wire up handlers using the (possibly per-request) toolHandler
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: toolHandler.getToolDefinitions(),
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      this.logger.debug(`Handling tool call: ${request.params.name}`);
      try {
        const result = await toolHandler.handleToolCall(
          request.params.name,
          (request.params.arguments as Record<string, unknown>) || {}
        );
        return { content: result.content, isError: result.isError };
      } catch (error) {
        this.logger.error(`Failed to call tool ${request.params.name}:`, error);
        const message = error instanceof Error ? error.message : 'Unknown error';
        return {
          content: [{ type: 'text', text: message }],
          isError: true,
        };
      }
    });

    toolHandler.setServer(server);

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on('close', () => {
      transport.close();
      server.close();
    });

    server
      .connect(transport as any)
      .then(() => {
        // Returned, so a rejection reaches the catch below instead of being dropped.
        return transport.handleRequest(req, res, parsedBody);
      })
      .catch((err) => {
        this.logger.error('MCP transport connect error:', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal error' },
              id: null,
            })
          );
        }
      });
  }

  /**
   * Gracefully stop the server.
   */
  async stop(): Promise<void> {
    this.logger.info('Stopping CIPP MCP Server...');
    if (this.httpServer) {
      await new Promise<void>((resolve, reject) => {
        this.httpServer!.close((err) => (err ? reject(err) : resolve()));
      });
    }
    await this.server.close();
    this.logger.info('CIPP MCP Server stopped');
  }
}
