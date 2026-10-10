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
import { verifyS2sHeader, S2S_HEADER } from '../s2s-verify.js';
import { decideS2s, TIER_HEADER, USER_HEADER } from '../itsl/s2s-v2.js';
import { ToolContext } from '../itsl/meta-tools.js';

// Conduit service-to-service auth (gateway#377 parity). Non-empty =
// enforce X-Gateway-S2S on every /mcp request; empty = disabled, behavior
// exactly as before (dark-by-default until the gateway provisions this
// container's derived subkey). See src/s2s-verify.ts.
// IT Simply: read per request (not at import) so the policy below can be
// exercised under test; production sets it once at container start.
const s2sSecret = (): string => process.env.CONDUIT_S2S_SECRET || '';
const envFlag = (name: string): boolean => (process.env[name] || '').trim().toLowerCase() === 'true';

const headerValue = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);

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
- disabled: everything else that can change data, until IT Simply reviews it. Refused for everyone.
- blocked: sensitive or dangerous endpoints (LAPS passwords, BitLocker keys, MFA push, secrets and
  settings). Refused for everyone.
CIPP also applies your own CIPP role on top, so a write-tier call can still be refused by CIPP.
A refusal names its reason; do not retry with a different spelling. tools/list only shows tools
your tier can call.

To reach any CIPP endpoint, use the catalogue tools:
- cipp_search_tools: find endpoints you can call (search by keyword or browse a category)
- cipp_get_tool_info: input schema for named endpoints
- cipp_exec_tool: run an endpoint by name with 'arguments'
- cipp_graph_request: read-only Microsoft Graph query for a tenant through CIPP

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

    this.httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

      if (url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
      }

      if (url.pathname === '/mcp') {
        // Conduit service-to-service auth (gateway#377 parity): rejected
        // BEFORE any credential extraction (OAuth or static key), mirroring
        // every other ported wrapper (e.g.
        // containers/sentinelone-mcp/gateway_wrapper.py).
        // IT Simply: the decision also yields the caller's tier and user, which
        // are trusted ONLY from a verified v2 signature (see src/itsl/s2s-v2.ts).
        const s2s = decideS2s({
          header: headerValue(req.headers[S2S_HEADER]),
          secret: s2sSecret(),
          requireV2: envFlag('ITSL_REQUIRE_S2S_V2'),
          tierHeader: headerValue(req.headers[TIER_HEADER]),
          userHeader: headerValue(req.headers[USER_HEADER]),
          verifyV1: verifyS2sHeader,
        });
        if (!s2s.ok) {
          this.logger.warn('S2S check failed', { reason: s2s.reason });
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
            })
          );
          return;
        }
        const toolContext: ToolContext = { tier: s2s.tier, user: s2s.user };

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
            transport.handleRequest(req, res);
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
