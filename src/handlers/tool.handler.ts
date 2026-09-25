// CIPP Tool Handler
// Dispatches MCP tool calls to the correct CippService method.

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { CippService } from '../services/cipp.service.js';
import { Logger } from '../utils/logger.js';
import { TOOL_DEFINITIONS } from '../mcp/tool.definitions.js';

export interface McpToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export class CippToolHandler {
  private cippService: CippService;
  private logger: Logger;
  private mcpServer: Server | null = null;

  constructor(cippService: CippService, logger: Logger) {
    this.cippService = cippService;
    this.logger = logger;
  }

  setServer(server: Server): void {
    this.mcpServer = server;
  }

  getServer(): Server | null {
    return this.mcpServer;
  }

  getToolDefinitions() {
    return TOOL_DEFINITIONS;
  }

  async handleToolCall(name: string, args: Record<string, unknown>): Promise<McpToolResult> {
    this.logger.debug(`Dispatching tool call: ${name}`, { args });

    try {
      let result: unknown;

      switch (name) {
        // -----------------------------------------------------------------------
        // Tenants
        // -----------------------------------------------------------------------
        case 'cipp_list_tenants': {
          const { allTenants } = args as { allTenants?: boolean };
          result = await this.cippService.listTenants({ allTenants });
          break;
        }

        case 'cipp_get_tenant_details': {
          const { tenantFilter } = args as { tenantFilter: string };
          result = await this.cippService.getTenantDetails(tenantFilter);
          break;
        }

        // -----------------------------------------------------------------------
        // Users
        // -----------------------------------------------------------------------
        case 'cipp_list_users': {
          const { tenantFilter, searchField, searchValue } = args as {
            tenantFilter: string;
            searchField?: string;
            searchValue?: string;
          };
          result = await this.cippService.listUsers(tenantFilter, { searchField, searchValue });
          break;
        }

        case 'cipp_bec_check': {
          const { tenantFilter, userId } = args as { tenantFilter: string; userId: string };
          result = await this.cippService.becCheck(tenantFilter, userId);
          break;
        }

        case 'cipp_list_mfa_users': {
          const { tenantFilter } = args as { tenantFilter: string };
          result = await this.cippService.listMfaUsers(tenantFilter);
          break;
        }

        case 'cipp_list_user_devices': {
          const { tenantFilter, userId } = args as { tenantFilter: string; userId: string };
          result = await this.cippService.listUserDevices(tenantFilter, userId);
          break;
        }

        case 'cipp_list_user_groups': {
          const { tenantFilter, userId } = args as { tenantFilter: string; userId: string };
          result = await this.cippService.listUserGroups(tenantFilter, userId);
          break;
        }

        // -----------------------------------------------------------------------
        // Groups
        // -----------------------------------------------------------------------
        case 'cipp_list_groups': {
          const { tenantFilter, search } = args as { tenantFilter: string; search?: string };
          result = await this.cippService.listGroups(tenantFilter, { search });
          break;
        }

        // -----------------------------------------------------------------------
        // Mailboxes
        // -----------------------------------------------------------------------
        case 'cipp_list_mailboxes': {
          const { tenantFilter, type } = args as { tenantFilter: string; type?: string };
          result = await this.cippService.listMailboxes(tenantFilter, { type });
          break;
        }

        case 'cipp_list_mailbox_permissions': {
          const { tenantFilter, upn } = args as { tenantFilter: string; upn: string };
          result = await this.cippService.listMailboxPermissions(tenantFilter, upn);
          break;
        }

        case 'cipp_list_mailbox_usage': {
          const { tenantFilter, sortBy, limit, minSizeGB } = args as {
            tenantFilter: string;
            sortBy?: string;
            limit?: number;
            minSizeGB?: number;
          };
          result = await this.cippService.listMailboxUsage(tenantFilter, {
            sortBy,
            limit,
            minSizeGB,
          });
          break;
        }

        case 'cipp_get_mailbox_usage': {
          const { tenantFilter, upn } = args as { tenantFilter: string; upn: string };
          result = await this.cippService.getMailboxUsage(tenantFilter, upn);
          break;
        }

        // -----------------------------------------------------------------------
        // Security
        // -----------------------------------------------------------------------
        case 'cipp_list_conditional_access_policies': {
          const { tenantFilter } = args as { tenantFilter: string };
          result = await this.cippService.listConditionalAccessPolicies(tenantFilter);
          break;
        }

        case 'cipp_list_named_locations': {
          const { tenantFilter } = args as { tenantFilter: string };
          result = await this.cippService.listNamedLocations(tenantFilter);
          break;
        }

        // -----------------------------------------------------------------------
        // Applications
        // -----------------------------------------------------------------------
        case 'cipp_list_enterprise_apps': {
          const { tenantFilter, includeBuiltIn } = args as {
            tenantFilter: string;
            includeBuiltIn?: boolean;
          };
          result = await this.cippService.listEnterpriseApps(tenantFilter, { includeBuiltIn });
          break;
        }

        // -----------------------------------------------------------------------
        // Standards
        // -----------------------------------------------------------------------
        case 'cipp_list_standards': {
          const { tenantFilter } = args as { tenantFilter: string };
          result = await this.cippService.listStandards(tenantFilter);
          break;
        }

        case 'cipp_list_standard_templates': {
          result = await this.cippService.listStandardTemplates();
          break;
        }

        // `tenantFilter` is optional for these two tools: omit it to report
        // across all tenants. This diverges intentionally from other Standards
        // cases that require it.
        case 'cipp_get_tenant_drift': {
          const { tenantFilter } = args as { tenantFilter?: string };
          result = await this.cippService.getTenantDrift(tenantFilter);
          break;
        }

        case 'cipp_get_tenant_alignment': {
          const { tenantFilter } = args as { tenantFilter?: string };
          result = await this.cippService.getTenantAlignment(tenantFilter);
          break;
        }

        case 'cipp_list_bpa': {
          const { tenantFilter } = args as { tenantFilter: string };
          result = await this.cippService.listBPA(tenantFilter);
          break;
        }

        case 'cipp_list_domain_health': {
          const { tenantFilter } = args as { tenantFilter: string };
          result = await this.cippService.listDomainHealth(tenantFilter);
          break;
        }

        // -----------------------------------------------------------------------
        // Licenses
        // -----------------------------------------------------------------------
        case 'cipp_list_licenses': {
          const { tenantFilter } = args as { tenantFilter: string };
          result = await this.cippService.listLicenses(tenantFilter);
          break;
        }

        case 'cipp_list_csp_licenses': {
          result = await this.cippService.listCSPLicenses();
          break;
        }

        // -----------------------------------------------------------------------
        // Alerts
        // -----------------------------------------------------------------------
        case 'cipp_list_audit_logs': {
          const { tenantFilter, days, type } = args as {
            tenantFilter: string;
            days?: number;
            type?: string;
          };
          result = await this.cippService.listAuditLogs(tenantFilter, {
            Days: days,
            Type: type,
          });
          break;
        }

        case 'cipp_list_alert_queue': {
          result = await this.cippService.listAlertQueue();
          break;
        }

        // -----------------------------------------------------------------------
        // GDAP
        // -----------------------------------------------------------------------
        case 'cipp_list_gdap_roles': {
          result = await this.cippService.listGDAPRoles();
          break;
        }

        case 'cipp_list_gdap_invites': {
          result = await this.cippService.listGDAPInvites();
          break;
        }

        // -----------------------------------------------------------------------
        // Scheduler
        // -----------------------------------------------------------------------
        case 'cipp_list_scheduled_items': {
          result = await this.cippService.listScheduledItems();
          break;
        }

        // -----------------------------------------------------------------------
        // Core
        // -----------------------------------------------------------------------
        case 'cipp_ping': {
          result = await this.cippService.ping();
          break;
        }

        case 'cipp_get_version': {
          result = await this.cippService.getVersion();
          break;
        }

        case 'cipp_list_logs': {
          const { dateFilter } = args as { dateFilter?: string };
          result = await this.cippService.listLogs(
            dateFilter !== undefined ? { DateFilter: dateFilter } : undefined
          );
          break;
        }

        default:
          throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
      }

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      if (error instanceof McpError) {
        throw error;
      }
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Tool call failed: ${name}`, { error: message });
      throw new McpError(ErrorCode.InternalError, `Tool ${name} failed: ${message}`);
    }
  }
}
