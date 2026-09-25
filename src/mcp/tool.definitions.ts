// CIPP MCP Tool Definitions
// Defines every MCP tool the CIPP MCP server exposes, including name,
// description, and JSON Schema for input validation.

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

/**
 * A single MCP tool definition as required by the MCP protocol.
 */
export interface McpToolDefinition {
  /** Unique, snake_case identifier for the tool. */
  name: string;
  /** Human-readable description surfaced to MCP clients and LLM tool-selectors. */
  description: string;
  /** JSON Schema (object type) describing the tool's accepted input parameters. */
  inputSchema: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
  /** Optional annotations providing hints about the tool's behavior. */
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
}

// ---------------------------------------------------------------------------
// Shared property snippets (reused across tools)
// ---------------------------------------------------------------------------

const TENANT_FILTER_PROP = {
  type: 'string',
  description:
    "Tenant domain name or ID to scope the operation. Use 'allTenants' to target every managed tenant.",
};

const USER_ID_PROP = {
  type: 'string',
  description:
    "The target user's Azure AD object ID or User Principal Name (UPN, e.g. alice@contoso.com).",
};

// ---------------------------------------------------------------------------
// Tool Definitions
// ---------------------------------------------------------------------------

export const TOOL_DEFINITIONS: McpToolDefinition[] = [
  // -------------------------------------------------------------------------
  // Tenant tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_tenants',
    description: 'List all tenants managed in CIPP',
    inputSchema: {
      type: 'object',
      properties: {
        allTenants: {
          type: 'boolean',
          description:
            'When true, forces retrieval of every managed tenant regardless of any default filter.',
        },
      },
    },
  },
  {
    name: 'cipp_get_tenant_details',
    description: 'Get detailed information about a specific tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: {
          type: 'string',
          description: "Tenant domain name or ID, use 'allTenants' for all",
        },
      },
      required: ['tenantFilter'],
    },
  },

  // -------------------------------------------------------------------------
  // User tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_users',
    description: 'List users in a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        searchField: {
          type: 'string',
          enum: ['displayName', 'userPrincipalName', 'mail'],
          description:
            'The user attribute to search on. Must be provided together with searchValue.',
        },
        searchValue: {
          type: 'string',
          description:
            'Value to match against the chosen searchField. displayName matches on prefix; userPrincipalName and mail must match exactly. Omit both search parameters to list every user in the tenant.',
        },
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_bec_check',
    description: 'Run a Business Email Compromise check on a user',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        userId: USER_ID_PROP,
      },
      required: ['tenantFilter', 'userId'],
    },
  },
  {
    name: 'cipp_list_mfa_users',
    description: 'List users and their MFA status in a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_list_user_devices',
    description: 'List devices enrolled by a user',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        userId: USER_ID_PROP,
      },
      required: ['tenantFilter', 'userId'],
    },
  },
  {
    name: 'cipp_list_user_groups',
    description: 'List groups a user is a member of',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        userId: USER_ID_PROP,
      },
      required: ['tenantFilter', 'userId'],
    },
  },

  // -------------------------------------------------------------------------
  // Group tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_groups',
    description: 'List groups in a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        search: {
          type: 'string',
          description:
            'Optional text to filter results by group display name. Partial matches are supported.',
        },
      },
      required: ['tenantFilter'],
    },
  },

  // -------------------------------------------------------------------------
  // Mailbox tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_mailboxes',
    description: 'List mailboxes in a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        type: {
          type: 'string',
          enum: ['UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox'],
          description:
            'Filter mailboxes by recipient type. Omit to return all mailbox types.',
        },
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_list_mailbox_permissions',
    description: 'List permissions on a specific mailbox',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        upn: {
          type: 'string',
          description: 'User Principal Name of the mailbox whose permissions should be listed.',
        },
      },
      required: ['tenantFilter', 'upn'],
    },
  },
  {
    name: 'cipp_list_mailbox_usage',
    description:
      'Report mailbox and online-archive sizes across a tenant, largest first, with ' +
      'tenant-wide totals. Each mailbox reports bytes used, a human-readable size, item ' +
      'count, quota and percent-of-quota, for both the primary store and the archive. ' +
      "Answers 'who is near quota', 'which mailboxes need archiving', and 'how much " +
      "Exchange storage does this tenant use'. Sizes come from CIPP's reporting database, " +
      'which must have been synced — the live Exchange query carries no size data at all. ' +
      'For one mailbox, or when the cache is unavailable, use cipp_get_mailbox_usage.',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        sortBy: {
          type: 'string',
          enum: ['mailboxSize', 'archiveSize', 'totalSize', 'percentOfQuota'],
          description:
            'Ordering, largest first. `mailboxSize` (default) ranks by the primary store, ' +
            '`archiveSize` by the online archive, `totalSize` by the two combined, and ' +
            '`percentOfQuota` by how full the primary store is relative to its quota — ' +
            'the one to use when hunting for mailboxes about to stop receiving mail.',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 1000,
          description:
            'Number of mailboxes to return (default 50, maximum 1000). The summary totals ' +
            'always cover every mailbox in the tenant, not just the ones returned — including ' +
            '`nearQuotaCount`, how many mailboxes sit at or above `nearQuotaPercent` of their ' +
            'quota, which answers the "who is about to stop receiving mail" question without ' +
            'reading a single row.',
        },
        minSizeGB: {
          type: 'number',
          minimum: 0,
          description:
            'Only return mailboxes whose primary store and archive together reach this ' +
            'size in GB. Omit to return every mailbox.',
        },
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_get_mailbox_usage',
    description:
      'Report the primary mailbox size and online-archive size for a single mailbox, with ' +
      'item counts, quotas and percent-of-quota. Reads live from Exchange, so unlike ' +
      "cipp_list_mailbox_usage it needs no CIPP report-cache sync and still returns real " +
      'sizes for a tenant that conceals names in its Microsoft 365 usage reports.',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: {
          type: 'string',
          description:
            "Tenant domain name or ID that owns the mailbox. 'allTenants' is not supported " +
            'here — this tool reads one mailbox at a time.',
        },
        upn: {
          type: 'string',
          description:
            "User Principal Name or Entra object ID of the mailbox owner (e.g. alice@contoso.com).",
        },
      },
      required: ['tenantFilter', 'upn'],
    },
  },

  // -------------------------------------------------------------------------
  // Security tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_conditional_access_policies',
    description: 'List Conditional Access policies for a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_list_named_locations',
    description: 'List named locations (trusted IPs) for a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
      },
      required: ['tenantFilter'],
    },
  },

  // -------------------------------------------------------------------------
  // Applications tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_enterprise_apps',
    description:
      "List enterprise applications (service principals) in a tenant — including third-party SaaS apps that customers have integrated via OAuth (Slack, Salesforce, Zoom, etc.). Returns appId, displayName, publisher, owner-org, signInAudience, tags, and creation date. Use tenantFilter='allTenants' for cross-tenant fan-out — CIPP handles per-tenant errors inline, so a 403 from one opt-out tenant returns as an error row rather than failing the call. Excludes Microsoft-built-in apps by default (owner org f8cdef31-…); pass includeBuiltIn=true to include them.",
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        includeBuiltIn: {
          type: 'boolean',
          description:
            "When true, includes Microsoft-built-in service principals (owner org f8cdef31-a31e-4b4a-93e4-5f571e91255a). Defaults to false (third-party / customer-installed apps only).",
        },
      },
      required: ['tenantFilter'],
    },
  },

  // -------------------------------------------------------------------------
  // Standards tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_standards',
    description: 'List compliance standards configured for a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_list_standard_templates',
    description: 'List the CIPP Standards Templates configured across the partner tenant.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    annotations: {
      title: 'List standards templates',
      readOnlyHint: true,
      destructiveHint: false,
    },
  },
  {
    name: 'cipp_get_tenant_drift',
    description:
      'Report standards drift — settings that deviate from a tenant\'s assigned ' +
      'Standards Template. Omit tenantFilter to report drift across all tenants.',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: {
          type: 'string',
          description:
            'Optional tenant domain or ID. Omit to report drift across all managed tenants.',
        },
      },
    },
    annotations: {
      title: 'Get tenant standards drift',
      readOnlyHint: true,
      destructiveHint: false,
    },
  },
  {
    name: 'cipp_get_tenant_alignment',
    description:
      "Report each tenant's alignment percentage against its assigned Standards " +
      'Templates — the key signal for deciding which standards are safe to ' +
      'promote to Remediate. Omit tenantFilter to report on all tenants.',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: {
          type: 'string',
          description:
            'Optional tenant domain or ID. Omit to report alignment across all managed tenants.',
        },
      },
    },
    annotations: {
      title: 'Get tenant standards alignment',
      readOnlyHint: true,
      destructiveHint: false,
    },
  },
  {
    name: 'cipp_list_bpa',
    description: 'Get Best Practice Analyser results for a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_list_domain_health',
    description: 'Check domain health (DMARC, DKIM, SPF) for a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
      },
      required: ['tenantFilter'],
    },
  },

  // -------------------------------------------------------------------------
  // License tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_licenses',
    description: 'List license assignments and usage for a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_list_csp_licenses',
    description: 'List all CSP licenses across tenants',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },

  // -------------------------------------------------------------------------
  // Alert tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_audit_logs',
    description: 'List audit log entries for a tenant',
    inputSchema: {
      type: 'object',
      properties: {
        tenantFilter: TENANT_FILTER_PROP,
        days: {
          type: 'number',
          description:
            'Number of days to look back when retrieving log entries. Defaults to 7 when omitted.',
        },
        type: {
          type: 'string',
          description:
            'Filter results to a specific log type (e.g. "AzureActiveDirectory", "Exchange", "SharePoint").',
        },
      },
      required: ['tenantFilter'],
    },
  },
  {
    name: 'cipp_list_alert_queue',
    description: 'List queued alerts across all tenants',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },

  // -------------------------------------------------------------------------
  // GDAP tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_gdap_roles',
    description: 'List available GDAP (Granular Delegated Admin Privileges) roles',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'cipp_list_gdap_invites',
    description: 'List pending GDAP relationship invites',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },

  // -------------------------------------------------------------------------
  // Scheduler tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_list_scheduled_items',
    description: 'List scheduled tasks in CIPP',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },

  // -------------------------------------------------------------------------
  // Core tools
  // -------------------------------------------------------------------------
  {
    name: 'cipp_ping',
    description: 'Check CIPP API connectivity',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'cipp_get_version',
    description: 'Get CIPP version information',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'cipp_list_logs',
    description: 'List CIPP application logs',
    inputSchema: {
      type: 'object',
      properties: {
        dateFilter: {
          type: 'string',
          description:
            'ISO 8601 date string used to filter log entries to a specific day (e.g. "2024-06-01"). Omit to retrieve recent logs.',
        },
      },
    },
  },
];

// ---------------------------------------------------------------------------
// Tool Categories
// ---------------------------------------------------------------------------

/**
 * Maps a human-readable category label to the names of all tools in that group.
 * Useful for selectively registering or describing subsets of tools.
 */
export const TOOL_CATEGORIES: Record<string, string[]> = {
  tenants: ['cipp_list_tenants', 'cipp_get_tenant_details'],
  users: [
    'cipp_list_users',
    'cipp_bec_check',
    'cipp_list_mfa_users',
    'cipp_list_user_devices',
    'cipp_list_user_groups',
  ],
  groups: ['cipp_list_groups'],
  mailboxes: [
    'cipp_list_mailboxes',
    'cipp_list_mailbox_permissions',
    'cipp_list_mailbox_usage',
    'cipp_get_mailbox_usage',
  ],
  security: ['cipp_list_conditional_access_policies', 'cipp_list_named_locations'],
  applications: ['cipp_list_enterprise_apps'],
  standards: [
    'cipp_list_standards',
    'cipp_list_standard_templates',
    'cipp_get_tenant_drift',
    'cipp_get_tenant_alignment',
    'cipp_list_bpa',
    'cipp_list_domain_health',
  ],
  licenses: ['cipp_list_licenses', 'cipp_list_csp_licenses'],
  alerts: ['cipp_list_audit_logs', 'cipp_list_alert_queue'],
  gdap: ['cipp_list_gdap_roles', 'cipp_list_gdap_invites'],
  scheduler: ['cipp_list_scheduled_items'],
  core: ['cipp_ping', 'cipp_get_version', 'cipp_list_logs'],
};
