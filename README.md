# CIPP MCP Server

MCP (Model Context Protocol) server for [CIPP](https://github.com/KelvinTegelaar/CIPP) — the CyberDrain Improved Partner Portal. Provides AI assistants with structured access to CIPP's M365 multi-tenant management capabilities.

> **This is IT Simply's read-only fork.** 14 write-capable tools present in
> upstream have been removed. See [IT Simply modifications](#it-simply-modifications)
> below.

## Features

- **31 tools** across 12 categories, all read-only
- Tenant, user, group, and mailbox visibility
- Mailbox and online-archive size reporting, per tenant or per user
- Security: Conditional Access policies, named locations
- Standards & compliance: BPA, domain health, drift detection
- License reporting (per-tenant and CSP-wide)
- Alerts, audit logs, and scheduled tasks
- GDAP role and invite management
- Stdio and HTTP transport modes
- MCP Gateway compatible

## Prerequisites

- Node.js 18+
- A running CIPP deployment
- CIPP API Key (generated from CIPP Settings → API Client Management)

## Installation

### Via npm (once published)

```sh
npx cipp-mcp
```

### From source

```sh
git clone https://github.com/WYRE-AI/cipp-mcp
cd cipp-mcp
npm install
npm run build
```

## Configuration

Set these environment variables (or copy `.env.example` to `.env`):

| Variable | Required | Description |
|---|---|---|
| `CIPP_BASE_URL` | Yes | Your CIPP **Azure Function App** URL (e.g. `https://cippXXXXX.azurewebsites.net`). **Do not use the SWA / frontend URL** — see [Finding your Function App URL](#finding-your-function-app-url). |
| `CIPP_API_KEY` | One of | Static Bearer token. Use this **or** the OAuth trio below. |
| `CIPP_TENANT_ID` | One of | Entra tenant ID that owns the CIPP API-client app registration. |
| `CIPP_CLIENT_ID` | One of | OAuth client ID issued by CIPP's API Client Management page. |
| `CIPP_CLIENT_SECRET` | One of | OAuth client secret paired with `CIPP_CLIENT_ID`. |
| `CIPP_TOKEN_SCOPE` | No | Override OAuth scope (default: `<clientId>/.default`). |
| `CIPP_TOKEN_URL` | No | Override OAuth token endpoint (sovereign clouds only). |
| `MCP_TRANSPORT` | No | `stdio` (default) or `http` |
| `MCP_HTTP_PORT` | No | Port for HTTP mode (default: 8080) |
| `LOG_LEVEL` | No | `error`, `warn`, `info` (default), or `debug` |

> [!IMPORTANT]
> `CIPP_BASE_URL` must be the **Azure Function App** URL — the CIPP-API backend,
> `https://<function-app-name>.azurewebsites.net` — **not** the Static Web App /
> custom-domain UI URL (e.g. `https://cipp.yourdomain.com`). The SWA's built-in
> auth intercepts bearer tokens and redirects them to its interactive login page,
> so every API call fails. Find the Function App (named like `cippXXXXX`) in your
> CIPP resource group in the Azure Portal.

## Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cipp": {
      "command": "node",
      "args": ["/path/to/cipp-mcp/dist/entry.js"],
      "env": {
        "CIPP_BASE_URL": "https://cippXXXXX.azurewebsites.net",
        "CIPP_TENANT_ID": "your-entra-tenant-id",
        "CIPP_CLIENT_ID": "your-client-id",
        "CIPP_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

> **Note:** `CIPP_BASE_URL` must be the Azure **Function App** URL (`.azurewebsites.net`), not
> the frontend SWA URL (`.azurestaticapps.net` or your custom domain). The SWA enforces
> browser-based auth and will redirect all API requests to a Microsoft login page.

## Tools

| Category | Tools |
|---|---|
| Tenants | list_tenants, get_tenant_details |
| Users | list_users, bec_check, list_mfa_users, list_user_devices, list_user_groups |
| Groups | list_groups |
| Mailboxes | list_mailboxes, list_mailbox_permissions, list_mailbox_usage, get_mailbox_usage |
| Security | list_conditional_access_policies, list_named_locations |
| Applications | list_enterprise_apps |
| Standards | list_standards, list_standard_templates, get_tenant_drift, get_tenant_alignment, list_bpa, list_domain_health |
| Licenses | list_licenses, list_csp_licenses |
| Alerts | list_audit_logs, list_alert_queue |
| GDAP | list_gdap_roles, list_gdap_invites |
| Scheduler | list_scheduled_items |
| Core | ping, get_version, list_logs |

### Mailbox and archive sizes

`list_mailbox_usage` reports every mailbox in a tenant — primary size, item
count, quota, percent of quota, and the same four figures for the online
archive — sorted largest first, with tenant-wide totals that cover every
mailbox even when only the top rows are returned.

**It requires CIPP's reporting database to have been synced for that tenant.**
This is not a design choice: `Invoke-ListMailboxes`' live Exchange query selects
no size fields at all, so the cache is the only tenant-wide source of sizes.
Sync it from CIPP under Reports → Report Settings. If it has not been synced the
tool says so and names the remedy rather than returning an empty result.

`get_mailbox_usage` reports the same figures for a single mailbox and reads
live, so it needs no cache. Prefer it when the cache is unavailable or stale.

Two caveats worth knowing:

- **Concealed report names blank the tenant-wide sizes.** With *Reports:
  conceal user, group, and site names* enabled in the Microsoft 365 admin
  centre, Graph's usage report returns 32-character hashes instead of UPNs, so
  CIPP's join against the mailbox list matches nothing and every mailbox caches
  a size of `0` — a tenant that reads as empty rather than as failed.
  `list_mailbox_usage` detects this and returns a warning alongside the totals.
  `get_mailbox_usage` is unaffected: it reads the Exchange admin API directly.
- **Sizes are gigabyte-rounded on the per-user path.** CIPP rounds to two
  decimal places of a gigabyte before returning, so `get_mailbox_usage` byte
  counts are accurate to roughly 10 MB. Quotas are exact — they are recovered
  from the raw `Get-Mailbox` string, which carries the true byte count.

## Authentication Setup

CIPP's API Client Management page provisions an Entra ID app registration and
returns an OAuth **client ID + client secret** (not a long-lived Bearer token).
The server exchanges these for a short-lived access token on each request using
the OAuth 2.0 client-credentials flow, and caches the token until just before
its expiry.

1. In CIPP, go to **Settings → CIPP Settings → Integrations → CIPP-API**
2. Create a new API client
3. Copy the **Client ID** and **Client Secret** — you will not be able to
   retrieve the secret later
4. Configure the server with the **Function App URL** (see below):
   ```env
   CIPP_BASE_URL=https://cippXXXXX.azurewebsites.net
   CIPP_TENANT_ID=<your-entra-tenant-id>
   CIPP_CLIENT_ID=<client-id-from-cipp>
   CIPP_CLIENT_SECRET=<client-secret-from-cipp>
   ```

If you already have a static Bearer token (older CIPP deployments), set
`CIPP_API_KEY` instead and leave the OAuth variables unset. When both are
provided, `CIPP_API_KEY` wins.

## Finding your Function App URL

CIPP runs as an Azure Static Web App (SWA) backed by an Azure Function App.
The SWA URL (your custom domain or `*.azurestaticapps.net`) enforces browser-only
auth and **cannot be used as `CIPP_BASE_URL`**. Use the Function App URL instead.

**Self-hosted CIPP:** Find the Function App in the Azure portal (look for an App Service
with `Kind: functionapp` in the same resource group as your SWA), or run:
```sh
az staticwebapp show --name <your-swa-name> --resource-group <rg> \
  --query "linkedBackends[0].backendResourceId" -o tsv
```

**CIPP-sponsored hosting:** Contact the CIPP team for your instance's Function App URL —
it is not the same as the URL shown in your browser.

## IP Allowlist

CIPP validates each API client against an `IPRange` field stored in Azure Table Storage.
If your server's public IP is not in this list, you will receive:

> `Access to this CIPP API endpoint is not allowed, the API Client does not have the required permission`

**Self-hosted:** Add your IP via the CIPP UI (Settings → API Client Management) or
directly in the `ApiClients` table of your CIPP storage account.

**CIPP-sponsored hosting:** Ask the CIPP team to add your server's public IP to your
API client's allowed range.

## IT Simply modifications

This is IT Simply Ltd's fork of [`WYRE-AI/cipp-mcp`](https://github.com/WYRE-AI/cipp-mcp),
forked from upstream commit [`56e39301`](https://github.com/WYRE-AI/cipp-mcp/commit/56e39301a07b34fede5ca59c424a94b85f8f4ba4).
Per Apache License 2.0 §4(b), this notice records that the files below were
changed from that upstream version.

**14 write-capable tools were removed** — their tool definitions, dispatch
cases, and underlying `CippService` HTTP methods — so this server can only
read CIPP data, never modify a managed tenant. This is deliberate: CIPP can
reset passwords, delete accounts, redirect mail, and push conditional access
policies across every customer tenant it manages, and IT Simply runs this
server with read-only intent. Deleting the code, rather than gating it behind
a configuration flag, means there is no flag to mistype and no write path left
for a future tool to reach even if reintroduced.

Removed tools:

| Tool | Reason |
|---|---|
| `cipp_create_user` | creates an AAD user |
| `cipp_edit_user` | edits attributes, adds/strips licences |
| `cipp_disable_user` | blocks sign-in |
| `cipp_reset_password` | invalidates the current password |
| `cipp_reset_mfa` | clears all MFA methods |
| `cipp_revoke_sessions` | kills sessions and refresh tokens |
| `cipp_offboard_user` | can pass `DeleteUser: true` — irreversible |
| `cipp_create_group` | creates an AAD group |
| `cipp_set_out_of_office` | sets mailbox auto-reply |
| `cipp_set_email_forwarding` | redirects mail; a data-exfiltration vector |
| `cipp_run_standards_check` | reads as a check, but applies remediation if the tenant's Standards Template has a Remediate-action standard |
| `cipp_create_standard_template` | upserts a template that modifies tenants on the next standards run |
| `cipp_delete_standard_template` | silently un-enforces whatever it enforced |
| `cipp_add_scheduled_item` | forwards an arbitrary command string to CIPP's scheduler, optionally against every managed tenant |

`tests/tool-guard.test.ts` is new IT Simply code (not present upstream) that
asserts `TOOL_DEFINITIONS.length === 31` and that none of the 14 names above
are present, so a future `git merge upstream/main` that silently reintroduces
one of these tools fails the build rather than shipping.

Files changed from upstream: `src/mcp/tool.definitions.ts`,
`src/handlers/tool.handler.ts`, `src/services/cipp.service.ts`,
`tests/cipp.service.standards.test.ts`, `README.md` (this file), and the
addition of `tests/tool-guard.test.ts`. Five now-dead test files that covered
only removed tools were deleted:
`tests/cipp.service.create-user.test.ts`, `tests/cipp.service.edit-user.test.ts`,
`tests/cipp.service.offboard-user.test.ts`, `tests/cipp.service.mailbox.test.ts`,
`tests/cipp.service.scheduled-items.test.ts`.

`listEnterpriseApps` was kept: it calls CIPP's `ListGraphRequest` relay with a
hardcoded GET query and is a legitimate read, not a write in disguise.

## License

Apache-2.0 — see [LICENSE](LICENSE)

## Contributing

Issues and PRs welcome. This server is tracked against [wyre-technology/msp-claude-plugins#24](https://github.com/wyre-technology/msp-claude-plugins/issues/24).
