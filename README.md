# CIPP MCP Server

MCP (Model Context Protocol) server for [CIPP](https://github.com/CyberDrain/CIPP) — the CyberDrain Improved Partner Portal. Provides AI assistants with structured access to CIPP's M365 multi-tenant management capabilities.

> **This is IT Simply's tiered fork.** Every CIPP endpoint is read, write, disabled or
> blocked, and the 14 write tools stay disabled. See
> [IT Simply modifications](#it-simply-modifications) below.

## Features

- **47 named tools** plus a tiered catalogue of CIPP's whole API (`cipp_search_tools`, `cipp_get_tool_info`, `cipp_exec_tool`); only tools your tier can call are listed
- Tenant, user, group, and mailbox visibility
- Mailbox and online-archive size reporting, per tenant or per user
- Per-user Entra ID sign-in logs (status, location, Conditional Access, MFA)
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
| `CIPP_TOKEN_SCOPE` | No | Override OAuth scope. Default: `api://<clientId>/.default`. An explicit value disables the legacy-scope fallback below. |
| `CIPP_TOKEN_SCOPE_FALLBACK` | No | When no explicit scope is set, retry a CIPP HTTP 401 once with the legacy `<clientId>/.default` scope and reuse whichever audience this client accepts. Default: `true`. `TOKEN_SCOPE_FALLBACK` is an alias. Gateway requests can send `x-token-scope-fallback`. |
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
| Users | list_users, bec_check, list_mfa_users, list_user_devices, list_user_groups, list_user_signin_logs |
| Groups | list_groups |
| Mailboxes | list_mailboxes, list_mailbox_permissions, list_mailbox_usage, get_mailbox_usage, list_trusted_blocked_senders |
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

### User sign-in logs

`list_user_signin_logs` returns one user's most recent interactive sign-ins,
newest first: time, app, IP, location, success or failure with error code and
reason, client app, Conditional Access status and the policies that evaluated,
the authentication methods Graph recorded (first factor included — whether
MFA was required is `authenticationRequirement`), device, and risk when
flagged — plus a summary of failures, distinct IPs and countries.

- **Accepts a UPN or an object id, and always resolves it first.** CIPP filters
  Graph on `userId`, which is the Entra object id; a UPN there matches nothing
  and returns an empty page that reads as "this user never signs in". An
  unresolvable user is an error, not an empty result.
- **One tenant, one user, one page.** `top` defaults to 50 and caps at 1000; a
  full page carries a warning that older sign-ins may exist. `allTenants` is
  rejected — the endpoint has no all-tenants branch. Tenant-wide sign-ins are
  CIPP's Sign-Ins report (`ListSignIns`), which this server does not expose.
- **Needs Entra ID P1/P2 in the tenant.** Graph refuses sign-in log API access
  otherwise; the tool names the licence gap instead of relaying a generic
  "Failed to retrieve Sign In report".

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

The access token is requested for `api://<clientId>/.default`. That is the
Application ID URI CIPP's App Service authentication allows. A token requested
for the bare `<clientId>/.default` scope has its `aud` set to the client id
GUID, and App Service auth rejects it with HTTP 401 and an empty body.
Deployments that still expect that legacy audience are handled automatically:
when no explicit scope is configured, a 401 is retried once with the other
automatic audience (`api://<clientId>/.default` or `<clientId>/.default`).
The audience that succeeds is reused for later calls from the same client.
If that audience later starts failing with 401, the pin is dropped and the
other audience is tried once, then whichever succeeds is remembered again.
The retry does not run for any other status (403, 500, and so on), and a
single request never tries more than once. Set `CIPP_TOKEN_SCOPE` to force
a scope, or `CIPP_TOKEN_SCOPE_FALLBACK=false` (alias `TOKEN_SCOPE_FALLBACK`,
gateway header `x-token-scope-fallback`) to skip the retry.

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

This is IT Simply Ltd's fork of [`WYRE-AI/cipp-mcp`](https://github.com/WYRE-AI/cipp-mcp).
Per Apache License 2.0 section 4(b), each modified upstream file carries a
"Modified by IT Simply Ltd, 2026" line at the top. New IT Simply code lives in `src/itsl/`.

**The 14 write tools are present again but unreachable.** An earlier version of this
fork deleted them; they are restored from upstream and held back by policy instead,
so a merge from upstream stays conflict-light. Every tool, and every endpoint
reached through `cipp_exec_tool`, gets a tier from `src/itsl/policy.ts`:

| Tier | Meaning |
|---|---|
| `read` | Callable by everyone: a `.Read` role on a non-mutating endpoint name (CIPP's own rule) |
| `write` | Callable only with the CIPP.Write gateway role: the cache and sync triggers on the allowlist |
| `disabled` | Everything else; refused for everyone until promoted in the `REVIEWED` map |
| `blocked` | Sensitive or dangerous (LAPS, BitLocker, MFA push, SuperAdmin/AppSettings/Extension config); always wins |

The tier check is in one place, `CippToolHandler.handleToolCall`, so no tool can
skip it. `tools/list` is filtered by tier. CIPP still applies each user's own CIPP role.

Per-user mode: in `AUTH_MODE=gateway` the `x-user-token` header is the credential
CIPP sees (and the only one used). The caller's tier and user come only from a
verified S2S v2 header `x-gateway-s2s: t=<unix>,v2=<hex>` where
`v2 = HMAC-SHA256(secret, "t=<unix>
tier=<read|write>
user=<upn>")`.

| Env var | Effect |
|---|---|
| `CONDUIT_S2S_SECRET` | S2S secret (as upstream) |
| `ITSL_REQUIRE_S2S_V2` | `true`: only a verified v2 header is accepted; tier defaults to read otherwise |
| `ITSL_REQUIRE_USER_TOKEN` | `true`: any request without `x-user-token` gets 401 |
| `ITSL_SPEC_PATH` | CIPP endpoint serving the OpenAPI spec (default `ListOpenApiSpec`) |
| `ITSL_SPEC_GITHUB_REPO` | Fallback spec repo (default `KelvinTegelaar/CIPP-API`) |

The catalogue is projected from CIPP's OpenAPI document at first use and every 6 hours.
CIPP-API is AGPL-3.0: this repository never contains its `openapi.json` or code.

Graph is reachable only through `cipp_graph_request`, which builds the CIPP call itself from an
allowlist of read collections (`GRAPH_ALLOWED_PREFIXES` in `src/itsl/policy.ts`, with a denylist of secret terms and
customer-content segments on top). To let the model read more of Graph, add a prefix there. The read tier is GET-only.
Every tool result starts with a line marking it as untrusted customer-tenant data; CIPP errors are truncated to 500 characters.
The S2S v2 string also binds `sha256(x-user-token)`; `x-mcp-user` arrives percent-encoded (non-printable-ASCII and `%`) and is signed as received.

Guard tests (`tests/itsl-*.test.ts`) fail the build if a blocked name is callable,
a `ReadWrite` endpoint computes to read, a read caller can run a write entry, a
write tool becomes reachable, or an unsigned/v1-only request is accepted with
`ITSL_REQUIRE_S2S_V2=true`.

## License

Apache-2.0 — see [LICENSE](LICENSE)

## Contributing

Issues and PRs welcome. This server is tracked against [wyre-technology/msp-claude-plugins#24](https://github.com/wyre-technology/msp-claude-plugins/issues/24).
