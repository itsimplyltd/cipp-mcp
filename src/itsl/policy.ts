// IT Simply Ltd: tier policy for the CIPP MCP server (new file, not derived from upstream).
//
// Every CIPP endpoint is assigned one of four tiers by `computeTier` (tier.ts)
// using ONLY the data in this file plus the endpoint's name and x-cipp-role.
// To change what the server will do, edit this file and nothing else.

/**
 * Endpoint names that are never callable, by anyone, through any route (meta
 * tool or named tool). Compared case-insensitively: CIPP resolves names
 * case-sensitively, but a spelling variant must not slip past the list.
 *
 * Decision 4 (sensitive reads the public CIPP MCP exposes), decision 6
 * (dangerous triggers Grant named), and the three endpoints CIPP's own
 * catalogue also excludes.
 */
export const BLOCKED_NAMES: readonly string[] = [
  // Decision 4: sensitive reads
  'ExecGetLocalAdminPassword', // LAPS passwords
  'ExecGetRecoveryKey', // BitLocker recovery keys
  // RULING (beyond the design's list, conservative): same exposure as the two above.
  'ExecBitlockerSearch', // searches BitLocker recovery keys
  // RULING (security review): Graph is reachable ONLY through cipp_graph_request,
  // which builds its own call from an allowlist (src/itsl/graph.ts). These four
  // are arbitrary-Graph or Graph-state relays and are never callable via cipp_exec_tool.
  'ListGraphRequest',
  'ListGraphBulkRequest',
  'ExecGraphExplorerPreset', // saves/deletes CIPP presets
  'ExecGraphRequestProfile', // arbitrary Graph GETs without a blocklist; Reset clears counters
  // RULING (security review): stored CIPP backups contain integration config, API clients, etc.
  'ExecListBackup',
  'ListApiTest', // echoes the request, including the caller's Authorization header
  'ListExoRequest', // arbitrary Exchange Online cmdlet proxy
  'ExecSendPush', // sends a live MFA push to a user
  'ExecMailTest',
  'ExecBreachSearch',
  'ListExtensionsConfig', // extension (integration) configuration
  // Decision 6: called dangerous by Grant
  'ExecCPVRefresh',
  'ExecStandardsRun',
  'ExecCIPPDBCacheAdmin',
  // Never exposed: the MCP transport itself, the spec dump, and the docs
  // search that CIPP serves as SearchDocs/GetDoc (this server has neither).
  'ExecMcp',
  'ListOpenApiSpec',
  'ListCippDocs',
];

/**
 * Role patterns that block every endpoint carrying a matching x-cipp-role.
 *
 * RULING (decision 4 says "every CIPP.Extension.* config read"): only the
 * `.Read` roles of CIPP.Extension are blocked. Blocking the whole prefix would
 * also block ExecExtensionSync (CIPP.Extension.ReadWrite), which decision 6
 * puts in the launch write tier. A side effect: ListExtensionSync, a status
 * read, is blocked too (conservative; promote via a reviewer decision if wanted).
 */
export const BLOCKED_ROLE_PATTERNS: readonly RegExp[] = [
  /^CIPP\.Backup\./i,
  /^CIPP\.SuperAdmin\./i,
  /^CIPP\.AppSettings\./i,
  /^CIPP\.Extension\.Read$/i,
];

/** Any endpoint whose name contains one of these is blocked (RULING: every *Backup* endpoint). */
export const BLOCKED_NAME_PATTERNS: readonly RegExp[] = [/backup/i];

/** Decision 6: the write tier at launch is the sync triggers only. */
export const WRITE_ALLOWLIST: readonly string[] = [
  'ExecCIPPDBCache',
  'ExecSyncAPDevices',
  'ExecSyncDEP',
  'ExecSyncVPP',
  'ExecExtensionSync',
  'ExecTestRefresh',
  'ExecTestRun',
];

/**
 * CIPP's own read-only rule: a `.Read` role (never `.ReadWrite`) ... AND, RULING
 * (security review), the endpoint must have a GET operation and is only ever
 * invoked as GET. POST-only `.Read` endpoints (e.g. ExecBECCheck) compute to
 * `disabled` pending review: CIPP labels some POST handlers `.Read` that change state.
 */
export const READ_ROLE_PATTERN = /\.Read$/i;

/** ... on an endpoint whose name does not imply a mutation. */
export const MUTATION_NAME_PATTERN =
  /^(Add|Set|Remove|Delete|Edit|New|Update|Disable|Enable|Reset|Revoke|Push|Clear|Start|Stop|Rename|Move|Copy)/;

/**
 * Manual promotions of an otherwise-`disabled` endpoint to `read` or `write`
 * after review. `blocked` always wins over this map.
 *
 * Both entries exist because named WYRE tools call endpoints that CIPP's spec
 * gives no `.Read` role (so the rule cannot place them):
 *  - ListBPA: absent from CIPP's openapi.json entirely.
 *  - PublicPing: role is `Public`; a connectivity check with no tenant data.
 */
export const REVIEWED: Readonly<Record<string, 'read' | 'write'>> = {
  ListBPA: 'read',
  PublicPing: 'read',
};

/**
 * cipp_graph_request allowlist. THIS IS THE KNOB: to let the model read more of
 * Microsoft Graph, add a collection prefix here (lower-case, no leading slash,
 * no version). NOTE: devicemanagement/deviceconfigurations is deliberately NOT
 * listed: full GETs may return Wi-Fi/VPN preSharedKey values (unverified). Re-add
 * it after a live check. A request path must equal a prefix or sit beneath it
 * (prefix + '/...'). Anything not listed is refused. The denylist below is
 * applied on top of the allowlist and always wins.
 */
export const GRAPH_ALLOWED_PREFIXES: readonly string[] = [
  'users',
  'groups',
  'devices',
  'serviceprincipals',
  'applications',
  'domains',
  'organization',
  'subscribedskus',
  'directoryroles',
  'rolemanagement/directory',
  'identity/conditionalaccess',
  'policies',
  'auditlogs',
  'reports',
  'security/alerts_v2',
  'security/incidents',
  'devicemanagement/manageddevices',
  'devicemanagement/devicecompliancepolicies',
  'teams',
  'sites',
];

/** Terms that are refused anywhere in a Graph path or in $select/$filter/$expand values (lower-case, substring). */
export const GRAPH_DENY_TERMS: readonly string[] = [
  'informationprotection',
  'bitlocker',
  'devicelocalcredentials',
  'recoverykeys',
  'recoverykey',
  'getfilevaultkey',
  'filevault',
  'getomasettingplaintextvalue',
  'secretreference',
  'activationlockbypasscode',
  'presharedkey',
  'temporaryaccesspass',
  'passwordmethod',
];

/**
 * Endpoints that carry a `.Read` role but change state (RULING, security review):
 * forced to `disabled` regardless of the read rule or the reviewed map.
 *  - ListAuditLogSearches: its default branch creates a unified-audit-log search.
 *  - ExecBECCheck: starts a BEC investigation.
 * Blocked still wins over this list.
 */
export const FORCE_DISABLED: readonly string[] = ['ListAuditLogSearches', 'ExecBECCheck'];

/**
 * Graph path SEGMENTS that are customer content (mail, calendar, files, chats,
 * notes, contacts, photos, list items) and are refused anywhere in a path, under
 * every allowed collection (RULING, prompt-injection hardening). Compared
 * case-insensitively against whole segments, so e.g. users/x/messages,
 * sites/x/drive, sites/x/lists/y/items and teams/x/channels/y/messages are all refused.
 * The same words are refused as whole words in $select and $expand.
 */
export const GRAPH_CONTENT_SEGMENTS: readonly string[] = [
  'messages',
  'mailfolders',
  'events',
  'calendar',
  'calendars',
  'calendarview',
  'drive',
  'drives',
  'onenote',
  'chats',
  'contacts',
  'contactfolders',
  'teamwork',
  'joinedteams',
  'photo',
  'photos',
  'extensions',
  'items',
  'conversations',
  'threads',
  'posts',
  'pages',
  'canvaslayout',
  'webparts',
  'planner',
  'todo',
  'mailboxsettings',
  'insights',
  'onlinemeetings',
  'shifts',
  'schedule',
  'notes',
  'attachments',
];

/**
 * Argument keys whose VALUES may contain '/' (free-text and filter keys), and
 * also '&' and the guest marker #EXT#. Compared case-insensitively, TOP-LEVEL
 * string values only (never nested). Even here `..`, backslash, control
 * characters, '?' and '%' are refused.
 * Keys ending "url" (siteUrl, url, webUrl, ...) are NOT here: their value must be
 * an https SharePoint URL (see values.ts), so '/' needs no blanket allowance.
 * Add a key here only after reviewing what CIPP does with it.
 *
 * NOTE: the value rules assume a read-only tool set. They MUST be revisited
 * (passwords, out-of-office text, templates, free-text bodies) before Grant
 * enables any write tool; today those tools are disabled so it is moot.
 */
export const VALUE_FILTER_KEYS: readonly string[] = ['filter', '$filter', 'graphfilter', 'search', 'query', 'searchstring'];
export const VALUE_SLASH_ALLOWED_KEYS: readonly string[] = VALUE_FILTER_KEYS;
