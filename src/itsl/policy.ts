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
  'ListGraphBulkRequest', // arbitrary Graph reads from a body; would bypass GRAPH_BLOCKED_ENDPOINTS
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
  /^CIPP\.SuperAdmin\./i,
  /^CIPP\.AppSettings\./i,
  /^CIPP\.Extension\.Read$/i,
];

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

/** CIPP's own read-only rule: a `.Read` role (never `.ReadWrite`) ... */
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
 * ListGraphRequest runs an arbitrary Graph GET (CIPP.Core.Read), so on its own
 * it would reopen the secrets the name blocklist closes (BitLocker keys, LAPS
 * passwords) through Graph paths. Any `Endpoint` matching one of these is
 * refused wherever ListGraphRequest is reachable (cipp_graph_request and
 * cipp_exec_tool). Matched case-insensitively against the decoded path.
 * RULING: not in the design text; added as the conservative reading of decision 4.
 */
export const GRAPH_BLOCKED_ENDPOINTS: readonly RegExp[] = [
  /bitlocker/i,
  /recoverykey/i,
  /devicelocalcredential/i,
  /temporaryaccesspass/i,
  /passwordmethod/i,
];
