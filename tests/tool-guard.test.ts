// IT Simply guard test.
//
// This fork removes 14 write-capable tools from upstream cipp-mcp (see the
// "IT Simply modifications" section of README.md for why). Upstream is
// actively maintained, so a future `git merge upstream/main` could silently
// reintroduce one of them. This test is the tripwire: it fails the build the
// moment a removed tool name reappears in TOOL_DEFINITIONS, or the count
// drifts from the known-good total, rather than that surfacing later as a
// live write capability in production.
import { TOOL_DEFINITIONS } from '../src/mcp/tool.definitions.js';

/**
 * The 14 tool names removed from upstream. Every one of these could reset a
 * password, delete an account, exfiltrate mail, or push a tenant-wide policy
 * change — see README.md for the endpoint each one called and why it went.
 */
const REMOVED_WRITE_TOOL_NAMES = [
  'cipp_create_user',
  'cipp_edit_user',
  'cipp_disable_user',
  'cipp_reset_password',
  'cipp_reset_mfa',
  'cipp_revoke_sessions',
  'cipp_offboard_user',
  'cipp_create_group',
  'cipp_set_out_of_office',
  'cipp_set_email_forwarding',
  'cipp_run_standards_check',
  'cipp_create_standard_template',
  'cipp_delete_standard_template',
  'cipp_add_scheduled_item',
] as const;

describe('IT Simply read-only guard', () => {
  it('exposes exactly 31 tools', () => {
    expect(TOOL_DEFINITIONS.length).toBe(31);
  });

  it('never reintroduces a removed write tool', () => {
    const currentNames = new Set(TOOL_DEFINITIONS.map((t) => t.name));
    const reintroduced = REMOVED_WRITE_TOOL_NAMES.filter((name) => currentNames.has(name));
    expect(reintroduced).toEqual([]);
  });

  it('every tool name still starts with the cipp_ prefix', () => {
    const offenders = TOOL_DEFINITIONS.map((t) => t.name).filter((name) => !name.startsWith('cipp_'));
    expect(offenders).toEqual([]);
  });
});
