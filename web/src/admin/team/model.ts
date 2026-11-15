// The pure part of the team and member pages and of the display name
// (SA-11, Daniel 2026-11-15 night; `docs/design/spec-amendments.md`).
//
// - `team.list` answers `{actions, rows}`: each Drafting, Judging and
//   Operations role of one programme, open invitations included, with
//   the display name and the invitation or login email.
// - `admin.members` answers `{actions, members}`: each member account of
//   the organisation with its roles across programmes.
// - `actions` names what the viewer may offer: grant, end, reinstate and
//   invite. The server decides each again when it is taken.
// - `me.set_display_name` takes `{display_name}`: plain text of at most
//   100 characters, or null to clear it.
//
// Every check is closed: an unknown or missing member refuses the reply.
// No role of the Receiving group is admitted, so no applicant is shown.

/** The roles the pages list, as `fstp_access::TEAM_ROLES` names them. */
export const TEAM_ROLES = [
  "programme_manager",
  "call_drafter",
  "fstp_coordinator",
  "committee_member",
  "committee_chair",
  "irc_member",
  "tenant_admin",
  "finance_approver",
  "payment_releaser",
  "contract_signatory",
  "financial_signatory",
  "legal_signatory",
  "auditor",
] as const;

/** One role the pages list. */
export type TeamRole = (typeof TEAM_ROLES)[number];

/** The statuses of a role (SA-11). */
export const TEAM_STATUSES = ["invited", "accepted", "verified", "active", "suspended", "ended"] as const;

/** One status. */
export type TeamStatus = (typeof TEAM_STATUSES)[number];

/** The actions a page may offer. */
export const TEAM_ACTIONS = ["grant", "end", "reinstate", "invite"] as const;

/** One action. */
export type TeamAction = (typeof TEAM_ACTIONS)[number];

/** The Operations roles: a grant needs the terms only, no verified identity (SoD-09). */
const OPERATIONS: ReadonlySet<string> = new Set([
  "finance_approver",
  "payment_releaser",
  "contract_signatory",
  "auditor",
]);

/** One role: a binding or an open invitation. */
export interface RoleRow {
  /** The programme, or null for a tenant-wide role. Team rows are all of the page's programme. */
  readonly programme: string | null;
  readonly binding: string | null;
  readonly invitation: string | null;
  readonly role: TeamRole;
  readonly status: TeamStatus;
  /** The rule of a suspension or a voiding, never an account (R-CF-03). */
  readonly rule: string | null;
  /** Instants as decimal strings of UTC microseconds. */
  readonly start: string | null;
  readonly end: string | null;
}

/** One row of the team page. */
export interface TeamRow extends RoleRow {
  readonly account: string | null;
  readonly displayName: string | null;
  readonly email: string | null;
}

/** The `team.list` reply. */
export interface TeamReply {
  readonly actions: readonly TeamAction[];
  readonly rows: readonly TeamRow[];
}

/** One member account. */
export interface Member {
  readonly account: string;
  readonly displayName: string | null;
  readonly email: string | null;
  readonly tenantAdmin: boolean;
  readonly roles: readonly RoleRow[];
}

/** The `admin.members` reply. */
export interface MembersReply {
  readonly actions: readonly TeamAction[];
  readonly members: readonly Member[];
}

const ID = /^(0|[1-9][0-9]{0,38})$/;

function isId(v: unknown): v is string {
  return typeof v === "string" && ID.test(v);
}

function isNullableId(v: unknown): v is string | null {
  return v === null || isId(v);
}

function isNullableText(v: unknown): v is string | null {
  return v === null || typeof v === "string";
}

function oneOf<T extends string>(values: readonly T[], v: unknown): v is T {
  return typeof v === "string" && (values as readonly string[]).includes(v);
}

function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

/** Whether `o` has exactly the members `required` and at most those of `optional` besides. */
function closed(o: Readonly<Record<string, unknown>>, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(o);
  return required.every((k) => Object.hasOwn(o, k)) && keys.every((k) => required.includes(k) || optional.includes(k));
}

const ROLE_MEMBERS = ["binding", "invitation", "role", "status", "start", "end"] as const;

function roleOf(o: Readonly<Record<string, unknown>>, programme: string | null): RoleRow | null {
  const { binding, invitation, role, status, rule, start, end } = o;
  if (!isNullableId(binding) || !isNullableId(invitation)) return null;
  if (!oneOf(TEAM_ROLES, role) || !oneOf(TEAM_STATUSES, status)) return null;
  if (rule !== undefined && typeof rule !== "string") return null;
  if (!isNullableId(start) || !isNullableId(end)) return null;
  return Object.freeze({ programme, binding, invitation, role, status, rule: rule ?? null, start, end });
}

function actionsOf(v: unknown): readonly TeamAction[] | null {
  if (!Array.isArray(v)) return null;
  const out: TeamAction[] = [];
  for (const a of v as unknown[]) {
    if (!oneOf(TEAM_ACTIONS, a)) return null;
    out.push(a);
  }
  return Object.freeze(out);
}

/** The `team.list` reply of programme `programme`, or null when it has another shape. */
export function decodeTeam(v: unknown, programme: string): TeamReply | null {
  const o = record(v);
  if (o === null || !closed(o, ["actions", "rows"]) || !Array.isArray(o["rows"])) return null;
  const actions = actionsOf(o["actions"]);
  if (actions === null) return null;
  const rows: TeamRow[] = [];
  for (const x of o["rows"] as unknown[]) {
    const r = record(x);
    if (r === null || !closed(r, ["account", "display_name", "email", ...ROLE_MEMBERS], ["rule"])) return null;
    const role = roleOf(r, programme);
    const { account, display_name: displayName, email } = r;
    if (role === null || !isNullableId(account) || !isNullableText(displayName) || !isNullableText(email)) return null;
    rows.push(Object.freeze({ ...role, account, displayName, email }));
  }
  return Object.freeze({ actions, rows: Object.freeze(rows) });
}

/** The `admin.members` reply, or null when it has another shape. */
export function decodeMembers(v: unknown): MembersReply | null {
  const o = record(v);
  if (o === null || !closed(o, ["actions", "members"]) || !Array.isArray(o["members"])) return null;
  const actions = actionsOf(o["actions"]);
  if (actions === null) return null;
  const members: Member[] = [];
  for (const x of o["members"] as unknown[]) {
    const m = record(x);
    if (m === null || !closed(m, ["account", "display_name", "email", "tenant_admin", "roles"])) return null;
    const { account, display_name: displayName, email, tenant_admin: tenantAdmin, roles } = m;
    if (!isId(account) || !isNullableText(displayName) || !isNullableText(email)) return null;
    if (typeof tenantAdmin !== "boolean" || !Array.isArray(roles)) return null;
    const out: RoleRow[] = [];
    for (const y of roles as unknown[]) {
      const r = record(y);
      if (r === null || !closed(r, ["programme", ...ROLE_MEMBERS], ["rule"])) return null;
      const programme = r["programme"];
      if (!isNullableId(programme)) return null;
      const role = roleOf(r, programme);
      if (role === null) return null;
      out.push(role);
    }
    members.push(Object.freeze({ account, displayName, email, tenantAdmin, roles: Object.freeze(out) }));
  }
  return Object.freeze({ actions, members: Object.freeze(members) });
}

/** The `me.display_name` reply: the name, or null when none is set. Undefined for another shape. */
export function decodeDisplayName(v: unknown): string | null | undefined {
  const o = record(v);
  if (o === null || !closed(o, ["display_name"])) return undefined;
  const n = o["display_name"];
  return isNullableText(n) ? n : undefined;
}

/**
 * The per-role actions a page offers on `row`, among those the viewer
 * may take (`actions`). A grant needs an open invitation whose invitee
 * verified identity, or accepted the terms of an Operations role
 * (SoD-09). An end needs a binding that is active or suspended, and a
 * reinstatement a suspended one. The server decides each again.
 */
export function roleActions(row: RoleRow, actions: readonly TeamAction[]): readonly ("grant" | "end" | "reinstate")[] {
  const out: ("grant" | "end" | "reinstate")[] = [];
  const may = (a: TeamAction): boolean => actions.includes(a);
  if (row.programme === null) return out;
  if (may("grant") && row.invitation !== null) {
    if (row.status === "verified" || (row.status === "accepted" && OPERATIONS.has(row.role))) {
      out.push("grant");
    }
  }
  if (row.binding !== null) {
    if (may("reinstate") && row.status === "suspended") out.push("reinstate");
    if (may("end") && (row.status === "active" || row.status === "suspended")) out.push("end");
  }
  return Object.freeze(out);
}

/** The longest display name, in characters (SA-11). */
export const DISPLAY_NAME_MAX = 100;

/**
 * The `me.set_display_name` body for `text`: the trimmed name, or null to
 * clear it when `text` is blank. Null as a whole when the name is longer
 * than 100 characters or holds markup or a control character, which the
 * server refuses too.
 */
export function displayNameBody(text: string): { readonly display_name: string | null } | null {
  const t = text.trim();
  if (t === "") return Object.freeze({ display_name: null });
  if ([...t].length > DISPLAY_NAME_MAX || /[<>\p{Cc}]/u.test(t)) return null;
  return Object.freeze({ display_name: t });
}

/** `YYYY-MM-DD` of an instant in UTC microseconds, or the decimal text when it is out of range. */
export function dayOf(micros: string): string {
  const ms = Number(BigInt(micros) / 1000n);
  const d = new Date(ms);
  return Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 10) : micros;
}

/** The paths of the two pages. */
export const TEAM_PATHS = Object.freeze({
  team: (p: string): string => `/app/programmes/${p}/team`,
  members: "/app/admin/members",
  home: "/app/",
  account: "/auth/account",
});
