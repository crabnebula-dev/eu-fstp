// The page logic of invitations and role grants (J1, J2, SoD-09, D1; M4
// design sections 2.2 and 3.2).
//
// This module is pure: it touches no DOM, so Node can load it. The
// response readers are the interim readings of this lane, pending Daniel
// and the generated validators of `web/src/gen/api.ts` (lane W3a).

/**
 * The role keys of the invitation form, one per `fstp_domain::roles::Role`
 * that the creator's People step invites. Interim, pending Daniel: the
 * wire spelling of roles is not fixed yet.
 */
export const ROLES = [
  "programme_manager",
  "call_drafter",
  "fstp_coordinator",
  "committee_member",
  "committee_chair",
  "irc_member",
] as const;

/** One role the People step invites. */
export type RoleKey = (typeof ROLES)[number];

/** Whether `s` names a role of the invitation form. */
export function isRole(s: string): s is RoleKey {
  return (ROLES as readonly string[]).includes(s);
}

/** The Judging roles, whose terms state the programme's P-75 and P-77 choices (J2). */
export const JUDGING_ROLES: ReadonlySet<string> = new Set(["committee_member", "committee_chair", "irc_member"]);

/** An invitation's state as the people pages show it. */
export type InvitationState = "invited" | "accepted" | "verified" | "granted";

/** The live separation of duties check of an invitation (D3). */
export type SodState = "pass" | "fail" | "unchecked";

/**
 * Whether the people admin page offers the grant. It does only for an
 * invitee who accepted the confidentiality terms and verified identity
 * (J2, SoD-09), and never twice. While the programme is a draft, it does
 * only for a programme manager (D1). The server checks each rule again
 * at the grant.
 */
export function grantOffered(programme: "draft" | "active", role: string, state: InvitationState): boolean {
  if (state !== "verified") return false;
  return programme === "active" || role === "programme_manager";
}

/** An approval id as the pages pass it in a route: 1 to 64 URL-safe characters. */
export function isApprovalId(v: unknown): v is string {
  return typeof v === "string" && /^[0-9A-Za-z_-]{1,64}$/.test(v);
}

/**
 * The body of a role grant (`roles.grant`). A self-grant names the second
 * admin approval it consumes (SoD-07). Interim, pending Daniel: the wire
 * shape `{invitation, approval?}` is this lane's reading.
 */
export function grantBody(row: { readonly id: string; readonly approval: string | null }): Record<string, string> {
  return row.approval === null ? { invitation: row.id } : { approval: row.approval, invitation: row.id };
}

/** `v` as a plain object, or null. */
export function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

const STATES: ReadonlySet<string> = new Set(["invited", "accepted", "verified", "granted"]);
const SODS: ReadonlySet<string> = new Set(["pass", "fail", "unchecked"]);

/** One invitation of a programme. */
export interface InvitationRow {
  readonly id: string;
  readonly email: string;
  readonly role: RoleKey;
  readonly state: InvitationState;
  readonly sod: SodState;
  /** The rule a failed SoD check names, never an account (R-CF-03). */
  readonly rule: string | null;
  /**
   * The second admin approval of a self-grant (SoD-07), once one is
   * recorded for this invitation. The grant names it, and the server
   * consumes it.
   */
  readonly approval: string | null;
}

/**
 * Reads `{invitations: [{id, email, role, state, sod, rule?, approval?}]}`.
 * Null otherwise.
 *
 * Interim, pending Daniel and lane W3a: `approval` is this lane's
 * reading of how the people admin page learns the `ApprovalId` that
 * `admin.approve_self_grant` yields for a tenant admin's own grant.
 */
export function readInvitations(body: unknown): InvitationRow[] | null {
  const list = record(body)?.["invitations"];
  if (!Array.isArray(list)) return null;
  const out: InvitationRow[] = [];
  for (const x of list as unknown[]) {
    const r = record(x);
    if (r === null) return null;
    const id = r["id"];
    const email = r["email"];
    const role = r["role"];
    const state = r["state"];
    const sod = r["sod"];
    const rule = r["rule"];
    const approval = r["approval"];
    if (typeof id !== "string" || !/^[0-9A-Za-z_-]{1,64}$/.test(id)) return null;
    if (typeof email !== "string" || typeof role !== "string" || !isRole(role)) return null;
    if (typeof state !== "string" || !STATES.has(state) || typeof sod !== "string" || !SODS.has(sod)) return null;
    if (rule !== undefined && rule !== null && typeof rule !== "string") return null;
    if (approval !== undefined && approval !== null && !isApprovalId(approval)) return null;
    out.push({
      id,
      email,
      role,
      state: state as InvitationState,
      sod: sod as SodState,
      rule: typeof rule === "string" ? rule : null,
      approval: isApprovalId(approval) ? approval : null,
    });
  }
  return out;
}

/** An invitation as its landing page shows it to the invitee. */
export interface InvitationView {
  readonly role: RoleKey;
  /** The version of the confidentiality terms the acceptance names. */
  readonly termsVersion: number;
  /** The programme's P-75 choice, for the terms of a Judging role. */
  readonly p75: boolean | null;
  /** The programme's P-77 choice, for the terms of a Judging role. */
  readonly p77: string | null;
  readonly state: InvitationState;
}

/**
 * Reads `{role, terms_version, p75?, p77?, state}`. Null otherwise.
 *
 * Interim, pending Daniel: J2 says the terms of Judging roles state the
 * programme's P-75 and P-77 choices through bound placeholders. This is
 * the lane's reading of where the page gets them. A missing or null
 * choice means the programme has not made it yet. The landing then
 * states it as undecided and offers no acceptance, never a default.
 */
export function readInvitationView(body: unknown): InvitationView | null {
  const o = record(body);
  if (o === null) return null;
  const role = o["role"];
  const version = o["terms_version"];
  const state = o["state"];
  const p75 = o["p75"];
  const p77 = o["p77"];
  if (typeof role !== "string" || !isRole(role)) return null;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) return null;
  if (typeof state !== "string" || !STATES.has(state)) return null;
  if (p75 !== undefined && p75 !== null && typeof p75 !== "boolean") return null;
  if (p77 !== undefined && p77 !== null && p77 !== "draft_only" && p77 !== "allowed") return null;
  return {
    role,
    termsVersion: version,
    p75: typeof p75 === "boolean" ? p75 : null,
    p77: typeof p77 === "string" ? p77 : null,
    state: state as InvitationState,
  };
}

/**
 * The invitation token of a landing link, `/app/invitation#<token>`: 32
 * to 128 lower-case hex digits. Null for any other fragment. The token
 * travels in the fragment, so it never reaches a server log as a query.
 */
export function invitationToken(fragment: string): string | null {
  return /^[0-9a-f]{32,128}$/.test(fragment) ? fragment : null;
}

/** An email address as the invitation form takes it: one `@`, no spaces. */
export function plausibleEmail(s: string): boolean {
  const t = s.trim();
  const at = t.indexOf("@");
  return t.length <= 254 && at > 0 && at === t.lastIndexOf("@") && at < t.length - 1 && !/\s/.test(t);
}
