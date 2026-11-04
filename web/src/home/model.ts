// The model of the home page and the site navigation: the caller's own
// roles as `me.roles` gives them, and the work each role leads to (M4
// design sections 2.2 J0 to J8, 3.6 and 3.9; Daniel's report of
// 2026-10-31).
//
// Interim, pending Daniel (design section 15.0, 2026-10-31): design
// section 2.2 names no home page. This module is the reading built for
// it. Each role links to the pages of its journey:
//
// - an applicant or team member to each own proposal and the proposal
//   list, a guardian to the guardian page of the proposal (J4);
// - a tenant admin to the onboarding summary, a new programme draft and
//   the approval inbox (J0, J1, J2);
// - a programme manager to the creator review and the people page of
//   each programme that holds a creator draft, and to the call board of
//   each published call (J1, J3); a call drafter to the call board (J3);
// - the FSTP coordinator to the intake queue, the call board and the
//   notifiable conflicts of each published call (J5, R-CF-04);
// - a committee member to the assignments list, and every committee
//   member and the chair to the ranking of each published call and to
//   each open cut-off round (J6, J7);
// - an IRC member to the IRC cases (J8).
//
// Every person also gets the open calls. A role with no page in this
// release is named in a separate list, without a link.
//
// This module is pure: it reads values that `JSON.parse` produced and
// builds plain data. It holds no DOM code and no network code.

// ---------------------------------------------------------------------------
// The `me.roles` reply
// ---------------------------------------------------------------------------

/** The roles as the wire spells them (`fstp_access::role_wire_name`). */
export const ROLE_NAMES = [
  "programme_manager",
  "call_drafter",
  "fstp_coordinator",
  "committee_member",
  "committee_chair",
  "irc_member",
  "applicant",
  "applicant_team_member",
  "guardian",
  "tenant_admin",
  "finance_approver",
  "payment_releaser",
  "contract_signatory",
  "auditor",
] as const;

/** One role name. */
export type RoleName = (typeof ROLE_NAMES)[number];

/** One active binding of the caller. */
export interface RoleBinding {
  readonly role: RoleName;
  readonly programme: string;
  /** The proposal of a Receiving binding, else null. */
  readonly proposal: string | null;
  /**
   * The published calls the binding reaches: the proposal's call for a
   * Receiving binding, and every published call of the programme for a
   * programme binding.
   */
  readonly calls: readonly string[];
}

/** One open cut-off round of a call where the caller sits on the committee. */
export interface OpenRound {
  readonly round: string;
  readonly call: string;
}

/** The caller's own roles (`me.roles`, I-86). */
export interface MyRoles {
  readonly tenantAdmin: boolean;
  readonly roles: readonly RoleBinding[];
  /** The published title of each call named in `roles`, when the cell has it. */
  readonly titles: ReadonlyMap<string, string>;
  readonly rounds: readonly OpenRound[];
  /**
   * The programmes of the caller's programme manager bindings that hold
   * a creator draft. The creator and people pages read the draft, so the
   * home page links them only for these (review finding U1).
   */
  readonly drafts: ReadonlySet<string>;
}

type Rec = Readonly<Record<string, unknown>>;

/** A decimal id, as the server spells ids. */
const ID = /^(0|[1-9][0-9]{0,38})$/;

function isId(v: unknown): v is string {
  return typeof v === "string" && ID.test(v);
}

function rec(v: unknown): Rec | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Rec) : null;
}

/** Whether `o` holds every member of `required`, and no member outside it and `optional`. */
function closed(o: Rec, required: readonly string[], optional: readonly string[] = []): boolean {
  for (const k of required) {
    if (!Object.hasOwn(o, k)) {
      return false;
    }
  }
  return Object.keys(o).every((k) => required.includes(k) || optional.includes(k));
}

function each<T>(v: unknown, item: (x: unknown) => T | null): readonly T[] | null {
  if (!Array.isArray(v)) {
    return null;
  }
  const out: T[] = [];
  for (const x of v as readonly unknown[]) {
    const y = item(x);
    if (y === null) {
      return null;
    }
    out.push(y);
  }
  return Object.freeze(out);
}

function isRoleName(v: unknown): v is RoleName {
  return typeof v === "string" && (ROLE_NAMES as readonly string[]).includes(v);
}

function binding(v: unknown): RoleBinding | null {
  const o = rec(v);
  if (o === null || !closed(o, ["role", "programme", "calls"], ["proposal"])) {
    return null;
  }
  const role = o["role"];
  const programme = o["programme"];
  const proposal = Object.hasOwn(o, "proposal") ? o["proposal"] : null;
  const calls = each(o["calls"], (x) => (isId(x) ? x : null));
  if (!isRoleName(role) || !isId(programme) || calls === null || (proposal !== null && !isId(proposal))) {
    return null;
  }
  return Object.freeze({ role, programme, proposal, calls });
}

function callTitle(v: unknown): readonly [string, string | null] | null {
  const o = rec(v);
  if (o === null || !closed(o, ["call"], ["title"])) {
    return null;
  }
  const call = o["call"];
  const title = Object.hasOwn(o, "title") ? o["title"] : null;
  if (!isId(call) || (title !== null && typeof title !== "string")) {
    return null;
  }
  return [call, title];
}

function round(v: unknown): OpenRound | null {
  const o = rec(v);
  if (o === null || !closed(o, ["round", "call"])) {
    return null;
  }
  const r = o["round"];
  const c = o["call"];
  return isId(r) && isId(c) ? Object.freeze({ round: r, call: c }) : null;
}

/**
 * The `me.roles` reply, or null when `v` does not fit its shape: a closed
 * object `{tenant_admin, roles, calls, rounds, drafts}`, the shape of
 * `fstp_access::REPLIES` that `gen/api.ts` `SCHEMAS` holds.
 */
export function readMyRoles(v: unknown): MyRoles | null {
  const o = rec(v);
  if (o === null || !closed(o, ["tenant_admin", "roles", "calls", "rounds", "drafts"])) {
    return null;
  }
  const tenantAdmin = o["tenant_admin"];
  const roles = each(o["roles"], binding);
  const calls = each(o["calls"], callTitle);
  const rounds = each(o["rounds"], round);
  const drafts = each(o["drafts"], (x) => (isId(x) ? x : null));
  if (
    typeof tenantAdmin !== "boolean" ||
    roles === null ||
    calls === null ||
    rounds === null ||
    drafts === null
  ) {
    return null;
  }
  const titles = new Map<string, string>();
  for (const [c, title] of calls) {
    if (title !== null && title.trim() !== "") {
      titles.set(c, title);
    }
  }
  return Object.freeze({ tenantAdmin, roles, titles, rounds, drafts: new Set(drafts) });
}

// ---------------------------------------------------------------------------
// Work
// ---------------------------------------------------------------------------

/**
 * The kind of one piece of work, as `a[data-work]` names it on the home
 * page. The e2e contract (`e2e/navigation/support.ts`) names every kind
 * but `approvals`, `people` and `notifiable`, which this page adds.
 */
export type WorkKind =
  | "assignments"
  | "irc-cases"
  | "intake"
  | "board"
  | "notifiable"
  | "ranking"
  | "cut-off-round"
  | "proposals"
  | "proposal"
  | "guardian"
  | "onboarding"
  | "creator"
  | "approvals"
  | "people"
  | "open-calls";

/** One own proposal, as `proposal.list_own` gives it. */
export interface OwnProposal {
  readonly proposal: string;
  readonly role: "lead" | "member" | "guardian" | undefined;
  /** The title, or `""` when the cell sends none. */
  readonly title: string;
}

/** A message id of the home catalogue and its arguments. */
export interface Text {
  readonly id: string;
  readonly args: Readonly<Record<string, string>>;
}

/**
 * The card of the home page a link sits in, one per role group of
 * `docs/design/01-navigation-home.md` "Your work home per role": the
 * caller's own applications, guardian consent, the tenant admin, the
 * programme staff, the coordinator, the committee, the IRC, and the
 * open calls that anyone may read.
 */
export type WorkGroup =
  | "applicant"
  | "guardian"
  | "tenant_admin"
  | "programme"
  | "coordinator"
  | "committee"
  | "irc"
  | "everyone";

/** One link of the home page. */
export interface WorkItem {
  readonly kind: WorkKind;
  readonly href: string;
  readonly text: Text;
  readonly group: WorkGroup;
}

/** One role with no page in this release. */
export interface OtherRole {
  readonly role: RoleName;
  readonly programme: string;
}

/** What the home page lists. */
export interface Work {
  readonly items: readonly WorkItem[];
  readonly other: readonly OtherRole[];
  /**
   * Whether the caller holds no role at all: no binding, no own
   * proposal and not a tenant admin. The open calls are still listed.
   */
  readonly noRole: boolean;
}

/** The paths the home page links to (the route tables of `web/src`). */
export const WORK_PATHS = Object.freeze({
  home: "/app/",
  account: "/auth/account",
  calls: "/app/calls",
  proposals: "/app/proposals",
  notices: "/app/notices",
  proposal: (p: string): string => `/app/proposals/${p}`,
  guardian: (p: string): string => `/app/proposals/${p}/guardian`,
  onboarding: "/app/admin/onboarding/summary",
  creatorNew: "/app/creator/new",
  approvals: "/app/admin/approvals",
  creator: (p: string): string => `/app/programmes/${p}/creator/review`,
  people: (p: string): string => `/app/programmes/${p}/people`,
  board: (c: string): string => `/app/calls/${c}/board`,
  intake: (c: string): string => `/app/calls/${c}/intake`,
  notifiable: (c: string): string => `/app/calls/${c}/notifiable-conflicts`,
  ranking: (c: string): string => `/app/calls/${c}/ranking`,
  round: (r: string): string => `/app/cut-off-rounds/${r}`,
  assignments: "/app/me/assignments",
  ircCases: "/app/me/irc-cases",
});

/** The roles whose pages this release has, beside the Receiving roles. */
const STAFF_WITH_PAGES: ReadonlySet<RoleName> = new Set<RoleName>([
  "programme_manager",
  "call_drafter",
  "fstp_coordinator",
  "committee_member",
  "committee_chair",
  "irc_member",
  "tenant_admin",
]);

const RECEIVING: ReadonlySet<RoleName> = new Set<RoleName>(["applicant", "applicant_team_member", "guardian"]);

function text(id: string, args: Readonly<Record<string, string>> = {}): Text {
  return Object.freeze({ id, args: Object.freeze({ ...args }) });
}

/** Ids ascending as decimals, so call 2 comes before call 10. */
export function byId(a: string, b: string): number {
  return a.length === b.length ? (a < b ? -1 : a > b ? 1 : 0) : a.length - b.length;
}

/** The own proposals of the Receiving bindings, without titles. */
function receivingProposals(r: MyRoles): OwnProposal[] {
  return r.roles
    .filter((b) => RECEIVING.has(b.role) && b.proposal !== null)
    .map((b) => ({
      proposal: b.proposal ?? "",
      role: b.role === "guardian" ? "guardian" : b.role === "applicant" ? "lead" : "member",
      title: "",
    }));
}

/**
 * The work of the caller, in the order the home page lists it: own
 * proposals, tenant admin work, programme work, Judging work by call,
 * and the open calls last. A link appears once, under its first role.
 *
 * `own` is the `proposal.list_own` reply, or null when it could not be
 * read; then the proposals of the caller's Receiving bindings stand in,
 * without titles. `proposalName` names a proposal without a title, and
 * `callName` a call whose title the cell did not send.
 */
export function workOf(
  r: MyRoles,
  own: readonly OwnProposal[] | null,
  callName: (call: string) => string,
  proposalName: (proposal: string) => string,
): Work {
  const items: WorkItem[] = [];
  const seen = new Set<string>();
  const add = (group: WorkGroup, kind: WorkKind, href: string, t: Text): void => {
    if (!seen.has(href)) {
      seen.add(href);
      items.push(Object.freeze({ kind, href, text: t, group }));
    }
  };
  const nameOf = (c: string): string => r.titles.get(c) ?? callName(c);

  // J4: own proposals first, then the proposal list. A proposal the
  // list does not hold but a Receiving binding names is listed too.
  const proposals = new Map<string, OwnProposal>();
  for (const p of [...(own ?? []), ...receivingProposals(r)]) {
    const had = proposals.get(p.proposal);
    if (had === undefined) {
      proposals.set(p.proposal, p);
    } else if (had.title === "" && p.title !== "") {
      proposals.set(p.proposal, { ...had, title: p.title });
    }
  }
  let applies = false;
  for (const p of [...proposals.values()].sort((a, b) => byId(a.proposal, b.proposal))) {
    const title = p.title === "" ? proposalName(p.proposal) : p.title;
    if (p.role === "guardian") {
      add("guardian", "guardian", WORK_PATHS.guardian(p.proposal), text("home.work.guardian", { title }));
    } else {
      applies = true;
      add("applicant", "proposal", WORK_PATHS.proposal(p.proposal), text("home.work.proposal", { title }));
    }
  }
  if (applies) {
    add("applicant", "proposals", WORK_PATHS.proposals, text("home.work.proposals"));
  }

  // J0, J1, J2: the tenant admin.
  if (r.tenantAdmin) {
    add("tenant_admin", "onboarding", WORK_PATHS.onboarding, text("home.work.onboarding"));
    add("tenant_admin", "creator", WORK_PATHS.creatorNew, text("home.work.creator_new"));
    add("tenant_admin", "approvals", WORK_PATHS.approvals, text("home.work.approvals"));
  }

  const staff = r.roles.filter((b) => b.proposal === null);
  const holds = (role: RoleName): readonly RoleBinding[] => staff.filter((b) => b.role === role);
  const programmes = (bs: readonly RoleBinding[]): string[] => [...new Set(bs.map((b) => b.programme))].sort(byId);
  const callsOf = (bs: readonly RoleBinding[]): string[] => [...new Set(bs.flatMap((b) => b.calls))].sort(byId);

  // J1, J3: the programme manager. The creator and people pages read
  // the programme's creator draft, so they are linked only for a
  // programme that holds one (review finding U1).
  for (const p of programmes(holds("programme_manager")).filter((x) => r.drafts.has(x))) {
    add("programme", "creator", WORK_PATHS.creator(p), text("home.work.creator", { programme: p }));
    add("programme", "people", WORK_PATHS.people(p), text("home.work.people", { programme: p }));
  }
  // J6: a committee member's assignments.
  if (holds("committee_member").length > 0) {
    add("committee", "assignments", WORK_PATHS.assignments, text("home.work.assignments"));
  }
  // J8: the IRC cases.
  if (holds("irc_member").length > 0) {
    add("irc", "irc-cases", WORK_PATHS.ircCases, text("home.work.irc_cases"));
  }
  // J5: the coordinator, by call.
  for (const c of callsOf(holds("fstp_coordinator"))) {
    const call = nameOf(c);
    add("coordinator", "intake", WORK_PATHS.intake(c), text("home.work.intake", { call }));
    add("coordinator", "board", WORK_PATHS.board(c), text("home.work.board", { call }));
    add("coordinator", "notifiable", WORK_PATHS.notifiable(c), text("home.work.notifiable", { call }));
  }
  // J7: the committee, by call, and its open rounds.
  const committeeCalls = callsOf([...holds("committee_member"), ...holds("committee_chair")]);
  for (const c of committeeCalls) {
    add("committee", "ranking", WORK_PATHS.ranking(c), text("home.work.ranking", { call: nameOf(c) }));
  }
  const rounds = r.rounds.filter((x) => committeeCalls.includes(x.call)).sort((a, b) => byId(a.round, b.round));
  for (const x of rounds) {
    add("committee", "cut-off-round", WORK_PATHS.round(x.round), text("home.work.round", { call: nameOf(x.call) }));
  }
  // J1, J3: the call boards of the programme staff.
  for (const c of callsOf([...holds("programme_manager"), ...holds("call_drafter")])) {
    add("programme", "board", WORK_PATHS.board(c), text("home.work.board", { call: nameOf(c) }));
  }

  // J4: anyone may read the open calls.
  add("everyone", "open-calls", WORK_PATHS.calls, text("home.work.open_calls"));

  const other: OtherRole[] = [];
  const named = new Set<string>();
  for (const b of staff) {
    const key = `${b.role} ${b.programme}`;
    if (!STAFF_WITH_PAGES.has(b.role) && !named.has(key)) {
      named.add(key);
      other.push(Object.freeze({ role: b.role, programme: b.programme }));
    }
  }
  const noRole = !r.tenantAdmin && r.roles.length === 0 && proposals.size === 0;
  return Object.freeze({ items: Object.freeze(items), other: Object.freeze(other), noRole });
}

// ---------------------------------------------------------------------------
// The site navigation
// ---------------------------------------------------------------------------

/** The kinds of link of the site navigation, as `a[data-nav]` names them. */
export type NavKind =
  | "home"
  | "assignments"
  | "irc-cases"
  | "onboarding"
  | "creator"
  | "approvals"
  | "proposals"
  | "calls"
  | "account";

/** One link of the site navigation. */
export interface NavLink {
  readonly kind: NavKind;
  readonly href: string;
  /** The label id in the home catalogue. */
  readonly label: string;
}

/**
 * The role links of the site navigation: every page the caller's roles
 * may open without an id (Daniel, 2026-10-31: "please add all links to
 * routes in the top row"; `docs/design/01-navigation-home.md` "Top row"
 * and "Navigation per role group"). A page that needs an id, such as
 * the intake queue of one call, is listed on the home page instead.
 */
export function navLinksOf(r: MyRoles): readonly NavLink[] {
  const out: NavLink[] = [];
  const staff = r.roles.filter((b) => b.proposal === null);
  const holds = (role: RoleName): boolean => staff.some((b) => b.role === role);
  if (holds("committee_member")) {
    out.push({ kind: "assignments", href: WORK_PATHS.assignments, label: "nav.my_assignments" });
  }
  if (holds("irc_member")) {
    out.push({ kind: "irc-cases", href: WORK_PATHS.ircCases, label: "nav.my_cases" });
  }
  if (r.tenantAdmin) {
    out.push({ kind: "onboarding", href: WORK_PATHS.onboarding, label: "nav.onboarding" });
    out.push({ kind: "creator", href: WORK_PATHS.creatorNew, label: "nav.programme_setup" });
    out.push({ kind: "approvals", href: WORK_PATHS.approvals, label: "nav.approvals" });
  }
  return Object.freeze(out);
}

/**
 * The whole site navigation, in order: Home, the role links of
 * `navLinksOf`, the pages anyone signed in may open without an id (their
 * own applications and the open calls), and Account. `roles` is null
 * until the shell has read them.
 */
export function navOf(roles: MyRoles | null): readonly NavLink[] {
  return Object.freeze([
    { kind: "home", href: WORK_PATHS.home, label: "nav.home" },
    ...(roles === null ? [] : navLinksOf(roles)),
    { kind: "proposals", href: WORK_PATHS.proposals, label: "nav.my_applications" },
    { kind: "calls", href: WORK_PATHS.calls, label: "nav.open_calls" },
    { kind: "account", href: WORK_PATHS.account, label: "nav.account" },
  ] satisfies NavLink[]);
}

/** The order in which the role chip names roles: programme roles first. */
const CHIP_ORDER: readonly RoleName[] = [
  "programme_manager",
  "call_drafter",
  "fstp_coordinator",
  "committee_chair",
  "committee_member",
  "irc_member",
  "finance_approver",
  "payment_releaser",
  "contract_signatory",
  "auditor",
  "tenant_admin",
  "applicant",
  "applicant_team_member",
  "guardian",
];

/**
 * The roles the role chip names, each once, in chip order
 * (`docs/design/01-navigation-home.md` "Sidebar layout", slot 2). Empty
 * for a person with no role.
 */
export function chipRoles(r: MyRoles): readonly RoleName[] {
  const held = new Set<RoleName>(r.roles.map((b) => b.role));
  if (r.tenantAdmin) {
    held.add("tenant_admin");
  }
  return Object.freeze(CHIP_ORDER.filter((x) => held.has(x)));
}

// ---------------------------------------------------------------------------
// Pages a person without a session may read
// ---------------------------------------------------------------------------

/**
 * The `/app/` pages that a person without an account may read: the open
 * calls, one call, its Guide, and the invitation landing, which an
 * invitee reads before enrolling. Every other `/app/` page sends a person
 * without a session to the login page, which returns them after sign-in.
 */
const PUBLIC_PAGES: readonly RegExp[] = [
  /^\/app\/calls$/,
  /^\/app\/calls\/[^/]+$/,
  /^\/app\/calls\/[^/]+\/guide$/,
  /^\/app\/invitation$/,
];

/** Whether `path` is a page a person without an account may read. */
export function isPublicPage(path: string): boolean {
  return PUBLIC_PAGES.some((re) => re.test(path));
}
