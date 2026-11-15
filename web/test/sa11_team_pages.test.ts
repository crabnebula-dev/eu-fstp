// The team and member pages and the display name (SA-11, Daniel
// 2026-11-15 night). The replies decode strictly and admit no Receiving
// role, the per-role actions follow the reply's actions, the pages are
// gated and linked from home and navigation, and the pages render over
// the fake DOM and send the role operations.

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { nameBody } from "../src/auth/pages/account.js";
import { navRolesOf, siteLinks } from "../src/auth/sitenav.js";
import { TEAM_LABELS } from "../src/admin/team/messages.en.js";
import {
  TEAM_ROLES,
  decodeDisplayName,
  decodeMembers,
  decodeTeam,
  displayNameBody,
  roleActions,
  type RoleRow,
} from "../src/admin/team/model.js";
import { TEAM_PAGES } from "../src/admin/team/page.js";
import { OPERATIONS, PAGES, VALIDATORS } from "../src/gen/api.js";
import { navOf, readMyRoles, workOf } from "../src/home/model.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { appPatterns } from "../src/shell/routes.js";
import { assert, eq, test } from "./support/harness.js";
import { FakeElement, fakeDocument, freshDom } from "./support/fakedom.js";

const TEAM = {
  actions: ["grant", "end", "reinstate", "invite"],
  rows: [
    {
      account: "3",
      display_name: "Synthetic Programme Lead",
      email: "manager@example.invalid",
      binding: "11",
      invitation: null,
      role: "programme_manager",
      status: "active",
      start: "1794700800000000",
      end: null,
    },
    {
      account: "210",
      display_name: null,
      email: null,
      binding: "12",
      invitation: null,
      role: "committee_member",
      status: "suspended",
      rule: "I-06",
      start: "1794700800000000",
      end: "1826236800000000",
    },
    {
      account: null,
      display_name: null,
      email: "invitee@example.invalid",
      binding: null,
      invitation: "5",
      role: "auditor",
      status: "invited",
      start: "1794700800000000",
      end: null,
    },
    {
      account: "404",
      display_name: null,
      email: "auditor@example.invalid",
      binding: null,
      invitation: "6",
      role: "finance_approver",
      status: "accepted",
      start: "1794700800000000",
      end: null,
    },
  ],
};

const MEMBERS = {
  actions: ["grant", "end", "reinstate"],
  members: [
    {
      account: "3",
      display_name: "Synthetic Programme Lead",
      email: "manager@example.invalid",
      tenant_admin: false,
      roles: [
        {
          programme: "3",
          binding: "11",
          invitation: null,
          role: "programme_manager",
          status: "active",
          start: "1794700800000000",
          end: null,
        },
      ],
    },
    {
      account: "405",
      display_name: null,
      email: null,
      tenant_admin: true,
      roles: [
        { programme: null, binding: null, invitation: null, role: "financial_signatory", status: "active", start: null, end: null },
      ],
    },
  ],
};

/** SA-11, TH-26: both replies decode, the generated validators agree, and any other shape is refused. */
test("i17_sa11_team_and_member_replies_decode_strictly_with_no_receiving_role", () => {
  const team = decodeTeam(TEAM, "3");
  assert(team !== null, "the team reply decodes");
  eq(team?.rows.length, 4, "four rows");
  eq(team?.rows[1]?.rule, "I-06", "the rule of a suspension");
  eq(team?.rows[0]?.programme, "3", "a team row is of the page's programme");
  const members = decodeMembers(MEMBERS);
  assert(members !== null, "the member reply decodes");
  eq(members?.members[1]?.roles[0]?.programme, null, "a tenant-wide role");
  const vt = VALIDATORS["team.list"];
  const vm = VALIDATORS["admin.members"];
  assert(vt !== undefined && vt(TEAM), "the generated validator takes the team reply");
  assert(vm !== undefined && vm(MEMBERS), "the generated validator takes the member reply");
  const row = TEAM.rows[0];
  for (const bad of [
    null,
    { ...TEAM, extra: 1 },
    { ...TEAM, actions: ["delete"] },
    { ...TEAM, rows: [{ ...row, role: "applicant" }] },
    { ...TEAM, rows: [{ ...row, role: "guardian" }] },
    { ...TEAM, rows: [{ ...row, status: "voided" }] },
    { ...TEAM, rows: [{ ...row, name: "x" }] },
    { ...TEAM, rows: [{ ...row, account: 3 }] },
  ]) {
    eq(decodeTeam(bad, "3"), null, JSON.stringify(bad));
  }
  eq(decodeMembers({ ...MEMBERS, members: [{ ...MEMBERS.members[0], roles: [{ role: "applicant_team_member" }] }] }), null, "a Receiving role");
  assert(!TEAM_ROLES.some((r) => ["applicant", "applicant_team_member", "guardian"].includes(r)), "no Receiving role");
  eq(decodeDisplayName({ display_name: "Synthetic" }), "Synthetic", "a name");
  eq(decodeDisplayName({ display_name: null }), null, "no name");
  eq(decodeDisplayName({ display_name: 3 }), undefined, "another shape");
});

/** SA-11, SoD-09: grant on a verified invitation (or an accepted Operations one), end on a held binding, reinstate on a suspended one, and only what the reply allows. */
test("i78_sa11_role_actions_follow_the_reply_and_the_role_state", () => {
  const team = decodeTeam(TEAM, "3");
  assert(team !== null, "decodes");
  const rows = team?.rows ?? [];
  const all = team?.actions ?? [];
  const of = (r: RoleRow | undefined): string => (r === undefined ? "" : roleActions(r, all).join(","));
  eq(of(rows[0]), "end", "an active binding");
  eq(of(rows[1]), "reinstate,end", "a suspended binding");
  eq(of(rows[2]), "", "an invitation not accepted");
  eq(of(rows[3]), "grant", "an accepted Operations invitation");
  const manager = rows.map((r) => roleActions(r, ["invite"]).length);
  eq(manager, [0, 0, 0, 0], "the manager gets no per-role action");
  const tenantWide = decodeMembers(MEMBERS)?.members[1]?.roles[0];
  assert(tenantWide !== undefined && roleActions(tenantWide, all).length === 0, "no action on a tenant-wide role");
});

/** SA-11: a display name is plain text of at most 100 characters. A blank one clears it. The account page and the app agree. */
test("i86_sa11_display_name_body_is_plain_text_of_at_most_100_characters", () => {
  const cases: readonly [string, { display_name: string | null } | null][] = [
    ["  Synthetic Name ", { display_name: "Synthetic Name" }],
    ["", { display_name: null }],
    ["   ", { display_name: null }],
    ["é".repeat(100), { display_name: "é".repeat(100) }],
    ["a".repeat(101), null],
    ["<b>x</b>", null],
    ["a>b", null],
    ["two\nlines", null],
  ];
  for (const [text, want] of cases) {
    eq(displayNameBody(text), want, `app: ${text}`);
    eq(nameBody(text), want, `account page: ${text}`);
  }
});

/** SA-09, SA-11: both pages are in the gate's table and the client's routes, and the four operations are web reads and one POST. */
test("i86_sa11_team_and_member_pages_are_gated_and_routed", () => {
  for (const pattern of ["/app/programmes/{programme}/team", "/app/admin/members"]) {
    assert(PAGES.some((p) => p.pattern === pattern), `the gate lists ${pattern}`);
    assert(appPatterns().includes(pattern), `the shell routes ${pattern}`);
  }
  eq(TEAM_PAGES.map((p) => p.route.pattern), ["/app/programmes/{programme}/team", "/app/admin/members"], "two pages");
  const op = (n: string): { method: string; path: string } | undefined => OPERATIONS.find((o) => o.name === n);
  eq(op("team.list")?.method, "GET", "team.list");
  eq(op("team.list")?.path, "/programmes/{programme}/team", "team.list path");
  eq(op("admin.members")?.method, "GET", "admin.members");
  eq(op("me.display_name")?.method, "GET", "me.display_name");
  eq(op("me.set_display_name")?.method, "POST", "me.set_display_name");
  eq(op("me.set_display_name")?.path, "/me/display-name", "me.set_display_name path");
  eq(TEAM_LABELS["team.title"], "Team", "the plain name Team");
  eq(TEAM_LABELS["team.members_title"], "Members", "the plain name Members");
  eq(TEAM_LABELS["team.no_name"], "no name set", "no name set");
});

const ADMIN_ROLES = { tenant_admin: true, roles: [], calls: [], rounds: [], drafts: [], signatories: [] };
const PM_ROLES = {
  tenant_admin: false,
  roles: [
    { role: "programme_manager", programme: "12", calls: [] },
    { role: "programme_manager", programme: "3", calls: [] },
  ],
  calls: [],
  rounds: [],
  drafts: [],
  signatories: [],
};

/** SA-11, R-NF-03: the tenant admin's home links the member page and the team page of each programme, and its navigation the member page. The manager's home links its team pages. */
test("r_nf_03_sa11_home_and_navigation_link_the_team_and_member_pages", () => {
  const admin = readMyRoles(ADMIN_ROLES);
  const pm = readMyRoles(PM_ROLES);
  assert(admin !== null && pm !== null, "the roles read");
  if (admin === null || pm === null) return;
  const name = (c: string): string => c;
  const hrefs = (w: ReturnType<typeof workOf>): string[] => w.items.map((i) => i.href);
  const a = hrefs(workOf(admin, [], name, name, ["3", "12"]));
  for (const h of ["/app/admin/members", "/app/programmes/3/team", "/app/programmes/12/team"]) {
    assert(a.includes(h), `the admin's home links ${h}`);
  }
  const p = hrefs(workOf(pm, [], name, name));
  for (const h of ["/app/programmes/3/team", "/app/programmes/12/team"]) {
    assert(p.includes(h), `the manager's home links ${h}`);
  }
  assert(!p.includes("/app/admin/members"), "the manager is not linked to the member page");
  const nav = (r: ReturnType<typeof readMyRoles>): string[] => navOf(r).map((l) => `${l.kind} ${l.href}`);
  assert(nav(admin).includes("members /app/admin/members"), "the admin's navigation");
  // R-NF-03: the navigation links only pages without an id, so the
  // manager reaches the team page from home and from the people page.
  assert(!nav(pm).some((l) => l.includes("/team")), "no id-bearing navigation link");
  const auth = navRolesOf(PM_ROLES);
  assert(auth !== null, "the account page reads the roles");
  eq(
    siteLinks(auth).map((l) => `${l.kind} ${l.href}`),
    nav(pm),
    "the account page's navigation is the app's",
  );
});

// ---------------------------------------------------------------------------
// The pages over the fake DOM
// ---------------------------------------------------------------------------

const g = globalThis as unknown as Record<string, unknown>;

interface Sent {
  readonly path: string;
  readonly body: unknown;
}

function env(replies: Readonly<Record<string, unknown>>, sent: Sent[]): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, params, body, validate): Promise<ApiOutcome> {
      let path = op.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`{${k}}`, v);
      }
      sent.push({ path: `${op.method} ${path}`, body });
      const r = replies[`${op.method} ${path}`];
      if (r === undefined) {
        return { kind: "refused", code: "refused", rule: "actor" };
      }
      return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
    },
  };
  return { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
}

function prepare(): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement", "HTMLInputElement"]) {
    g[n] = FakeElement;
  }
}

function text(): string {
  return fakeDocument.body.textContent ?? "";
}

function byId(id: string): FakeElement {
  const el = fakeDocument.getElementById(id) as FakeElement | null;
  if (el === null) {
    throw new Error(`no #${id} in: ${text().slice(0, 400)}`);
  }
  return el;
}

const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

function page(name: string): (env: PageEnv, params: Readonly<Record<string, string>>) => Promise<void> {
  const p = TEAM_PAGES.find((x) => x.route.name === name);
  if (p === undefined) {
    throw new Error(`no page ${name}`);
  }
  return (e, params) => p.mount(e, params);
}

/** SA-11: the team page shows each row with its name or "no name set", its email, role, status and dates, and ends a role through `roles.end`. */
test("i78_sa11_team_page_lists_rows_and_ends_a_role", async () => {
  prepare();
  const sent: Sent[] = [];
  const e = env({ "GET /programmes/3/team": TEAM, "POST /programmes/3/roles/11/end": { accepted: true } }, sent);
  await page("admin.team")(e, { programme: "3" });
  await tick();
  const shown = text();
  for (const s of [
    "Team",
    "Synthetic Programme Lead",
    "manager@example.invalid",
    "no name set",
    "Programme manager",
    "Suspended (I-06)",
    "Invited",
    "from 2026-11-15",
    "Invite a person",
  ]) {
    assert(shown.includes(s), `${s} is not shown: ${shown.slice(0, 900)}`);
  }
  byId("reinstate-binding-12");
  byId("grant-invitation-6");
  byId("end-binding-11").click();
  await tick();
  assert(
    sent.some((s) => s.path === "POST /programmes/3/roles/11/end"),
    `no end was sent: ${JSON.stringify(sent.map((s) => s.path))}`,
  );
});

/** SA-11: the manager's team page offers no grant, end or reinstate, only the invitation. */
test("i78_sa11_team_page_for_the_manager_offers_the_invitation_only", async () => {
  prepare();
  const sent: Sent[] = [];
  await page("admin.team")(env({ "GET /programmes/3/team": { ...TEAM, actions: ["invite"] } }, sent), { programme: "3" });
  await tick();
  for (const id of ["end-binding-11", "reinstate-binding-12", "grant-invitation-6"]) {
    eq(fakeDocument.getElementById(id), null, `${id} is offered`);
  }
  byId("team-invite-form");
});

/** SA-11: the member page lists each account with its name, email and roles, links each programme's team page, and offers the per-role actions. */
test("i86_sa11_member_page_lists_accounts_and_their_roles", async () => {
  prepare();
  const sent: Sent[] = [];
  await page("admin.members")(env({ "GET /admin/members": MEMBERS }, sent), {});
  await tick();
  const shown = text();
  for (const s of [
    "Members",
    "Synthetic Programme Lead",
    "no name set",
    "Programme manager in programme 3",
    "Financial signatory for the whole organisation",
    "Tenant admin",
    "Team of programme 3",
  ]) {
    assert(shown.includes(s), `${s} is not shown: ${shown.slice(0, 900)}`);
  }
  byId("end-binding-11");
});

/** SA-09: a refused read shows no rows and no control. */
test("i86_sa11_refused_team_read_shows_no_rows", async () => {
  prepare();
  await page("admin.team")(env({}, []), { programme: "3" });
  await tick();
  assert(!text().includes("manager@example.invalid"), text().slice(0, 300));
  eq(fakeDocument.getElementById("team-rows"), null, "no table");
});
