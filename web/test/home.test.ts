// The home page model, the site navigation links and the return path
// after sign-in (I-86, R-NF-03, ADR-014; M4 design sections 2.2 and 3.9).
//
// Interim, pending Daniel (design section 15.0, 2026-10-31): the home
// page and the landing after sign-in are the reading built for Daniel's
// report that a signed-in person found no way to their work. Every value
// here is synthetic.

import { HOME_PATH, LOGIN_PATH, MAX_RETURN, isReturnPath, landingAfterSignIn, loginPathFor } from "../src/auth/next.js";
import { SCHEMAS, VALIDATORS } from "../src/gen/api.js";
import { AUTH_EN } from "../src/auth/messages.en.js";
import { navRolesOf, siteLinks } from "../src/auth/sitenav.js";
import { HOME_LABELS } from "../src/home/messages.en.js";
import {
  type MyRoles,
  ROLE_NAMES,
  type RoleName,
  SIGNATORY_NAMES,
  chipRoles,
  isPublicPage,
  navLinksOf,
  navOf,
  readMyRoles,
  workOf,
} from "../src/home/model.js";
import { assert, eq, forAll, show, test } from "./support/harness.js";
import { type Rng } from "./support/rng.js";

/** A `me.roles` reply with every member, as the cell sends it. */
const FULL = {
  tenant_admin: true,
  roles: [
    { role: "fstp_coordinator", programme: "1", calls: ["1", "2"] },
    { role: "committee_member", programme: "1", calls: ["1"] },
    { role: "applicant", programme: "1", proposal: "1001", calls: ["1"] },
  ],
  calls: [{ call: "1", title: "Synthetic open call 2026" }, { call: "2" }],
  rounds: [{ round: "7", call: "1" }],
  drafts: [],
  signatories: [],
};

const EMPTY = { tenant_admin: false, roles: [], calls: [], rounds: [], drafts: [], signatories: [] };

function roles(v: unknown): MyRoles {
  const r = readMyRoles(v);
  assert(r !== null, `readMyRoles refused ${show(v)}`);
  return r;
}

const name = (c: string): string => `Call ${c}`;
const untitled = (p: string): string => `Proposal ${p}`;

/** I-86, TH-26: the reader takes the generated `me.roles` shape, and both refuse the same extra member. */
test("i86_home_reader_takes_the_generated_me_roles_shape", () => {
  const check = VALIDATORS["me.roles"];
  assert(check !== undefined && SCHEMAS["me.roles"] !== undefined, "gen/api.ts holds me.roles");
  for (const v of [FULL, EMPTY]) {
    assert(check(v), `the generated validator accepts ${show(v)}`);
    assert(readMyRoles(v) !== null, `the reader accepts ${show(v)}`);
  }
  const extra: unknown[] = [
    { ...EMPTY, email: "synthetic@e2e.invalid" },
    { ...EMPTY, roles: [{ role: "applicant", programme: "1", calls: [], account: "9" }] },
    { ...EMPTY, roles: [{ role: "owner", programme: "1", calls: [] }] },
    { ...EMPTY, calls: [{ call: "1", title: "T", name: "Synthetic Person" }] },
    { ...EMPTY, rounds: [{ round: "1", call: "1", ballot: "x" }] },
    { tenant_admin: false, roles: [], rounds: [], drafts: [] },
    { tenant_admin: false, roles: [], calls: [], rounds: [] },
    { ...EMPTY, drafts: [1] },
    { tenant_admin: false, roles: [], calls: [], rounds: [], drafts: [] },
    { ...EMPTY, signatories: ["contract_signatory"] },
    { ...EMPTY, signatories: "financial_signatory" },
    { ...EMPTY, roles: [{ role: "applicant", programme: 1, calls: [] }] },
  ];
  for (const v of extra) {
    eq(check(v), false, `the generated validator refuses ${show(v)}`);
    eq(readMyRoles(v), null, `the reader refuses ${show(v)}`);
  }
  eq([...ROLE_NAMES], [...ROLE_NAMES].filter((n, i, all) => all.indexOf(n) === i), "role names are distinct");
});

/**
 * R-NF-03, design section 2.2 J4 to J8: each role leads to the page of
 * its journey, a call is named by its published title, and the open
 * calls come last.
 */
test("r_nf_03_home_links_each_role_to_its_pages", () => {
  const w = workOf(roles(FULL), [{ proposal: "1001", role: "lead", title: "Synthetic sensor kit" }], name, untitled);
  const byHref = new Map(w.items.map((i) => [i.href, i]));
  const want: readonly (readonly [string, string])[] = [
    ["/app/proposals/1001", "proposal"],
    ["/app/proposals", "proposals"],
    ["/app/admin/onboarding/summary", "onboarding"],
    ["/app/creator/new", "creator"],
    ["/app/admin/approvals", "approvals"],
    ["/app/me/assignments", "assignments"],
    ["/app/calls/1/intake", "intake"],
    ["/app/calls/1/board", "board"],
    ["/app/calls/1/notifiable-conflicts", "notifiable"],
    ["/app/calls/2/intake", "intake"],
    ["/app/calls/1/ranking", "ranking"],
    ["/app/cut-off-rounds/7", "cut-off-round"],
    ["/app/calls", "open-calls"],
  ];
  for (const [href, kind] of want) {
    eq(byHref.get(href)?.kind, kind, href);
  }
  eq(w.items.length, new Set(w.items.map((i) => i.href)).size, "each link once");
  eq(w.items[w.items.length - 1]?.kind, "open-calls", "the open calls come last");
  eq(byHref.get("/app/calls/1/intake")?.text.args["call"], "Synthetic open call 2026", "the call title");
  eq(byHref.get("/app/calls/2/intake")?.text.args["call"], "Call 2", "a call without a title");
  eq(byHref.get("/app/proposals/1001")?.text.args["title"], "Synthetic sensor kit", "the proposal title");
  eq(w.noRole, false, "a role holder has a role");
  eq(byHref.has("/app/me/irc-cases"), false, "no IRC link without the IRC role");
});

/** R-NF-03, design section 2.2 J4: a person with no role is told so and offered the open calls only. */
test("r_nf_03_home_without_a_role_offers_the_open_calls", () => {
  const w = workOf(roles(EMPTY), [], name, untitled);
  eq(w.noRole, true, "no role");
  eq(
    w.items.map((i) => i.kind),
    ["open-calls"],
    "only the open calls",
  );
  const lead = workOf(roles(EMPTY), [{ proposal: "1004", role: "lead", title: "" }], name, untitled);
  eq(lead.noRole, false, "an own proposal whose binding ended still counts");
  eq(lead.items[0]?.text.args["title"], "Proposal 1004", "a proposal without a title is named by its id");
});

/** R-NF-03, design section 2.2 J4 and J8: a guardian reaches the guardian page, an IRC member the cases. */
test("r_nf_03_home_guardian_and_irc_member_reach_their_pages", () => {
  const r = roles({
    tenant_admin: false,
    roles: [
      { role: "guardian", programme: "1", proposal: "1004", calls: ["1"] },
      { role: "irc_member", programme: "1", calls: ["1"] },
      { role: "auditor", programme: "1", calls: ["1"] },
    ],
    calls: [{ call: "1" }],
    rounds: [{ round: "8", call: "1" }],
    drafts: [],
    signatories: [],
  });
  const w = workOf(r, null, name, untitled);
  const kinds = w.items.map((i) => `${i.kind} ${i.href}`);
  assert(kinds.includes("guardian /app/proposals/1004/guardian"), show(kinds));
  assert(kinds.includes("irc-cases /app/me/irc-cases"), show(kinds));
  assert(!kinds.some((k) => k.startsWith("cut-off-round")), "an open round is the committee's only");
  assert(!kinds.some((k) => k.startsWith("proposals ")), "a guardian has no proposal list link");
  eq(w.other, [], "the auditor reaches the funder reports through the operations page");
  assert(w.items.some((i) => i.kind === "operations"), "the operations queues are offered to the auditor");
  eq(
    navLinksOf(r).map((l) => l.kind),
    ["irc-cases", "operations"],
    "the site navigation links the IRC cases and the auditor operations queue",
  );
});

const ROLE_GEN: readonly RoleName[] = ROLE_NAMES;

function randomRoles(r: Rng): unknown {
  const n = r.below(5);
  const list: unknown[] = [];
  for (let i = 0; i < n; i += 1) {
    const role = r.pick(ROLE_GEN);
    const calls = Array.from({ length: r.below(3) }, () => String(1 + r.below(12)));
    list.push(
      r.bool()
        ? { role, programme: String(1 + r.below(3)), proposal: String(1000 + r.below(9)), calls }
        : { role, programme: String(1 + r.below(3)), calls },
    );
  }
  return {
    tenant_admin: r.bool(),
    roles: list,
    calls: [],
    rounds: [{ round: String(r.below(9)), call: "1" }],
    drafts: r.bool() ? [String(1 + r.below(3))] : [],
    signatories: r.bool() ? [r.pick(SIGNATORY_NAMES)] : [],
  };
}

/**
 * R-NF-03, ADR-014: for any roles, every home and navigation link is a
 * same-origin `/app/` path that a return path may name, each link
 * appears once, and the open calls are always offered.
 */
test("r_nf_03_home_links_are_same_origin_app_paths", () => {
  forAll(randomRoles, (v) => {
    const r = roles(v);
    const w = workOf(r, null, name, untitled);
    const hrefs = [...w.items.map((i) => i.href), ...navLinksOf(r).map((l) => l.href)];
    for (const href of hrefs) {
      assert(isReturnPath(href), `${href} is a same-origin /app/ path`);
    }
    eq(w.items.length, new Set(w.items.map((i) => i.href)).size, "each link once");
    assert(w.items.some((i) => i.kind === "open-calls"), "the open calls are offered");
  });
});

/** Whether `href` names an id: a path segment of digits. */
function namesAnId(href: string): boolean {
  return href.split("/").some((s) => /^[0-9]+$/.test(s));
}

/**
 * R-NF-03 (Daniel, 2026-10-31: "please add all links to routes in the
 * top row"; `docs/design/01-navigation-home.md` "Top row"): for any
 * roles, the navigation starts with Home and ends with Account, links
 * only pages without an id, and links every page without an id that the
 * home page offers. Each page that needs an id is on the home page.
 */
test("r_nf_03_nav_links_every_page_without_an_id_and_home_lists_the_rest", () => {
  forAll(randomRoles, (v) => {
    const r = roles(v);
    const nav = navOf(r);
    eq(nav[0]?.kind, "home", "Home comes first");
    eq(nav[nav.length - 1]?.kind, "account", "Account comes last");
    eq(nav[nav.length - 1]?.href, "/auth/account", "Account opens the account page");
    const hrefs = new Set(nav.map((l) => l.href));
    eq(hrefs.size, nav.length, "each navigation link once");
    for (const l of nav) {
      assert(!namesAnId(l.href), `the navigation link ${l.href} needs no id`);
    }
    const w = workOf(r, null, name, untitled);
    for (const i of w.items) {
      if (!namesAnId(i.href)) {
        assert(hrefs.has(i.href), `the home link ${i.href} needs no id, so the navigation holds it`);
      }
    }
    for (const want of ["/app/", "/app/proposals", "/app/calls"]) {
      assert(hrefs.has(want), `every signed-in person has ${want}`);
    }
  });
  const before = navOf(null).map((l) => l.kind);
  eq(before, ["home", "proposals", "grants", "calls", "account"], "before the roles are read");
});

/**
 * R-NF-03, review finding U1 (design section 2.2 J1): a programme
 * manager's creator and people links appear only for a programme that
 * holds a creator draft, since both pages read the draft. The call board
 * of a programme without one stays linked.
 */
test("r_nf_03_home_programme_manager_links_creator_only_with_a_draft", () => {
  const pm = (drafts: string[]): MyRoles =>
    roles({
      tenant_admin: false,
      roles: [{ role: "programme_manager", programme: "1", calls: ["1"] }, { role: "programme_manager", programme: "2", calls: [] }],
      calls: [{ call: "1", title: "Synthetic open call 2026" }],
      rounds: [],
      drafts,
      signatories: [],
    });
  const none = workOf(pm([]), null, name, untitled).items.map((i) => i.href);
  assert(!none.some((h) => h.includes("/creator") || h.endsWith("/people")), show(none));
  assert(none.includes("/app/calls/1/board"), "the call board stays linked");
  const two = workOf(pm(["2"]), null, name, untitled).items.map((i) => i.href);
  assert(two.includes("/app/programmes/2/creator/review") && two.includes("/app/programmes/2/people"), show(two));
  assert(!two.includes("/app/programmes/1/creator/review"), "no creator link for the programme without a draft");
});

/** R-NF-03 (design "Sidebar layout", slot 2): the role chip names each role once, programme roles first. */
test("r_nf_03_role_chip_names_each_role_once", () => {
  eq(chipRoles(roles(FULL)), ["fstp_coordinator", "committee_member", "tenant_admin", "applicant"], "chip roles");
  eq(chipRoles(roles(EMPTY)), [], "no role");
});

/**
 * NOTE 5, I-86, R-NF-03 (design section 15.0, "Roles lane questions",
 * 2026-11-06): a holder of a signatory role and nothing else has a role.
 * The home page names each held signatory role, and the role chip shows
 * it. A caller without one sees none.
 */
test("r_nf_03_note5_home_names_the_callers_signatory_roles", () => {
  const both = roles({ ...EMPTY, signatories: ["financial_signatory", "legal_signatory"] });
  const w = workOf(both, [], name, untitled);
  eq(w.noRole, false, "a signatory holder has a role");
  eq(w.signatories, ["financial_signatory", "legal_signatory"], "both roles named");
  eq(chipRoles(both), ["financial_signatory", "legal_signatory"], "the chip names both");
  const legal = workOf(roles({ ...EMPTY, signatories: ["legal_signatory"] }), [], name, untitled);
  eq(legal.signatories, ["legal_signatory"], "only the held role");
  eq(workOf(roles(FULL), [], name, untitled).signatories, [], "no signatory role for others");
  for (const s of SIGNATORY_NAMES) {
    assert((ROLE_NAMES as readonly string[]).includes(s), `${s} is a role name`);
    assert(typeof HOME_LABELS[`role.${s}`] === "string", `${s} has a role label`);
  }
  for (const k of ["home.signatory.title", "home.signatory.item", "home.signatory.later"]) {
    assert(typeof HOME_LABELS[k] === "string" && HOME_LABELS[k] !== "", `${k} is in the catalogue`);
  }
});

/**
 * R-NF-03 (Daniel, 2026-10-31: Home and Account on every page): the
 * account page, which the auth bundle serves on its own, offers the same
 * links in the same order as the sidebar of the `/app/` pages, with the
 * same labels but Home, for any roles and before they are read.
 */
test("r_nf_03_account_nav_matches_the_app_nav", () => {
  const messages: Readonly<Record<string, string>> = AUTH_EN.messages;
  const same = (app: ReturnType<typeof navOf>, auth: ReturnType<typeof siteLinks>): void => {
    eq(
      auth.map((l) => `${l.kind} ${l.href}`),
      app.map((l) => `${l.kind} ${l.href}`),
      "the account page links as the sidebar does",
    );
    for (const l of app) {
      if (l.kind !== "home") {
        eq(messages[`account.nav.${l.kind}`], HOME_LABELS[l.label], `the label of ${l.kind}`);
      }
    }
  };
  same(navOf(null), siteLinks(null));
  forAll(randomRoles, (v) => {
    const auth = navRolesOf(v);
    assert(auth !== null, `the account page reads ${show(v)}`);
    same(navOf(roles(v)), siteLinks(auth));
  });
});

/** ADR-014: the return path after sign-in is never an open redirect. */
test("adr014_return_path_refuses_every_other_origin_and_shape", () => {
  const refused = [
    "",
    "/",
    "/app",
    "/APP/calls",
    "//evil.example/app/",
    "/app//evil.example",
    "https://evil.example/app/",
    "/app/../auth/account",
    "/app/./calls",
    "/app/%2e%2e/auth",
    "/app/%2E%2E/auth",
    "/app/%2fevil",
    "/app/%5cevil",
    "/app/\\evil",
    "/app/calls?x=1",
    "/app/calls#x",
    "/app/ calls",
    "/app/\tcalls",
    "/app/café",
    "/app/%zz",
    "/app/%",
    `/app/${"a".repeat(MAX_RETURN)}`,
  ];
  for (const p of refused) {
    eq(isReturnPath(p), false, show(p));
    eq(loginPathFor(p), LOGIN_PATH, `the login page of ${show(p)}`);
  }
  for (const p of ["/app/", "/app/me/assignments", "/app/calls/1/ranking", "/app/x%20y"]) {
    eq(isReturnPath(p), true, show(p));
  }
  eq(loginPathFor("/app/"), LOGIN_PATH, "the home page needs no return path");
  eq(loginPathFor("/app/me/assignments"), "/auth/login?next=%2Fapp%2Fme%2Fassignments", "a deep link");
  eq(landingAfterSignIn("?next=%2Fapp%2Fme%2Fassignments"), "/app/me/assignments", "it returns there");
  for (const q of ["", "?next=https%3A%2F%2Fevil.example%2F", "?next=%2F%2Fevil.example", "?next=%2Fauth%2Faccount", "?x=1"]) {
    eq(landingAfterSignIn(q), HOME_PATH, `the landing of ${show(q)}`);
  }
  assert(isPublicPage("/app/calls") && isPublicPage("/app/calls/1") && !isPublicPage("/app/calls/1/intake"), "public pages");
});

const PATHISH: readonly string[] = ["/", "//", "app", "/app/", ".", "..", "%2e", "%2F", "%5c", "%41", "\\", "?", "#", "a", "1", ":", "@", " ", "é"];

/**
 * ADR-014: for any string, an accepted return path stays on the cell
 * origin, keeps its path when the browser resolves it, and lies below
 * `/app/`; the landing is always such a path.
 */
test("adr014_return_path_stays_on_the_cell_origin", () => {
  const base = "https://a.fstp.test";
  forAll(
    (r) => (r.bool() ? "/app/" : "") + r.stringFrom(PATHISH, 8),
    (p) => {
      if (isReturnPath(p)) {
        const u = new URL(p, base);
        eq(u.origin, base, `${show(p)} stays on the origin`);
        eq(u.pathname, p, `${show(p)} keeps its path`);
        assert(p.startsWith("/app/"), `${show(p)} is below /app/`);
      }
      const landing = landingAfterSignIn(`?next=${encodeURIComponent(p)}`);
      assert(landing === HOME_PATH || landing === p, `${show(p)} lands on ${show(landing)}`);
      assert(isReturnPath(landing), `the landing ${show(landing)} is a return path`);
    },
  );
});
