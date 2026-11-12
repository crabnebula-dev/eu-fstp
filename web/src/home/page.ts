// The home page `/app/`, "Your work" (R-NF-03, R-NF-04, I-86; M4 design
// sections 2.2 J0 to J8 and 3.9; `docs/design/01-navigation-home.md`
// "Your work home per role", approved by Daniel on 2026-11-01; the
// prototypes `home-voyager`, `home-reviewer`, `home-committee`,
// `home-coordinator`, `home-irc` and `home-admin`).
//
// Every sign-in lands here. The page reads the caller's own roles
// (`me.roles`) and own proposals (`proposal.list_own`), and lists one
// link per piece of work (`model.ts` `workOf`). It has one `h1`, "Your
// work", or "Administration" for a person who holds the tenant admin
// role only, then one card per role group, each with its `h2`:
//
// - an applicant's card per own proposal, headed by its title, with its
//   state as a chip beside the formal state name (I-96);
// - a reviewer's "N proposals need your score" (`me.assignments`);
// - a committee member's "N proposals to rank" (`committee.ranking`);
// - a coordinator's "N proposals need a knock-out decision"
//   (`intake.queue`) and "Queue health", the counts per state of each
//   call board, with no title and no applicant data (O-57);
// - an IRC member's "N nominated proposals for independent review"
//   (`me.irc_cases`), with no status strip (O-58);
// - a tenant admin's "Organisation settings", "First-time setup" and
//   "Members and roles" (`tenant.list_admins`), each linking the pages
//   this release has: the onboarding steps, the programme set-up and the
//   approvals;
// - the open calls, which anyone may read, in an "Other places" aside.
//
// The first card is the primary card. Interim, pending the lead: the
// recent activity of the design needs the activity log filtered by the
// visibility function (I-93), which this release does not have, so it
// is left out rather than shown empty. A count whose read fails is
// left out too, and the card keeps its links.
//
// The page contract of the e2e specs (`e2e/navigation/support.ts`):
//
// - `main` holds `#home`, and `#home` holds `#home-work`: one `li` per
//   piece of work, each with one link `a[data-work="<kind>"]` whose text
//   names the work, such as the call or the proposal title.
// - A person with no role sees `#home-no-role`, which says so. The list
//   then holds the open calls only.
// - `#home-other` names each role this release has no page for.
// - `#home-signatory` names each signatory role the caller holds, one
//   `li[data-signatory="<role>"]` each (NOTE 5; design section 15.0,
//   2026-11-06).
//
// Every element is built with `h`, and every text goes in as a text node.

import { call } from "../applicant/client.js";
import { frame, stateLabel } from "../applicant/ui.js";
import { type ProposalInfo, decodeOwnProposals } from "../applicant/wire.js";
import { type Child, h } from "../core/dom.js";
import type { Label } from "../core/i18n.js";
import { isIntakeQueue, isBoard } from "../coordinator/models.js";
import { isRankingView } from "../committee/models.js";
import { isIrcCase } from "../irc/models.js";
import { isScoreSheet } from "../reviewer/models.js";
import {
  type AssignmentSummary,
  type Guard,
  browserEnv,
  isAssignmentSummary,
  isBool,
  isId,
  isText,
  list,
  readOp,
  record,
} from "../reviewer/kit.js";
import { type MyRoles, type OwnProposal, WORK_PATHS, type Work, type WorkItem, workOf } from "./model.js";
import { mailboxCount } from "../mailbox/pages.js";
import { decodeQueue, type QueueRow } from "../grant/models.js";
import { homeLabel } from "./nav.js";
import { myRoles } from "./session.js";
import { activityNav, journeyNav } from "../journey/links.js";

/** The path of one onboarding step (`onboarding/routes.ts`). */
function ONBOARDING_STEP(step: "organisation" | "administrators"): string {
  return `/app/admin/onboarding/${step}`;
}

/** One link of the home page, as its list item. */
function workLink(i: WorkItem, primary: boolean): HTMLElement {
  const attrs: Record<string, string> = { href: i.href, "data-work": i.kind };
  if (primary) {
    attrs["class"] = "btn btn--primary";
  }
  return h("li", { "data-work-item": i.kind }, [h("a", attrs, [homeLabel(i.text.id, i.text.args)])]);
}

/** One card of the home page: its heading, what it says and its links. */
interface Card {
  readonly id: string;
  readonly title: Label | string;
  readonly body: readonly Child[];
  readonly items: readonly WorkItem[];
}

/** A card element. The primary card carries the kicker and a primary button. */
function cardElement(c: Card, kicker: Label | null): HTMLElement {
  const heading = `${c.id}-heading`;
  const primary = kicker !== null;
  return h("section", { id: c.id, class: primary ? "card card--primary" : "card", "aria-labelledby": heading }, [
    ...(kicker === null ? [] : [h("p", { class: "card-kicker" }, [kicker])]),
    h("h2", { id: heading }, [c.title]),
    ...c.body,
    ...(c.items.length === 0
      ? []
      : [h("ul", { class: "fstp-list" }, c.items.map((i, n) => workLink(i, primary && n === 0)))]),
  ]);
}

/** A count heading: the `one` form for 1, else the `other` form. */
function counted(key: string, n: number): Label {
  return homeLabel(n === 1 ? `${key}_one` : `${key}_other`, { count: String(n) });
}

/** The chip of a proposal state with its formal name beside it (I-96, R-NF-03). */
function stateChip(p: ProposalInfo): HTMLElement {
  return h("p", { class: "primary-meta", "data-state": p.state }, [
    h("span", { class: "badge badge--info" }, [stateLabel(p.state)]),
    h("span", { class: "state-name" }, [homeLabel("home.formal_state", { state: p.state })]),
    h("span", { class: "pid" }, [homeLabel("home.proposal", { id: p.proposal })]),
  ]);
}

/** What the summaries of the home page read. A count is null when its read failed. */
interface Counts {
  readonly toScore: number | null;
  readonly toRank: number | null;
  readonly knockOut: number | null;
  readonly queue: ReadonlyMap<string, number> | null;
  readonly irc: number | null;
  readonly admins: number | null;
  /** The payment requests waiting on the caller's own line review (R-PR-08). */
  readonly toReview: number | null;
}

const isAdmins: Guard<{ readonly admins: readonly { readonly account: string; readonly handle: string; readonly verified: boolean }[] }> =
  record({ admins: list(record({ account: isId, handle: isText, verified: isBool })) });

/** The calls of the work items of `kind`, from their paths. */
function callsOf(items: readonly WorkItem[], kind: string): string[] {
  return items.filter((i) => i.kind === kind).map((i) => i.href.split("/")[3] ?? "").filter((c) => c !== "");
}

/** The sum of `n` over `xs`, or null when any read failed. */
async function sum<T>(xs: readonly T[], n: (x: T) => Promise<number | null>): Promise<number | null> {
  const all = await Promise.all(xs.map(n));
  let total = 0;
  for (const x of all) {
    if (x === null) {
      return null;
    }
    total += x;
  }
  return total;
}

/**
 * The reviewer assignments of `rows` that still need the caller's score,
 * or null when that cannot be read (R-CF-02, R-EV-02). A ranked proposal
 * takes no score, and the reviewer page reads it through the ranking of
 * its call, never its sheet (`reviewer/pages.ts`). So the ranking of each
 * call is read once, and a ranked proposal counts as scored.
 */
async function toScoreOf(env: ReturnType<typeof browserEnv>, rows: readonly AssignmentSummary[]): Promise<number | null> {
  const calls = [...new Set(rows.filter((x) => x.active && !x.stage2).map((x) => x.call))];
  const ranked = new Set<string>();
  for (const c of calls) {
    const v = await readOp(env, "committee.ranking", { call: c }, isRankingView);
    if (v.ok) {
      for (const row of v.data) {
        ranked.add(row.proposal);
      }
    } else if (v.problem.kind !== "refused") {
      return null;
    }
  }
  return sum(rows, (x) => needsScore(env, x, ranked));
}

/**
 * 1 when the reviewer assignment `x` still needs the caller's score, 0
 * when it does not, or null when that cannot be read. The list holds
 * unreleased assignments only. One awaiting the declaration needs the
 * declaration and then the score. An active one needs a score while its
 * sheet holds no current one. A ranked proposal, or a sheet the route
 * refuses, is closed to scoring: the sheet opens in STAGE1 and STAGE2 only.
 */
async function needsScore(
  env: ReturnType<typeof browserEnv>,
  x: AssignmentSummary,
  ranked: ReadonlySet<string>,
): Promise<number | null> {
  if (x.awaiting_declaration) {
    return 1;
  }
  if (!x.active || (!x.stage2 && ranked.has(x.proposal))) {
    return 0;
  }
  const sheet = await readOp(env, "review.score_sheet", { assignment: x.assignment }, isScoreSheet);
  if (sheet.ok) {
    return sheet.data.current === null ? 1 : 0;
  }
  return sheet.problem.kind === "refused" ? 0 : null;
}

/**
 * 1 when the IRC case `x` is a nomination in independent review, 0 when
 * it is not, or null when that cannot be read (O-58). One awaiting the
 * declaration counts. An active one counts while its case reads, which it
 * does in IRC_REVIEW only. The count names no proposal state.
 */
async function inIrcReview(env: ReturnType<typeof browserEnv>, x: AssignmentSummary): Promise<number | null> {
  if (x.awaiting_declaration) {
    return 1;
  }
  if (!x.active) {
    return 0;
  }
  const c = await readOp(env, "irc.case", { irc_assignment: x.assignment }, isIrcCase);
  if (c.ok) {
    return 1;
  }
  return c.problem.kind === "refused" ? 0 : null;
}

let reviewCount: Promise<number | null> | null = null;

/**
 * The payment requests waiting on the caller's own line review, read once per page load from
 * `payment.queue`, or null when it cannot be read (R-PR-08). The cell lists a request for
 * review only to an active assigned reviewer of its grant.
 */
export function paymentReviewCount(): Promise<number | null> {
  reviewCount ??= readOp(browserEnv(document.body), "payment.queue", {}, (v): v is readonly QueueRow[] => decodeQueue(v) !== null)
    .then((q) => (q.ok ? (decodeQueue(q.data) ?? []).filter((r) => r.task === "review").length : null))
    .catch(() => null);
  return reviewCount;
}

/** Reads the counts the caller's cards show. Each read is made only for a card the caller has. */
async function readCounts(w: Work, r: MyRoles): Promise<Counts> {
  const env = browserEnv(document.body);
  const has = (kind: string): boolean => w.items.some((i) => i.kind === kind);
  const toScore = has("assignments")
    ? readOp(env, "me.assignments", {}, list(isAssignmentSummary)).then((a) =>
        a.ok ? toScoreOf(env, a.data.filter((x) => x.kind === "reviewer")) : null,
      )
    : Promise.resolve(null);
  const toRank = sum(callsOf(w.items, "ranking"), async (c) => {
    const v = await readOp(env, "committee.ranking", { call: c }, isRankingView);
    return v.ok ? v.data.length : null;
  });
  const knockOut = sum(callsOf(w.items, "intake"), async (c) => {
    const q = await readOp(env, "intake.queue", { call: c }, isIntakeQueue);
    return q.ok ? q.data.proposals.filter((p) => p.state === "SUBMITTED").length : null;
  });
  const queue = has("intake")
    ? Promise.all(
        callsOf(w.items, "intake").map((c) => readOp(env, "call.board", { call: c }, isBoard)),
      ).then((boards) => {
        const out = new Map<string, number>();
        for (const b of boards) {
          if (!b.ok) {
            return null;
          }
          for (const row of b.data) {
            out.set(row.state, (out.get(row.state) ?? 0) + 1);
          }
        }
        return out;
      })
    : Promise.resolve(null);
  const irc = has("irc-cases")
    ? readOp(env, "me.irc_cases", {}, list(isAssignmentSummary)).then((a) =>
        a.ok ? sum(a.data.filter((x) => x.kind === "irc"), (x) => inIrcReview(env, x)) : null,
      )
    : Promise.resolve(null);
  const admins = r.tenantAdmin
    ? readOp(env, "tenant.list_admins", {}, isAdmins).then((a) => (a.ok ? a.data.admins.length : null))
    : Promise.resolve(null);
  const toReview = has("assignments") ? paymentReviewCount() : Promise.resolve(null);
  return {
    toScore: await toScore,
    toReview: await toReview,
    toRank: has("ranking") ? await toRank : null,
    knockOut: has("intake") ? await knockOut : null,
    queue: await queue,
    irc: await irc,
    admins: await admins,
  };
}

/** The queue health table: the count of proposals per state, with no title or applicant data (O-57). */
function queueHealth(queue: ReadonlyMap<string, number>): HTMLElement {
  const rows = [...queue.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return h("section", { id: "home-queue", "aria-labelledby": "home-queue-heading" }, [
    h("h2", { id: "home-queue-heading" }, [homeLabel("home.queue.title")]),
    h("p", { class: "fstp-hint" }, [homeLabel("home.queue.intro")]),
    rows.length === 0
      ? h("p", {}, [homeLabel("home.queue.empty")])
      : h("table", {}, [
          h("caption", {}, [homeLabel("home.queue.caption")]),
          h("thead", {}, [
            h("tr", {}, [
              h("th", { scope: "col" }, [homeLabel("home.queue.state")]),
              h("th", { scope: "col" }, [homeLabel("home.queue.count")]),
            ]),
          ]),
          h(
            "tbody",
            {},
            rows.map(([state, n]) =>
              h("tr", {}, [h("td", { class: "state-name" }, [state]), h("td", {}, [String(n)])]),
            ),
          ),
        ]),
  ]);
}

/** The cards of the caller's work, in the order of the design: own proposals first. */
function cards(w: Work, own: readonly ProposalInfo[], c: Counts): { readonly main: Card[]; readonly after: HTMLElement[] } {
  const out: Card[] = [];
  const after: HTMLElement[] = [];
  const of = (pred: (i: WorkItem) => boolean): WorkItem[] => w.items.filter(pred);

  // J4: one card per own proposal, headed by its title.
  for (const i of of((x) => x.kind === "proposal")) {
    const id = i.href.split("/")[3] ?? "";
    const p = own.find((x) => x.proposal === id);
    out.push({
      id: `home-proposal-${id}`,
      title: p !== undefined && p.title.trim() !== "" ? p.title : homeLabel("home.proposal", { id }),
      body: p === undefined ? [journeyNav(id)] : [stateChip(p), journeyNav(id)],
      items: [i, ...of((x) => x.kind === "grant" && x.href === `/app/grants/${id}`)],
    });
  }
  const proposals = of((x) => x.kind === "proposals" || (x.kind === "grants" && x.group === "applicant"));
  if (proposals.length > 0) {
    out.push({ id: "home-applications", title: homeLabel("home.group.applicant"), body: [], items: proposals });
  }
  const guardian = of((x) => x.group === "guardian");
  if (guardian.length > 0) {
    // O-60: the guardian reaches the activity log, which holds their own
    // consent steps, by clicking from the home page.
    out.push({
      id: "home-guardian",
      title: homeLabel("home.group.guardian"),
      body: guardian.map((i) => activityNav(i.href.split("/")[3] ?? "")),
      items: guardian,
    });
  }

  // J5: the coordinator.
  const coordinator = of((x) => x.group === "coordinator");
  if (coordinator.length > 0) {
    out.push({
      id: "home-coordinator",
      title: c.knockOut === null ? homeLabel("home.group.coordinator") : counted("home.knock_out", c.knockOut),
      body: [h("p", {}, [homeLabel("home.knock_out.intro")])],
      items: coordinator,
    });
    if (c.queue !== null) {
      after.push(queueHealth(c.queue));
    }
  }

  // R-PR-08 (lane m5/polish-access): an assigned reviewer with payment lines to decide gets
  // a card first, linking to Operations, which lists each request to review.
  if (c.toReview !== null && c.toReview > 0) {
    out.push({
      id: "home-payment-review",
      title: counted("home.to_review_payments", c.toReview),
      body: [h("p", {}, [homeLabel("home.to_review_payments.intro")])],
      items: [{ kind: "operations", href: WORK_PATHS.operations, text: { id: "home.work.payment_review", args: {} }, group: "committee" }],
    });
  }

  // J6: the reviewer's assignments.
  const assignments = of((x) => x.kind === "assignments" || (x.kind === "grants" && x.group === "committee"));
  if (assignments.length > 0) {
    out.push({
      id: "home-reviewer",
      title: c.toScore === null ? homeLabel("home.group.reviewer") : counted("home.to_score", c.toScore),
      body: [h("p", {}, [homeLabel("home.to_score.intro")])],
      items: assignments,
    });
  }

  // J7: the committee's rankings and open rounds.
  const committee = of((x) => x.kind === "ranking" || x.kind === "cut-off-round");
  if (committee.length > 0) {
    out.push({
      id: "home-committee",
      title: c.toRank === null ? homeLabel("home.group.committee") : counted("home.to_rank", c.toRank),
      body: [h("p", {}, [homeLabel("home.to_rank.intro")])],
      items: committee,
    });
  }

  // J8: the IRC, with no status strip (O-58).
  const irc = of((x) => x.group === "irc");
  if (irc.length > 0) {
    out.push({
      id: "home-irc",
      title: c.irc === null ? homeLabel("home.group.irc") : counted("home.irc", c.irc),
      body: [h("p", {}, [homeLabel("home.irc.intro")])],
      items: irc,
    });
  }

  // J0, J1, J2: the tenant admin.
  const onboarding = of((x) => x.kind === "onboarding");
  if (onboarding.length > 0) {
    out.push({
      id: "home-org",
      title: homeLabel("home.admin.org"),
      body: [
        h("p", {}, [homeLabel("home.admin.org.intro")]),
        h("p", {}, [h("a", { href: ONBOARDING_STEP("organisation") }, [homeLabel("home.work.org")])]),
      ],
      items: [],
    });
    out.push({
      id: "home-setup",
      title: homeLabel("home.admin.setup"),
      body: [h("p", {}, [homeLabel("home.admin.setup.intro")])],
      items: onboarding,
    });
    out.push({
      id: "home-members",
      title: homeLabel("home.admin.members"),
      body: [
        h("p", {}, [
          c.admins === null
            ? homeLabel("home.admin.members.intro")
            : counted("home.admin.members.count", c.admins),
        ]),
        h("p", {}, [h("a", { href: ONBOARDING_STEP("administrators") }, [homeLabel("home.work.admins")])]),
      ],
      items: [],
    });
  }
  const setup = of((x) => x.group === "tenant_admin" && x.kind !== "onboarding");
  if (setup.length > 0) {
    out.push({ id: "home-programmes", title: homeLabel("home.admin.programmes"), body: [], items: setup });
  }

  // M5: the Operations queues.
  const operations = of((x) => x.group === "operations");
  if (operations.length > 0) {
    out.push({
      id: "home-operations",
      title: homeLabel("home.group.operations"),
      body: [h("p", {}, [homeLabel("home.operations.intro")])],
      items: operations,
    });
  }

  // J1, J3: the programme staff.
  const programme = of((x) => x.group === "programme");
  if (programme.length > 0) {
    out.push({ id: "home-programme", title: homeLabel("home.group.programme"), body: [], items: programme });
  }
  return { main: out, after };
}

/** The roles this release has no page for, named without a link. */
function otherRoles(w: Work): HTMLElement[] {
  if (w.other.length === 0) {
    return [];
  }
  return [
    h("section", { id: "home-other", class: "card", "aria-labelledby": "home-other-heading" }, [
      h("h2", { id: "home-other-heading" }, [homeLabel("home.other.title")]),
      h(
        "ul",
        { class: "fstp-list" },
        w.other.map((o) =>
          h("li", {}, [
            homeLabel("home.other.item", { role: homeLabel(`role.${o.role}`), programme: o.programme }),
          ]),
        ),
      ),
    ]),
  ];
}

/**
 * The tenant-wide signatory roles of the caller (NOTE 5). What they
 * approve has no page until M5, so each role is named without a link.
 */
function signatoryRoles(w: Work): HTMLElement[] {
  if (w.signatories.length === 0) {
    return [];
  }
  return [
    h("section", { id: "home-signatory", class: "card", "aria-labelledby": "home-signatory-heading" }, [
      h("h2", { id: "home-signatory-heading" }, [homeLabel("home.signatory.title")]),
      h(
        "ul",
        { class: "fstp-list" },
        w.signatories.map((role) =>
          h("li", { "data-signatory": role }, [homeLabel("home.signatory.item", { role: homeLabel(`role.${role}`) })]),
        ),
      ),
      h("p", { class: "text-sm" }, [homeLabel("home.signatory.later")]),
    ]),
  ];
}

/** Whether the caller holds the tenant admin role and nothing else. */
function adminOnly(r: MyRoles): boolean {
  return r.tenantAdmin && r.roles.length === 0;
}

/** Mounts the home page. */
export function mountHome(): void {
  const f = frame(homeLabel("home.title"));
  const loading = h("p", { "aria-busy": "true" }, [homeLabel("home.loading")]);
  const home = h("section", { id: "home", "aria-labelledby": "home-title" }, [loading]);
  f.heading.id = "home-title";
  f.main.append(home);
  const failed = (): void => {
    f.alert.textContent = homeLabel("home.failed");
    f.alert.hidden = false;
    home.replaceChildren();
  };
  (async () => {
    const a = await myRoles();
    if (a.kind === "signed_out") {
      // The shell opens the login page (`session.ts`).
      home.replaceChildren(h("p", { role: "status" }, [homeLabel("home.signed_out")]));
      return;
    }
    if (a.kind !== "roles") {
      failed();
      return;
    }
    if (adminOnly(a.roles)) {
      const title = homeLabel("home.admin.title");
      f.heading.replaceChildren(title);
      document.title = homeLabel("home.document_title", { page: title });
    }
    const listed = await call("proposal.list_own", {}, undefined, decodeOwnProposals);
    const infos: readonly ProposalInfo[] = listed.ok ? listed.value : [];
    const own: readonly OwnProposal[] | null = listed.ok
      ? listed.value.map((p) => ({ proposal: p.proposal, role: p.role, title: p.title }))
      : null;
    const w = workOf(
      a.roles,
      own,
      (c) => homeLabel("home.call", { id: c }),
      (p) => homeLabel("home.proposal", { id: p }),
    );
    const counts = await readCounts(w, a.roles);
    const { main, after } = cards(w, infos, counts);
    const everyone = w.items.filter((i) => i.group === "everyone");
    const parts: HTMLElement[] = [];
    if (w.noRole) {
      parts.push(h("p", { id: "home-no-role" }, [homeLabel("home.no_role")]));
    } else {
      parts.push(h("p", { class: "muted" }, [homeLabel(adminOnly(a.roles) ? "home.admin.intro" : "home.intro")]));
    }
    // Lane m6/mailbox: the way to the work waiting for the caller.
    const open = await mailboxCount();
    if (open !== null) {
      parts.push(
        h("p", { id: "home-mailbox", class: "callout" }, [
          h("a", { href: WORK_PATHS.mailbox, "data-mailbox-link": "", "data-open": String(open) }, [
            open === 0 ? homeLabel("home.mailbox_none") : homeLabel("home.mailbox", { count: String(open) }),
          ]),
        ]),
      );
    }
    const work = h("div", { id: "home-work", class: "layout-side" }, [
      h("div", { class: "home-cards" }, [
        ...main.map((c, n) => cardElement(c, n === 0 ? homeLabel("home.primary.kicker") : null)),
        ...after,
      ]),
      h("aside", { "aria-label": homeLabel("home.other_places") }, [
        cardElement({ id: "home-calls", title: homeLabel("home.group.everyone"), body: [h("p", { class: "text-sm" }, [homeLabel("home.calls.intro")])], items: everyone }, null),
      ]),
    ]);
    parts.push(work, ...signatoryRoles(w), ...otherRoles(w));
    home.replaceChildren(...parts);
  })().catch(failed);
}
