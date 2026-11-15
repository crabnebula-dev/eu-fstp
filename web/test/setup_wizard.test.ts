// The programme set-up wizard and the set-up progress page
// (`docs/design/11-programme-setup-wizard.md`; Daniel's answers of
// 2026-11-15 to its section 14).
//
// The wizard adds no rule. Its stages group the 11 creator steps, its
// checks are projections of the team the invitation list shows, and the
// progress page reads only the existing replies. Every reply and address
// here is synthetic.

import { CREATOR_STEPS, readDraft, type Report, type ReportResult } from "../src/creator/model.js";
import { readMyRoles, workOf } from "../src/home/model.js";
import { grantOffered, readInvitations, type InvitationRow } from "../src/people/model.js";
import {
  MILESTONES,
  ROLE_GROUPS,
  STAGES,
  datesProblem,
  endDate,
  endMicros,
  groupOf,
  milestones,
  refusedLine,
  sodLines,
  stageStates,
  startDate,
  startMicros,
  statusRow,
  teamStatus,
  type ProgressFacts,
} from "../src/setup/model.js";
import { SETUP_ROUTES } from "../src/setup/routes.js";
import {
  approverNotice,
  approverOverrideSlot,
  milestoneList,
  milestoneStrip,
  sodItems,
  stageBar,
  statusTable,
  summaryPanel,
  teamTables,
} from "../src/setup/view.js";
import { createRouter } from "../src/core/router.js";
import { asFake, freshDom, sinkUses, type FakeElement } from "./support/fakedom.js";
import { assert, eq, forAll, test } from "./support/harness.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function rep(results: readonly ReportResult[]): Report {
  return { revision: "r1", results };
}

function failure(field: string): ReportResult {
  return { check: "FieldUnset", severity: "failure", acknowledged: false, key: `k:${field}`, field, step: null, values: [] };
}

function row(email: string, role: string, state: InvitationRow["state"] = "invited", id = "1"): InvitationRow {
  return { id, email, role: role as InvitationRow["role"], state, sod: "unchecked", rule: null, approval: null, start: "1794009600000000", end: null };
}

function byAttr(root: FakeElement, name: string, value?: string): FakeElement[] {
  return [root, ...root.descendants()].filter((e) => {
    const v = e.getAttribute(name);
    return v !== null && (value === undefined || v === value);
  });
}

const ROLES = ROLE_GROUPS.flatMap((g) => g.roles);
const EMAILS = ["a.one@horizon-bridges.example", "b.two@horizon-bridges.example", "c.three@lakeside.example"];

// ---------------------------------------------------------------------------
// Stages
// ---------------------------------------------------------------------------

/**
 * R-PG-01, design doc 11 section 5: the seven stages group the 11 creator
 * steps in their spec order. The creator steps stay the source of truth.
 */
test("r_pg_01_setup_stages_group_the_11_creator_steps_in_order", () => {
  eq(
    STAGES.map((s) => s.id),
    ["start", "programme", "applicants", "evaluation", "team", "communications", "review"],
    "the seven stages",
  );
  eq(
    STAGES.flatMap((s) => s.steps),
    CREATOR_STEPS.map((s) => s.id),
    "every creator step once, in order",
  );
});

/**
 * R-PG-01, design doc 11 section 5: each stage validates before the next
 * opens. Without a draft only the start is open. A failure on a step
 * keeps its stage open and locks every later stage. The review is done
 * only once activation is requested (I-66).
 */
test("r_pg_01_setup_stage_opens_only_after_the_stages_before_it_validate", () => {
  const none = stageStates(null, false, false);
  eq(none.map((s) => s.condition), ["open", "locked", "locked", "locked", "locked", "locked", "locked"], "no draft yet");
  const clean = stageStates(rep([]), true, false);
  eq(clean.map((s) => s.condition), ["done", "done", "done", "done", "done", "done", "open"], "a clean report opens the review");
  const requested = stageStates(rep([]), true, true);
  eq(requested.every((s) => s.condition === "done"), true, "a request completes the review");
  const failing = stageStates(rep([failure("eligibility.minors")]), true, false);
  eq(failing.map((s) => s.condition), ["done", "done", "open", "locked", "locked", "locked", "locked"], "a failure in stage 3");
  eq(failing[2]?.failures, 1, "the failure is counted on its stage");
  const unread = stageStates(null, true, false);
  eq(unread.map((s) => s.condition), ["done", "open", "locked", "locked", "locked", "locked", "locked"], "no report read");
});

/** R-PG-01: the stage routes take a programme id and a stage, never `start` or `progress` as a stage. */
test("r_pg_01_setup_routes_check_their_parameters", () => {
  const r = createRouter(SETUP_ROUTES);
  eq(r.match("/app/setup/new")?.name, "setup.start", "the start");
  eq(r.match("/app/programmes/7/setup/team")?.params["stage"], "team", "a stage");
  eq(r.match("/app/programmes/7/setup/progress")?.name, "setup.progress", "the progress page");
  eq(r.match("/app/programmes/7/setup/start"), null, "the start is not a stage of a draft");
  eq(r.match("/app/programmes/7/setup/people"), null, "a creator step is not a stage");
  eq(r.match("/app/programmes/7%2F8/setup/team"), null, "a bad programme id");
});

// ---------------------------------------------------------------------------
// Dates on invitations (design doc 11 Q3)
// ---------------------------------------------------------------------------

/**
 * I-23, O-47, design doc 11 Q3: a role date becomes the instant the
 * invitation carries and reads back as the same date. A start is the UTC
 * midnight of its day. An end is the midnight after its day, so the role
 * holds through it.
 */
test("i23_setup_role_dates_round_trip_through_the_invitation_instants", () => {
  eq(startMicros("2026-11-03"), "1793664000000000", "the start instant");
  eq(endMicros("2026-11-03"), "1793750400000000", "the end instant is the next midnight");
  forAll(
    (r) => {
      const y = 1970 + r.between(0, 130);
      const m = r.between(1, 12);
      const d = r.between(1, 28);
      return `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
    },
    (date) => {
      eq(startDate(startMicros(date)), date, `the start of ${date}`);
      eq(endDate(endMicros(date)), date, `the end of ${date}`);
    },
  );
  for (const bad of ["", "2026-02-30", "2026-13-01", "26-11-03", "2026-11-3", "1969-12-31"]) {
    eq(startMicros(bad), null, `no start from ${JSON.stringify(bad)}`);
  }
  eq(startDate("01"), null, "a non-canonical instant reads as no date");
});

/** I-23, design doc 11 Q3: a start is needed, and an end may not lie before it. The server checks again. */
test("i23_setup_role_dates_need_a_start_and_an_end_not_before_it", () => {
  eq(datesProblem("", ""), "start", "no start");
  eq(datesProblem("2026-12-01", ""), null, "an open end");
  eq(datesProblem("2026-12-01", "2026-12-01"), null, "a one-day role");
  eq(datesProblem("2026-12-01", "2026-11-30"), "order", "an end before the start");
  eq(datesProblem("2026-12-01", "2026-02-30"), "end", "an end that is no date");
});

/** I-23, design doc 11 Q3: the invitation list's role dates are read, and a malformed one refuses the reply. */
test("i23_setup_invitation_list_reads_the_role_dates", () => {
  const base = { id: "5", email: "x@horizon-bridges.example", role: "auditor", state: "invited", sod: "unchecked" };
  const rows = readInvitations({ invitations: [{ ...base, start: "1794009600000000", end: null }] });
  eq(rows?.[0]?.start, "1794009600000000", "the start");
  eq(rows?.[0]?.end, null, "an open end");
  eq(readInvitations({ invitations: [base] })?.[0]?.start, null, "an older reply without dates");
  eq(readInvitations({ invitations: [{ ...base, start: "01" }] }), null, "a non-canonical start refuses");
  eq(readInvitations({ invitations: [{ ...base, start: 5 }] }), null, "a number refuses");
});

// ---------------------------------------------------------------------------
// The Team stage
// ---------------------------------------------------------------------------

/**
 * R-CF-03, SoD-01, SoD-02, design doc 11 section 6.4: a refusal from roles
 * in this programme names the rule and the role that blocks it, never an
 * account. Every line names one of the seven rules, and a choice with a
 * refused line cannot be added.
 */
test("r_cf_03_setup_live_checks_name_the_rule_and_role_never_an_account", () => {
  forAll(
    (r) => ({
      role: r.pick(ROLES),
      email: r.pick(EMAILS),
      team: Array.from({ length: r.between(0, 6) }, (_, i) => row(r.pick(EMAILS), r.pick(ROLES), "invited", String(i + 1))),
    }),
    ({ role, email, team }) => {
      const lines = sodLines(role, email, team);
      eq(lines.map((l) => l.rule), ["SoD-01", "SoD-02", "SoD-03", "SoD-04", "SoD-05", "SoD-07", "SoD-09"], "the seven rules");
      for (const l of lines) {
        assert(l.blocking === null || ROLES.includes(l.blocking), `a blocking value is a role: ${String(l.blocking)}`);
        assert((l.blocking !== null) === (l.badge === "refused"), "only a refusal names a role");
      }
      freshDom();
      const text = sodItems(lines).map((e) => asFake(e).textContent).join(" ");
      for (const e of EMAILS) assert(!text.includes(e), `no address in the checks: ${e}`);
    },
  );
  const irc = sodLines("irc_member", EMAILS[0] ?? "", [row(EMAILS[0] ?? "", "fstp_coordinator")]);
  eq(refusedLine(irc)?.rule, "SoD-02", "an IRC member who coordinates here is refused under SoD-02");
  eq(refusedLine(irc)?.blocking, "fstp_coordinator", "the blocking role");
  const cross = sodLines("committee_member", EMAILS[1] ?? "", [row(EMAILS[1] ?? "", "call_drafter")]);
  eq(refusedLine(cross)?.rule, "SoD-01", "a drafter on the committee is refused under SoD-01");
  eq(refusedLine(sodLines("committee_member", EMAILS[2] ?? "", [row(EMAILS[1] ?? "", "call_drafter")])), null, "another person passes");
  eq(refusedLine(sodLines("committee_member", "  A.ONE@horizon-bridges.example ", [row(EMAILS[0] ?? "", "irc_member")]))?.rule, "SoD-02", "addresses compare without case");
});

/**
 * SoD-04, SoD-09 NOTE, design doc 11 section 6.4: an Operations role is
 * outside SoD-01, SoD-02, SoD-05 and SoD-09. One person as finance
 * approver and payment releaser, with nobody else in either, is refused.
 */
test("r_cf_03_setup_operations_checks_and_the_two_person_payment_rule", () => {
  const lines = sodLines("auditor", EMAILS[0] ?? "", []);
  const badge = (rule: string): string | undefined => lines.find((l) => l.rule === rule)?.badge;
  eq([badge("SoD-01"), badge("SoD-02"), badge("SoD-05"), badge("SoD-09")], ["not_affected", "not_affected", "not_affected", "not_affected"], "outside the groups");
  eq(badge("SoD-03"), "passed", "no Receiving role on a draft");
  const alone = sodLines("payment_releaser", EMAILS[0] ?? "", [row(EMAILS[0] ?? "", "finance_approver")]);
  eq(refusedLine(alone)?.rule, "SoD-04", "one person approving and releasing");
  const two = sodLines("payment_releaser", EMAILS[0] ?? "", [row(EMAILS[0] ?? "", "finance_approver"), row(EMAILS[1] ?? "", "finance_approver", "invited", "2")]);
  eq(refusedLine(two), null, "another approver keeps two people per payment");
  const judging = sodLines("committee_chair", EMAILS[0] ?? "", []);
  eq(judging.find((l) => l.rule === "SoD-09")?.badge, "waiting", "identity waits for the invitee, never refused here");
});

/**
 * Design doc 11 Q2 (Daniel, 2026-11-15): Operations roles are planned
 * rows until a tenant admin grants them after activation. They need no
 * identity check, so the grant is offered once the person accepted, and
 * never while the programme is a draft. Drafting and Judging keep SoD-09.
 */
test("r_pg_01_setup_operations_rows_are_planned_and_granted_after_activation", () => {
  for (const role of ["finance_approver", "payment_releaser", "contract_signatory", "auditor"]) {
    eq(groupOf(role), "operations", `${role} is an Operations role`);
    eq(teamStatus(row("x@horizon-bridges.example", role, "accepted")), "planned", `${role} accepted is planned`);
    eq(teamStatus(row("x@horizon-bridges.example", role, "granted")), "granted", `${role} granted`);
    eq(statusRow(row("x@horizon-bridges.example", role, "accepted"), true).verified, "not_needed", "no identity check");
    eq(grantOffered("active", role, "accepted"), true, `${role} is granted once accepted after activation`);
    eq(grantOffered("draft", role, "verified"), false, `${role} is never granted on a draft`);
    eq(grantOffered("active", role, "invited"), false, `${role} needs the acceptance that binds the account`);
  }
  eq(grantOffered("active", "committee_member", "accepted"), false, "SoD-09: Judging waits for verification");
  eq(grantOffered("draft", "programme_manager", "verified"), true, "D1: the programme manager on a draft");
  eq(teamStatus(row("x@horizon-bridges.example", "call_drafter", "accepted")), "accepted", "Drafting shows its state");
});

// ---------------------------------------------------------------------------
// Progress
// ---------------------------------------------------------------------------

function facts(over: Partial<ProgressFacts>): ProgressFacts {
  return { drafted: true, clean: false, team: [], requested: false, active: false, calls: null, ...over };
}

/**
 * R-PC-03, I-66, I-67, design doc 11 section 8: the nine milestones are
 * done, then one current, then upcoming. A request waits for the
 * approval of a tenant admin outside the builders.
 */
test("r_pc_03_setup_progress_has_one_current_milestone_after_the_done_ones", () => {
  forAll(
    (r) =>
      facts({
        clean: r.bool(),
        requested: r.bool(),
        active: r.bool(),
        team: r.bool() ? [] : [row("x@horizon-bridges.example", r.pick(ROLES), r.pick(["invited", "accepted", "verified", "granted"] as const))],
        calls: r.bool() ? null : Array.from({ length: r.between(0, 3) }, () => r.pick(["DRAFT", "APPROVED", "PUBLISHED"] as const)),
      }),
    (f) => {
      const ms = milestones(f);
      eq(ms.map((m) => m.id), [...MILESTONES], "nine in order");
      const conds = ms.map((m) => m.condition).join(",");
      assert(/^(done,)*(current(,upcoming)*)?$|^(done,)*done$/.test(conds), `done, then one current, then upcoming: ${conds}`);
    },
  );
  const requested = milestones(facts({ clean: true, requested: true, team: [row("x@horizon-bridges.example", "call_drafter")] }));
  eq(requested.find((m) => m.condition === "current")?.id, "approved", "the approval is current after the request");
  const active = milestones(facts({ active: true, team: [row("x@horizon-bridges.example", "call_drafter", "granted")], calls: ["APPROVED"] }));
  eq(active.find((m) => m.condition === "current")?.id, "call_published", "an approved call waits for publication");
});

// ---------------------------------------------------------------------------
// The views
// ---------------------------------------------------------------------------

/**
 * R-NF-03, design doc 11 section 11: the stage bar is a nav named
 * "Set-up stages" with one current item. Done stages link back. Upcoming
 * stages are not links. Each item says its state in words.
 */
test("r_nf_03_setup_stage_bar_marks_the_current_stage_and_links_only_done_ones", () => {
  freshDom();
  const states = stageStates(rep([failure("eligibility.minors")]), true, false);
  const nav = asFake(stageBar("7", states, "applicants"));
  eq(nav.localName, "nav", "a nav landmark");
  eq(nav.getAttribute("aria-label"), "Set-up stages", "its name");
  eq(byAttr(nav, "aria-current", "step").map((e) => e.getAttribute("data-stage")), ["applicants"], "one current stage");
  const links = nav.descendants().filter((e) => e.localName === "a").map((e) => e.getAttribute("href"));
  eq(links, ["/app/programmes/7/setup/programme"], "only the done stage of the draft links back");
  const words = byAttr(nav, "data-stage").map((e) => e.textContent);
  eq(words[0], "✓1. Start, complete", "a done stage says so");
  eq(words[2], "33. Applicants, current stage", "the current stage says so");
  eq(words[3], "○4. Evaluation and money, not started", "an upcoming stage says so");
  eq(sinkUses, [], "no HTML sink reached");
});

/** R-NF-03, design doc 11 sections 2 and 11: the summary panel is an aside named "Your set-up so far". */
test("r_nf_03_setup_summary_panel_is_a_named_aside_with_change_links", () => {
  freshDom();
  const states = stageStates(rep([]), true, false);
  const team = [row("s.okafor@horizon-bridges.example", "programme_manager", "granted")];
  const aside = asFake(summaryPanel(states, { programme: "7", draft: null, team }, "review"));
  eq(aside.localName, "aside", "an aside landmark");
  eq(aside.getAttribute("aria-labelledby"), "setup-summary-title", "named by its heading");
  assert(aside.textContent.includes("Your set-up so far"), "the heading");
  assert(aside.textContent.includes("6 of 7 stages complete."), "the count");
  assert(aside.textContent.includes("s.okafor@horizon-bridges.example"), "the programme manager");
  const changes = aside.descendants().filter((e) => e.localName === "a").map((e) => e.getAttribute("href"));
  eq(changes.length, 5, "a Change link for each done stage of the draft");
});

/** I-67, design doc 11 Q4: the approver notice stays, and the override form of lane m4/i67-override has its named place. */
test("i67_setup_keeps_the_approver_notice_and_a_place_for_the_override", () => {
  freshDom();
  const notice = asFake(approverNotice());
  assert(notice.textContent.includes("I-67"), "the notice names I-67");
  assert(notice.textContent.includes("Nobody chooses that person"), "no approver choice");
  const slot = asFake(approverOverrideSlot());
  eq(slot.getAttribute("id"), "setup-approver-override", "the named place");
  eq(slot.getAttribute("data-slot"), "i67-override", "for the override lane");
  eq(slot.children.length, 0, "this lane builds no part of the override");
});

/** I-67, design doc 11 section 15: the notice says how many tenant admins remain outside the builders, as a count that names nobody. */
test("i67_setup_approver_notice_counts_the_admins_outside_the_builders", () => {
  freshDom();
  const none = asFake(approverNotice(0));
  assert(none.textContent.includes("No tenant admin"), "none left: says so");
  eq(byAttr(none, "data-approvers").map((e) => e.getAttribute("data-approvers")), ["0"], "the count in an attribute");
  assert(asFake(approverNotice(1)).textContent.includes("One tenant admin"), "one left");
  assert(asFake(approverNotice(3)).textContent.includes("3 tenant admins"), "three left");
  eq(byAttr(asFake(approverNotice()), "data-approvers").length, 0, "no count without a reply");
  eq(byAttr(asFake(approverNotice(null)), "data-approvers").length, 0, "no count when the server sends none");
});

/** R-PG-01, design doc 11 section 15: a draft reply may carry the approver count, and a bad count is refused. */
test("r_pg_01_read_draft_reads_the_approver_count", () => {
  const base = { spec: {}, revision: "1.2", status: "draft", pending_narratives: {} };
  eq(readDraft(base)?.approvers, null, "absent: null");
  eq(readDraft({ ...base, approvers: 2 })?.approvers, 2, "a count");
  eq(readDraft({ ...base, approvers: -1 }), null, "negative: refused");
  eq(readDraft({ ...base, approvers: "2" }), null, "a string: refused");
});

/** SoD-09, R-CF-03, design doc 11 sections 6.5 and 8: the team tables and the status table group people and say each state in words. */
test("r_cf_03_setup_team_tables_and_status_table_group_by_role_group", () => {
  freshDom();
  const team = [
    row("s.okafor@horizon-bridges.example", "programme_manager", "granted", "1"),
    { ...row("h.haddad@horizon-bridges.example", "fstp_coordinator", "accepted", "2"), sod: "fail" as const, rule: "SoD-09" },
    row("k.wu@horizon-bridges.example", "finance_approver", "accepted", "3"),
  ];
  const tables = asFake(teamTables(team));
  eq(byAttr(tables, "data-group").map((e) => e.getAttribute("data-group")), ["drafting", "judging", "operations"], "three tables");
  eq(byAttr(tables, "data-status").map((e) => e.getAttribute("data-status")), ["granted", "accepted", "planned"], "the statuses");
  assert(tables.textContent.includes("Refused under SoD-09"), "a vault refusal names the rule only");
  assert(tables.textContent.includes("From 7 Nov 2026, no end date"), "the role dates as a person reads them");
  const status = asFake(statusTable(team, false));
  assert(status.textContent.includes("Not needed"), "Operations need no identity check");
  const strip = asFake(milestoneStrip(milestones(facts({ clean: true, requested: true, team }))));
  eq(byAttr(strip, "aria-current", "step").length, 1, "one current milestone");
  const list = asFake(milestoneList(milestones(facts({ clean: true, requested: true, team }))));
  eq(byAttr(list, "data-milestone").length, 9, "nine milestones");
  assert(list.textContent.includes("A tenant admin outside the builders"), "who acts on the approval");
  eq(sinkUses, [], "no HTML sink reached");
});

/**
 * ADR-021, design doc 11 section 3: the tenant admin home links the
 * wizard, and the programme manager home links the wizard and the
 * progress of each draft. Before activation the home lists onboarding
 * alone (`home/page.ts`), so the wizard is not shown then.
 */
test("adr021_setup_wizard_is_linked_from_the_admin_and_manager_homes", () => {
  const roles = readMyRoles({
    tenant_admin: true,
    roles: [{ role: "programme_manager", programme: "7", calls: [] }],
    calls: [],
    rounds: [],
    drafts: ["7"],
    signatories: [],
  });
  assert(roles !== null, "the roles read");
  const w = workOf(roles, [], (c) => c, (p) => p);
  const hrefs = w.items.map((i) => `${i.group} ${i.kind} ${i.href}`);
  assert(hrefs.includes("tenant_admin setup /app/setup/new"), `the admin link: ${hrefs.join("; ")}`);
  assert(hrefs.includes("programme setup /app/programmes/7/setup/programme"), "the wizard of the draft");
  assert(hrefs.includes("programme setup-progress /app/programmes/7/setup/progress"), "the progress of the draft");
});
