// The Planning Studio, "Programme set-up" in the plain pack (lane studio;
// `SPEC/12-journey-ui.md` section 8.2; `docs/design/05-programme-staff-studio.md`).
//
// The studios only group the 11 creator steps. Every rule the pages show
// comes from a server read: the creator's validation report, the draft,
// the import proposals, the impact read, `me.roles` and `calls.get`.
// Every reply here is synthetic.

import { CREATOR_STEPS, type Report, type ReportResult, type ProposalRow } from "../src/creator/model.js";
import { readMyRoles, type MyRoles } from "../src/home/model.js";
import {
  STUDIOS,
  awaitingConfirmation,
  mayApproveCalls,
  programmeCalls,
  readCallState,
  readImpact,
  returnsCallToDraft,
  stepStates,
} from "../src/studio/model.js";
import {
  STUDIO_PATHS,
  activationPanel,
  afterApprovalNote,
  callsPanel,
  impactPanel,
  importsPanel,
  nextControl,
  studioNav,
} from "../src/studio/view.js";
import { FakeElement, asFake, freshDom, sinkUses } from "./support/fakedom.js";
import { assert, eq, forAll, show, test } from "./support/harness.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A report row about `field`, or about no field when `field` is null. */
function row(severity: "failure" | "warning", field: string | null, check = "FieldUnset", acknowledged = false): ReportResult {
  return { check, severity, acknowledged, key: `${check}:${field ?? "-"}`, field, step: null, values: [] };
}

function rep(results: readonly ReportResult[]): Report {
  return { revision: "r1", results };
}

/** One field key of each of steps 1 to 10, from the creator catalogue. */
const FIELD_OF: Readonly<Record<string, string>> = {
  funder: "funder.action_number",
  identity: "identity.name",
  eligibility: "eligibility.persons_supported",
  funding: "funding.p55_activity_types",
  evaluation: "evaluation.p02_threshold",
  money: "money.p05_recipient_cap",
  contract: "contract.flow_down",
  support: "support.p61_complaint_window",
  people: "people.p12_cooling_off",
  comms: "comms.contact",
};

function roles(v: unknown): MyRoles {
  const r = readMyRoles(v);
  assert(r !== null, `readMyRoles refused ${show(v)}`);
  return r;
}

function byAttr(root: unknown, name: string, value?: string): FakeElement[] {
  return asFake(root)
    .descendants()
    .filter((e) => e.hasAttribute(name) && (value === undefined || e.getAttribute(name) === value));
}

function links(root: unknown): FakeElement[] {
  return asFake(root).descendants().filter((e) => e.localName === "a");
}

// ---------------------------------------------------------------------------
// R-PG-01: the grouping of section 8.2
// ---------------------------------------------------------------------------

/**
 * R-PG-01, `SPEC/12-journey-ui.md` section 8.2: the five studios group
 * the 11 creator steps in their order, each step exactly once, with the
 * plain heading first and the studio name as the secondary line.
 */
test("r_pg_01_studio_groups_match_section_8_2", () => {
  eq(
    STUDIOS.map((s) => [s.id, [...s.steps]]),
    [
      ["territory", ["funder", "identity"]],
      ["border", ["eligibility", "funding"]],
      ["instruments", ["evaluation", "money", "contract"]],
      ["crew", ["support", "people", "comms"]],
      ["seal", ["review"]],
    ],
    "the studios and their steps",
  );
  eq(
    STUDIOS.flatMap((s) => s.steps),
    CREATOR_STEPS.map((s) => s.id),
    "the creator steps stay the source of truth, in order",
  );
  freshDom();
  const nav = asFake(studioNav("7", stepStates(rep([])), "money"));
  eq(nav.localName, "nav", "a nav landmark");
  eq(nav.getAttribute("aria-label"), "Set-up steps", "named as the design names it");
  const headings = nav.descendants().filter((e) => e.localName === "h2").map((e) => e.textContent);
  eq(
    headings,
    [
      "Funder and identity",
      "Eligibility and scope",
      "Evaluation, money and contract",
      "Support, people and communications",
      "Review and approval",
    ],
    "the plain headings lead",
  );
  const secondary = byAttr(nav, "class", "voyage-label").map((e) => e.textContent);
  eq(
    secondary,
    [
      "Studio: Surveying the territory",
      "Studio: Border rules",
      "Studio: Instruments",
      "Studio: Support and crew",
      "Studio: Charter seal",
    ],
    "the studio names as the secondary line",
  );
  eq(
    byAttr(nav, "data-step").map((e) => e.getAttribute("data-step")),
    CREATOR_STEPS.map((s) => s.id),
    "one li[data-step] per step",
  );
  eq(byAttr(nav, "aria-current", "step").length, 1, "the current step is marked once");
  eq(sinkUses, [], "no HTML sink reached");
});

// ---------------------------------------------------------------------------
// R-PG-01: per-step validation before the next step opens
// ---------------------------------------------------------------------------

/**
 * R-PG-01 AC: each step carries the state the creator's report gives it,
 * and a step opens only when every step before it has no failure. Without
 * a report only step 1 opens: the page never decides on its own.
 */
test("r_pg_01_studio_step_opens_only_after_its_validation", () => {
  const steps = CREATOR_STEPS.slice(0, 10).map((s) => s.id);
  forAll(
    (r) => {
      const results: ReportResult[] = [];
      for (const s of steps) {
        const pick = r.between(0, 3);
        const key = FIELD_OF[s] ?? "";
        if (pick === 1) results.push(row("failure", key));
        if (pick === 2) results.push(row("warning", key, "P39AboveP03"));
        if (pick === 3) results.push(row("warning", key, "P39AboveP03", true));
      }
      if (r.bool()) results.push(row("failure", null, "GuideSectionMissing"));
      return results;
    },
    (results) => {
      const states = stepStates(rep(results));
      eq(states.map((s) => s.id), CREATOR_STEPS.map((s) => s.id), "one state per step, in order");
      let blocked: string | null = null;
      for (const s of states) {
        const mine = results.filter((x) => (x.field === null ? s.id === "review" : x.field === FIELD_OF[s.id]));
        const failures = mine.filter((x) => x.severity === "failure").length;
        const warnings = mine.filter((x) => x.severity === "warning" && !x.acknowledged).length;
        eq([s.failures, s.warnings], [failures, warnings], `the counts of ${s.id}`);
        eq(s.condition, failures > 0 ? "failures" : warnings > 0 ? "warnings" : "valid", `the condition of ${s.id}`);
        eq(s.open, blocked === null, `${s.id} opens only after every earlier step validates`);
        eq(s.waitsFor, blocked, `what ${s.id} waits for`);
        if (blocked === null && failures > 0) blocked = s.id;
      }
    },
  );
  const none = stepStates(null);
  eq(
    none.map((s) => [s.id, s.condition, s.open]),
    CREATOR_STEPS.map((s, i) => [s.id, "unknown", i === 0]),
    "without the report only step 1 opens",
  );

  // The page: a locked step holds no link, is not focusable and says why.
  freshDom();
  const states = stepStates(rep([row("failure", "identity.name")]));
  const nav = asFake(studioNav("7", states, "identity"));
  const eligibility = byAttr(nav, "data-step", "eligibility")[0];
  assert(eligibility !== undefined, "step 3 is listed");
  eq(links(eligibility).length, 0, "a locked step holds no link");
  eq(eligibility.getAttribute("data-locked"), "true", "marked locked");
  assert(eligibility.textContent.includes("Opens when step 2 validates."), `the reason: ${eligibility.textContent}`);
  eq(
    eligibility.descendants().filter((e) => e.hasAttribute("tabindex")).length,
    0,
    "a locked step is not focusable",
  );
  const identity = byAttr(nav, "data-step", "identity")[0];
  assert(identity !== undefined && identity.textContent.includes("has failures"), "the step names its failures");
  const funder = byAttr(nav, "data-step", "funder")[0];
  eq(links(funder)[0]?.getAttribute("href"), "/app/programmes/7/creator/funder", "an open step links its page");

  const next = asFake(nextControl("7", "identity", states));
  eq(next.localName === "a" || links(next).length > 0, false, "no next link while the step has failures");
  assert(next.textContent.includes("The next step opens when this step validates."), next.textContent);
  const fine = asFake(nextControl("7", "funder", states));
  const a = fine.localName === "a" ? fine : links(fine)[0];
  eq(a?.getAttribute("href"), "/app/programmes/7/creator/identity", "a validated step links the next one");
  eq(a?.getAttribute("id"), "creator-step-next", "the e2e contract's id");
});

// ---------------------------------------------------------------------------
// I-66: the final validation report
// ---------------------------------------------------------------------------

/**
 * I-66, R-PG-03: on "Approval and publication" a failure blocks the
 * activation request, a warning blocks it until acknowledged, and an
 * acknowledgement never clears a failure.
 */
test("i66_studio_failures_block_activation_and_warnings_need_acknowledgement", () => {
  freshDom();
  const request = (panel: unknown): FakeElement[] => byAttr(panel, "data-action", "request-activation");
  const failed = activationPanel("7", rep([row("failure", "money.p05_recipient_cap", "CapAboveCeiling", true)]), "draft");
  eq(request(failed).length, 0, "a failure leaves no request control, acknowledged or not");
  eq(asFake(failed).getAttribute("data-gate"), "failures", "the gate says why");
  assert(asFake(failed).textContent.includes("(I-66)"), asFake(failed).textContent);

  const warned = activationPanel("7", rep([row("warning", "evaluation.p02_threshold", "P39AboveP03")]), "draft");
  eq(request(warned).length, 0, "an unacknowledged warning leaves no request control");
  eq(asFake(warned).getAttribute("data-gate"), "warnings", "the gate says why");
  assert(
    links(warned).some((l) => l.getAttribute("href") === "/app/programmes/7/creator/review"),
    "the review step, where warnings are acknowledged, is linked",
  );

  const clean = activationPanel("7", rep([row("warning", "evaluation.p02_threshold", "P39AboveP03", true)]), "draft");
  eq(asFake(clean).getAttribute("data-gate"), "clean", "an acknowledged warning clears the gate");
  eq(
    request(clean).map((e) => e.getAttribute("href")),
    ["/app/programmes/7/creator/review"],
    "the request is made on the review step",
  );

  const none = activationPanel("7", null, "draft");
  eq(request(none).length, 0, "no report, no request");
  eq(asFake(none).getAttribute("data-gate"), "unknown", "the gate is unknown without the report");
});

/**
 * I-67, R-PG-03: activation needs a second approver who did not build
 * the draft. The page names that rule and offers no approver choice.
 */
test("i67_studio_activation_names_the_second_approver_and_offers_no_choice", () => {
  freshDom();
  for (const status of ["draft", "requested", "active"] as const) {
    const panel = asFake(activationPanel("7", rep([]), status));
    eq(panel.getAttribute("data-status"), status, "the status from the draft read");
    eq(panel.getElementsByTagName("select").length, 0, `${status}: no approver select`);
    assert(panel.textContent.includes("(I-67)"), `${status}: ${panel.textContent}`);
  }
  eq(byAttr(activationPanel("7", rep([]), "active"), "data-action", "request-activation").length, 0, "no request once active");
});

// ---------------------------------------------------------------------------
// R-PC-03: approval and the return to DRAFT
// ---------------------------------------------------------------------------

/**
 * R-PC-03 NOTE: an edit to the call text, P-01 or P-09 after approval
 * returns the call to DRAFT, and the page says so before the save. Other
 * fields carry no such note, and a programme not yet active has no call.
 */
test("r_pc_03_studio_warns_before_saving_call_text_p01_or_p09_after_approval", () => {
  eq(returnsCallToDraft("call.text"), true, "the call text");
  eq(returnsCallToDraft("evaluation.p01_criteria"), true, "P-01");
  eq(returnsCallToDraft("evaluation.p09_knock_outs"), true, "P-09");
  for (const k of ["evaluation.p02_threshold", "money.p05_recipient_cap", "identity.name", "", "p01"]) {
    eq(returnsCallToDraft(k), false, `not ${show(k)}`);
  }
  freshDom();
  for (const k of ["evaluation.p01_criteria", "evaluation.p09_knock_outs", "call.text"]) {
    const note = afterApprovalNote(k, "active");
    assert(note !== null, `a note for ${k}`);
    const text = asFake(note).textContent;
    assert(text.includes("returns") && text.includes("DRAFT"), text);
    eq(asFake(note).getAttribute("data-note"), "returns-to-draft", "marked for the e2e contract");
  }
  eq(afterApprovalNote("evaluation.p01_criteria", "draft"), null, "no call exists before activation");
  eq(afterApprovalNote("evaluation.p02_threshold", "active"), null, "P-02 does not return a call to DRAFT");
});

/**
 * R-PC-03, R-PC-02: a caller who only drafts calls sees no approve
 * control. A programme manager does, and the server still refuses a
 * drafter of the call. Call states come from `calls.get`, open and
 * closed from its `open` member, never from the browser clock.
 */
test("r_pc_03_studio_drafter_sees_no_approve_control", () => {
  const drafter = roles({
    tenant_admin: false,
    roles: [{ role: "call_drafter", programme: "7", calls: ["3"] }],
    calls: [{ call: "3", title: "Synthetic call" }],
    rounds: [],
    drafts: [],
  });
  const pm = roles({
    tenant_admin: false,
    roles: [
      { role: "programme_manager", programme: "7", calls: ["3", "10"] },
      { role: "programme_manager", programme: "8", calls: ["4"] },
    ],
    calls: [],
    rounds: [],
    drafts: ["7"],
  });
  eq(mayApproveCalls(drafter, "7"), false, "a call drafter may not approve");
  eq(mayApproveCalls(pm, "7"), true, "a programme manager may ask to approve");
  eq(mayApproveCalls(pm, "9"), false, "only on their own programme");
  eq(programmeCalls(pm, "7"), ["3", "10"], "the programme's published calls, ascending");

  const published = readCallState({
    call: "3",
    programme: "7",
    status: "published",
    opens: "2026-10-01T09:00:00Z",
    deadline: "2026-12-01T17:00:00Z",
    deadline_zone: "Europe/Brussels",
    budget: "100000.00",
    currency: "EUR",
    open: false,
    title: "Synthetic call",
  });
  eq(published, { call: "3", state: "PUBLISHED", open: false, title: "Synthetic call" }, "the call state");
  eq(readCallState({ call: "3", status: "frozen", open: true }), null, "an unknown status is refused");

  freshDom();
  const forDrafter = asFake(callsPanel(drafter, "7", published === null ? [] : [published]));
  eq(byAttr(forDrafter, "data-action", "approve-call").length, 0, "no approve control for a drafter");
  assert(forDrafter.textContent.includes("(R-PC-03)"), forDrafter.textContent);
  const forPm = asFake(callsPanel(pm, "7", published === null ? [] : [published]));
  eq(byAttr(forPm, "data-action", "approve-call").length, 1, "the approve control for a programme manager");
  const listed = byAttr(forPm, "data-call", "3")[0];
  assert(listed !== undefined, "the call is listed");
  eq(listed.getAttribute("data-state"), "PUBLISHED", "its state");
  assert(listed.textContent.includes("PUBLISHED") && listed.textContent.includes("not open"), listed.textContent);
});

// ---------------------------------------------------------------------------
// I-65, R-PG-02: imported values
// ---------------------------------------------------------------------------

/** I-65, R-PG-02: imported values that still wait for a programme manager's confirmation are named. */
test("i65_studio_names_imported_values_awaiting_confirmation", () => {
  const proposal = (id: string, field: string, resolution: ProposalRow["resolution"]): ProposalRow => ({
    id,
    field,
    value: "1.00",
    digest: "d",
    evidence: [],
    flagged: false,
    resolution,
  });
  const rows = [
    proposal("1", "money.p05_recipient_cap", null),
    proposal("2", "identity.name", "confirmed"),
    proposal("3", "funder.action_number", null),
    proposal("4", "money.p04_grant_range", "dismissed"),
  ];
  eq(awaitingConfirmation(rows).map((r) => r.id), ["1", "3"], "the unresolved ones, in server order");
  freshDom();
  const panel = asFake(importsPanel("7", rows));
  const waiting = byAttr(panel, "data-awaiting");
  eq(waiting.map((e) => e.getAttribute("data-awaiting")), ["money.p05_recipient_cap", "funder.action_number"], "named by field");
  assert(waiting[0]?.textContent.includes("Cap per recipient") === true, show(waiting[0]?.textContent));
  assert(panel.textContent.includes("(I-65)"), panel.textContent);
  eq(
    links(panel).map((l) => l.getAttribute("href")),
    ["/app/programmes/7/creator/imports"],
    "the import review is linked",
  );
  const done = asFake(importsPanel("7", [proposal("2", "identity.name", "confirmed")]));
  eq(byAttr(done, "data-awaiting").length, 0, "nothing waits");
});

// ---------------------------------------------------------------------------
// R-PG-04, I-12: after activation
// ---------------------------------------------------------------------------

/**
 * R-PG-04, I-12: after activation the page lists the calls a change
 * affects from the impact read, and says that frozen parameters apply to
 * the next call only. A read the cell cannot answer lists nothing.
 */
test("r_pg_04_i12_studio_shows_affected_calls_and_the_next_call_rule", () => {
  eq(readImpact({ calls: [{ call: "3" }, { call: "10" }] }), ["3", "10"], "the impact read");
  eq(readImpact({ calls: [{ call: "x y" }] }), null, "a malformed id is refused");
  eq(readImpact({}), null, "a body without calls is refused");
  freshDom();
  const listed = asFake(impactPanel(["3", "10"], (c) => `Call ${c}`));
  eq(byAttr(listed, "data-affected").map((e) => e.getAttribute("data-affected")), ["3", "10"], "each affected call");
  assert(listed.textContent.includes("(I-12)") && listed.textContent.includes("next call"), listed.textContent);
  const none = asFake(impactPanel([], (c) => `Call ${c}`));
  eq(byAttr(none, "data-affected").length, 0, "no call");
  assert(none.textContent.includes("(I-12)"), "the frozen rule still shows");
  const unknown = asFake(impactPanel(null, (c) => `Call ${c}`));
  eq(unknown.getAttribute("data-impact"), "unavailable", "an unanswered read is not an empty list");
});

/** R-GA-01: the Guide for Applicants preview has its own studio page, linked from the overview. */
test("r_ga_01_studio_guide_preview_path", () => {
  eq(STUDIO_PATHS.overview("7"), "/app/programmes/7/studio", "the overview");
  eq(STUDIO_PATHS.approval("7"), "/app/programmes/7/studio/approval", "approval and publication");
  eq(STUDIO_PATHS.guide("7"), "/app/programmes/7/studio/guide", "the Guide preview");
});
