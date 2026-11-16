// The "Application" section of the applicant's proposal page (Daniel,
// 2026-11-15, night: "on this page i would like to be able to read the
// application" and "if i wrote it i should be able to read it"). Each
// team role reads the application read-only in every state, the former
// team included. The section calls only the reads its viewer may make
// (SA-09 rule 7), and it renders every answer as text, never as markup
// (ADR-014, TH-01).

import type { Outcome } from "../src/applicant/client.js";
import {
  APPLICATION_QUESTIONS,
  type ApplicationCall,
  applicationPlan,
  applicationSection,
  loadApplication,
} from "../src/applicant/application.js";
import { APPLICANT_LABELS } from "../src/applicant/messages.en.js";
import { PROPOSAL_STATES, type ProposalRole, type ProposalState, isTerminal } from "../src/applicant/rules.js";
import { type ProposalInfo, decodePlan, decodeStage2Thread } from "../src/applicant/wire.js";
import { FakeElement, asFake, freshDom, sinkUses } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";

const ROLES: readonly ProposalRole[] = ["lead", "member", "guardian"];

/** The states from stage 2 on, where stage 2 questions can exist. */
const STAGE2_ON: ReadonlySet<ProposalState> = new Set<ProposalState>([
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "DECLINED",
  "NEGOTIATION",
  "GRANTED",
  "IN_EXECUTION",
  "COMPLETED",
  "TERMINATED",
]);

/**
 * Whether `role` may make `op` on a proposal in `state`, as `fstp-access`
 * admits it after lane m4/author-reads. `proposal.get_workspace` admits
 * the active team and, once X ended, the former lead, member and guardian
 * (`ReadRule::FormerAuthor`). `stage2.view` and `proposal.get_plan` admit
 * the active team and the former lead and member only
 * (`ReadRule::FormerTeam`).
 */
function admitted(op: string, role: ProposalRole, state: ProposalState): boolean {
  if (op === "proposal.get_workspace") {
    return true;
  }
  if (op === "stage2.view" || op === "proposal.get_plan") {
    return !(role === "guardian" && isTerminal(state));
  }
  return false;
}

const MARKUP = '<img src=x onerror="alert(1)"><b>bold</b> &amp; <script>x()</script>';
const LONG = Array.from({ length: 400 }, (_, i) => `Line ${i} of a long narrative.`).join("\n");

const WORKSPACE = Object.freeze({ title: "Synthetic soil sensors", summary: MARKUP, narrative: LONG });
const QUESTIONS = Object.freeze([
  Object.freeze({
    handle: "R1",
    asked: Object.freeze({ text: "2026-10-01", year: 2026, month: 10, day: 1 }),
    text: "How does the sensor <b>calibrate</b>?",
  }),
  Object.freeze({
    handle: "R2",
    asked: Object.freeze({ text: "2026-10-02", year: 2026, month: 10, day: 2 }),
    text: "Who owns the data?",
  }),
]);

/** The team's answers as `stage2.view` sends them: two after the first question, none after the second. */
const ANSWERS = Object.freeze([
  Object.freeze({ after: 1, answered: "2026-10-03", text: "It calibrates against <script>x()</script> a reference." }),
  Object.freeze({ after: 1, answered: "2026-10-04", text: "A second answer." }),
]);

const STAGE2_BODY = Object.freeze({
  questions: QUESTIONS.map((q) => ({ handle: q.handle, asked: q.asked.text, text: q.text })),
  answers: ANSWERS,
});

const PLAN_TEXT = 'Work package <b>one</b>\n<img src=x onerror="alert(1)">';

/** The plan as `proposal.get_plan` sends it: two tasks, the total and the text. */
const PLAN_BODY = Object.freeze({
  plan: {
    plan: "31",
    origin: "stage2_revision",
    tasks: [
      { milestones: [{ amount: "1000.00", start: "2027-01-04", due: "2027-03-31" }] },
      {
        milestones: [
          { amount: "250.50", start: "2027-04-01", due: "2027-06-30" },
          { amount: "99.99", start: "2027-07-01", due: "2027-09-30" },
        ],
      },
    ],
    total: "1350.49",
    text: PLAN_TEXT,
  },
});

function info(state: ProposalState, role: ProposalRole | undefined): ProposalInfo {
  return Object.freeze({ proposal: "1003", call: "7", state, role, title: "Synthetic soil sensors", knockOutReason: "" });
}

/** A fake applicant call that records each read and answers it as the cell would. */
function fakeCall(role: ProposalRole | undefined, state: ProposalState, calls: string[]): ApplicationCall {
  return <T>(name: string, params: Readonly<Record<string, string>>, decode: (v: unknown) => T | null) => {
    calls.push(name);
    eq(params, { proposal: "1003" }, `${name} params`);
    if (role === undefined || !admitted(name, role, state)) {
      return Promise.resolve<Outcome<T>>({ ok: false, failure: { kind: "refused", code: "refused", rule: "R-AC-01" } });
    }
    const body: unknown = name === "stage2.view" ? STAGE2_BODY : name === "proposal.get_plan" ? PLAN_BODY : WORKSPACE;
    const v = decode(body);
    assert(v !== null, `${name} body decodes`);
    return Promise.resolve<Outcome<T>>({ ok: true, value: v });
  };
}

function byId(root: FakeElement, id: string): FakeElement | undefined {
  return root.descendants().find((e) => e.getAttribute("id") === id);
}

async function render(state: ProposalState, role: ProposalRole | undefined): Promise<{ root: FakeElement | null; calls: string[] }> {
  freshDom();
  const calls: string[] = [];
  const p = info(state, role);
  const plan = applicationPlan(role, state);
  const data = await loadApplication(p, plan, fakeCall(role, state, calls));
  const el = applicationSection(p, plan, data);
  return { root: el === null ? null : asFake(el), calls };
}

/** The reads a team role makes in `state`, in order. */
function expectedReads(role: ProposalRole, state: ProposalState): string[] {
  const former = role === "guardian" && isTerminal(state);
  const reads = ["proposal.get_workspace"];
  if (!former) {
    reads.push("proposal.get_plan");
  }
  if (STAGE2_ON.has(state) && !former) {
    reads.push("stage2.view");
  }
  return reads;
}

/**
 * SA-09 rule 7, I-21, R-AC-01: for every team role in every state the
 * section calls only reads its viewer may make, so the page never shows
 * a refusal. It always reads the workspace, the plan in every state and
 * stage 2 from stage 2 on, except for a guardian once the proposal ended
 * (lane m4/author-reads).
 */
test("r_ac_01_application_section_calls_only_admitted_reads_for_every_role_and_state", async () => {
  for (const state of PROPOSAL_STATES) {
    for (const role of ROLES) {
      const { root, calls } = await render(state, role);
      for (const c of calls) {
        assert(admitted(c, role, state), `${role} in ${state} calls ${c}, which refuses`);
      }
      eq(calls, expectedReads(role, state), `${role} in ${state}`);
      assert(root !== null, `${role} in ${state} sees the section`);
      eq(byId(root, "application-error"), undefined, `${role} in ${state}: no error`);
      eq(byId(root, "application-plan-error"), undefined, `${role} in ${state}: no plan error`);
      eq(byId(root, "application-stage2-error"), undefined, `${role} in ${state}: no stage 2 error`);
    }
  }
});

/** R-AC-01: a viewer with no team role makes no read and sees no section. */
test("r_ac_01_application_section_reads_nothing_without_a_team_role", async () => {
  for (const state of PROPOSAL_STATES) {
    const { root, calls } = await render(state, undefined);
    eq(calls, [], `no read in ${state}`);
    eq(root, null, `no section in ${state}`);
  }
});

/**
 * I-21: in DRAFT the lead, a team member and the guardian read the
 * current draft, each answer under its question in the order of the
 * form, with a link to edit it in the workspace.
 */
test("i21_application_section_in_draft_shows_the_draft_with_an_edit_link", async () => {
  for (const role of ROLES) {
    const { root } = await render("DRAFT", role);
    assert(root !== null, role);
    eq(root.getAttribute("aria-labelledby"), "application-heading", `${role}: labelled section`);
    eq(byId(root, "application-heading")?.textContent, APPLICANT_LABELS["application.heading"], `${role}: heading`);
    eq(byId(root, "application-source")?.textContent, APPLICANT_LABELS["application.source.draft"], `${role}: source`);
    eq(byId(root, "application-edit")?.getAttribute("href"), "/app/proposals/1003/workspace", `${role}: edit link`);
    eq(byId(root, "application-stage2"), undefined, `${role}: no stage 2 in DRAFT`);
    eq(byId(root, "application-copy"), undefined, `${role}: no copy pointer in DRAFT`);
    const dl = byId(root, "application-answers");
    assert(dl !== undefined && dl.localName === "dl", `${role}: a description list`);
    const dts = dl.children.filter((c) => c.localName === "dt").map((c) => c.textContent);
    eq(dts, APPLICATION_QUESTIONS.map(([, k]) => APPLICANT_LABELS[k]), `${role}: the questions in form order`);
    const dds = dl.children.filter((c) => c.localName === "dd").map((c) => c.textContent);
    eq(dds, [WORKSPACE.title, WORKSPACE.summary, WORKSPACE.narrative], `${role}: the answers, unchanged`);
    eq(dl.children.map((c) => c.localName), ["dt", "dd", "dt", "dd", "dt", "dd"], `${role}: each answer follows its question`);
  }
});

/**
 * I-21, R-SB-04: after submission (STAGE1) the lead, a team member and
 * the guardian read the application as submitted, with no edit link and
 * no stage 2 part yet.
 */
test("i21_application_section_in_stage1_shows_the_submitted_application_read_only", async () => {
  for (const role of ROLES) {
    const { root } = await render("STAGE1", role);
    assert(root !== null, role);
    eq(byId(root, "application-source")?.textContent, APPLICANT_LABELS["application.source.submitted"], `${role}: source`);
    eq(byId(root, "application-edit"), undefined, `${role}: no edit link`);
    eq(byId(root, "application-stage2"), undefined, `${role}: no stage 2 in STAGE1`);
    const dds = root.getElementsByTagName("dd").map((c) => c.textContent);
    eq(dds, [WORKSPACE.title, WORKSPACE.summary, WORKSPACE.narrative], `${role}: the answers`);
    eq(root.getElementsByTagName("textarea").length + root.getElementsByTagName("input").length, 0, `${role}: no control`);
  }
});

/**
 * R-SB-01, ADR-006 (lane m4/author-reads): the team reads back the plan
 * it recorded under its own heading in every state: each task with its
 * milestones, their amounts and days, the total the cell sent and the
 * work plan text. The page computes no money and shows no control.
 */
test("r_sb_01_application_section_shows_the_plan_read_only", async () => {
  for (const state of PROPOSAL_STATES) {
    for (const role of ROLES) {
      const { root } = await render(state, role);
      assert(root !== null, `${role} in ${state}`);
      const part = byId(root, "application-plan");
      if (role === "guardian" && isTerminal(state)) {
        eq(part, undefined, `the former guardian in ${state}: no plan part`);
        continue;
      }
      assert(part !== undefined, `${role} in ${state}: a plan part`);
      eq(byId(part, "application-plan-heading")?.localName, "h3", `${role} in ${state}: its heading`);
      eq(byId(part, "application-plan-origin")?.textContent, APPLICANT_LABELS["application.plan.origin.stage2_revision"], "origin");
      const tasks = byId(part, "application-plan-tasks");
      assert(tasks !== undefined && tasks.localName === "ol", "an ordered list of tasks");
      eq(tasks.children.length, 2, "two tasks");
      const milestones = part.descendants().filter((e) => e.getAttribute("class") === "fstp-plan-milestone");
      eq(milestones.length, 3, "three milestones");
      assert(milestones[1]?.textContent.includes("250.50") === true, "the amount as the cell sent it");
      assert(byId(part, "application-plan-total")?.textContent.includes("1350.49") === true, "the total the cell sent");
      eq(byId(part, "application-plan-text")?.textContent, PLAN_TEXT, "the work plan text, unchanged");
      eq(part.getElementsByTagName("input").length + part.getElementsByTagName("textarea").length, 0, "no control");
    }
  }
});

/**
 * R-SB-01 (lane m4/author-reads): with no plan recorded the plan part
 * says so. A plan whose text the cell does not hold says that the text
 * cannot be shown, never an empty text. A plan with no total shows none.
 */
test("r_sb_01_plan_part_names_a_missing_plan_and_a_missing_text", async () => {
  freshDom();
  const p = info("DRAFT", "lead");
  const plan = applicationPlan("lead", "DRAFT");
  const workspace = { ok: true, value: WORKSPACE } as const;
  const none = applicationSection(p, plan, { workspace, plan: { ok: true, value: { plan: null } }, stage2: null });
  assert(none !== null, "the section");
  eq(byId(asFake(none), "application-plan-none")?.textContent, APPLICANT_LABELS["application.plan.none"], "no plan yet");
  freshDom();
  const bare = {
    plan: "31",
    origin: "submitted" as const,
    tasks: [[{ amount: "5.00", start: QUESTIONS[0]!.asked, due: QUESTIONS[0]!.asked }]],
    total: undefined,
    text: undefined,
    textErased: undefined,
  };
  const el = applicationSection(p, plan, { workspace, plan: { ok: true, value: { plan: bare } }, stage2: null });
  assert(el !== null, "the section");
  const root = asFake(el);
  eq(byId(root, "application-plan-text"), undefined, "no text element");
  eq(byId(root, "application-plan-text-missing")?.textContent, APPLICANT_LABELS["application.plan.text_missing"], "the text is named missing");
  eq(byId(root, "application-plan-total"), undefined, "no total");
  eq(byId(root, "application-plan-origin")?.textContent, APPLICANT_LABELS["application.plan.origin.submitted"], "origin");
});

/**
 * R-EV-05, TH-08, P-11 (lane m4/author-reads): from stage 2 on, the stage
 * 2 questions follow under their own heading, by handle and day, and
 * under each question the team's own answers given after it, as text
 * with their day. A question with no answer after it has none under it.
 */
test("r_ev_05_application_section_in_stage2_shows_each_answer_under_its_question", async () => {
  for (const role of ROLES) {
    const { root } = await render("STAGE2", role);
    assert(root !== null, role);
    const part = byId(root, "application-stage2");
    assert(part !== undefined, `${role}: a stage 2 part`);
    eq(byId(part, "application-stage2-heading")?.localName, "h3", `${role}: its heading`);
    eq(byId(part, "application-stage2-heading")?.textContent, APPLICANT_LABELS["application.stage2.heading"], `${role}: heading text`);
    const items = (byId(part, "application-stage2-questions")?.children ?? []).filter((c) => c.localName === "li");
    eq(items.length, 2, `${role}: two questions`);
    assert(items[0]?.textContent.includes(QUESTIONS[0]?.text ?? "?") === true, `${role}: the question as text`);
    const answersOf = (li: FakeElement | undefined) =>
      (li?.descendants() ?? []).filter((e) => e.getAttribute("class") === "fstp-stage2-answer");
    const first = answersOf(items[0]);
    eq(first.length, 2, `${role}: both answers under the first question`);
    assert(first[0]?.textContent.includes(ANSWERS[0]?.text ?? "?") === true, `${role}: the first answer as text`);
    assert(first[1]?.textContent.includes(ANSWERS[1]?.text ?? "?") === true, `${role}: the second answer, in order`);
    eq(answersOf(items[1]).length, 0, `${role}: no answer under the second question`);
    eq(byId(part, "application-stage2-answers"), undefined, `${role}: no "no answer" note`);
    assert(!part.textContent.includes("R-0"), `${role}: no reviewer named on an answer`);
  }
});

/** R-EV-05 (lane m4/author-reads): with no answer yet, the stage 2 part says so. */
test("r_ev_05_stage2_part_names_no_answer_yet", async () => {
  freshDom();
  const p = info("STAGE2", "member");
  const plan = applicationPlan("member", "STAGE2");
  const el = applicationSection(p, plan, {
    workspace: { ok: true, value: WORKSPACE },
    plan: null,
    stage2: { ok: true, value: { questions: QUESTIONS, answers: [] } },
  });
  assert(el !== null, "the section");
  eq(byId(asFake(el), "application-stage2-answers")?.textContent, APPLICANT_LABELS["application.stage2.answers"], "no answer yet");
});

/**
 * Daniel, 2026-11-15 (night), R-SB-04: in a terminal state everyone who
 * was on the team still reads the application, and the section points
 * to the copy request. The former lead and member keep the plan and
 * their stage 2 answers. The former guardian gets neither part, since it
 * wrote neither and has no such read.
 */
test("r_sb_04_application_section_stays_with_the_former_team_in_terminal_states", async () => {
  for (const state of PROPOSAL_STATES.filter(isTerminal)) {
    for (const role of ROLES) {
      const { root } = await render(state, role);
      assert(root !== null, `${role} in ${state}`);
      const source = state === "WITHDRAWN" ? "application.source.withdrawn" : "application.source.submitted";
      eq(byId(root, "application-source")?.textContent, APPLICANT_LABELS[source], `${role} in ${state}: source`);
      eq(byId(root, "application-copy")?.textContent, APPLICANT_LABELS["application.copy"], `${role} in ${state}: copy pointer`);
      eq(byId(root, "application-edit"), undefined, `${role} in ${state}: no edit link`);
      eq(root.getElementsByTagName("dd").length, 3, `${role} in ${state}: three answers`);
      const stage2 = STAGE2_ON.has(state) && role !== "guardian";
      eq(byId(root, "application-stage2") !== undefined, stage2, `${role} in ${state}: stage 2 part`);
      eq(byId(root, "application-plan") !== undefined, role !== "guardian", `${role} in ${state}: plan part`);
      if (stage2) {
        eq(
          root.descendants().filter((e) => e.getAttribute("class") === "fstp-stage2-answer").length,
          ANSWERS.length,
          `${role} in ${state}: its stage 2 answers`,
        );
      }
    }
  }
});

/**
 * ADR-014, TH-01: submission content is untrusted. Markup in an answer,
 * in the plan text or in a stage 2 answer stays text: no element is
 * built from it, and no HTML sink is reached. Long answers keep their
 * line breaks under `fstp-text`.
 */
test("adr014_application_answers_render_as_text_only", async () => {
  const { root } = await render("STAGE2", "lead");
  assert(root !== null, "the section");
  eq(sinkUses, [], "no HTML sink reached");
  const tags = new Set(root.descendants().map((e) => e.localName));
  for (const bad of ["img", "script", "b"]) {
    assert(!tags.has(bad), `no ${bad} element from submission text`);
  }
  const dds = root.getElementsByTagName("dd");
  eq(dds[1]?.textContent, MARKUP, "the markup shows as typed");
  assert(dds[2]?.getAttribute("class")?.split(" ").includes("fstp-text") === true, "a long answer keeps its line breaks");
  eq(dds[2]?.textContent, LONG, "the long answer in full");
  eq(byId(root, "application-plan-text")?.textContent, PLAN_TEXT, "the plan text shows as typed");
  assert(byId(root, "application-plan-text")?.getAttribute("class") === "fstp-text", "the plan text keeps its line breaks");
  assert(root.textContent.includes(ANSWERS[0]?.text ?? "?"), "the stage 2 answer shows as typed");
});

/** R-NF-03: an empty answer says so in words, under its question. */
test("r_nf_03_application_empty_answer_is_named", async () => {
  freshDom();
  const p = info("DRAFT", "lead");
  const plan = applicationPlan("lead", "DRAFT");
  const el = applicationSection(p, plan, {
    workspace: { ok: true, value: { title: "", summary: "  ", narrative: "Text" } },
    plan: null,
    stage2: null,
  });
  assert(el !== null, "the section");
  const dds = asFake(el).getElementsByTagName("dd").map((d) => d.textContent);
  eq(dds, [APPLICANT_LABELS["application.empty"], APPLICANT_LABELS["application.empty"], "Text"], "empty answers named");
});

/** R-AC-01: a failed read shows its reason inside the section, so the page still loads. */
test("r_ac_01_application_read_failure_stays_inside_the_section", async () => {
  freshDom();
  const p = info("STAGE2", "member");
  const plan = applicationPlan("member", "STAGE2");
  const failed = { ok: false, failure: { kind: "failed", reason: "network" } } as const;
  const el = applicationSection(p, plan, { workspace: failed, plan: failed, stage2: failed });
  assert(el !== null, "the section");
  assert(byId(asFake(el), "application-error") !== undefined, "the reason shows");
  assert(byId(asFake(el), "application-plan-error") !== undefined, "the plan read's reason shows");
  assert(byId(asFake(el), "application-stage2-error") !== undefined, "the stage 2 read's reason shows");
  eq(asFake(el).getElementsByTagName("dl").length, 0, "no answers");
});

/**
 * R-SB-01, R-EV-05, TH-08 (lane m4/author-reads): the decoders refuse a
 * stage 2 answer placed after a question that does not exist, an answer
 * with a time of day, a plan with an unknown origin and a plan amount
 * that is not an ADR-006 string. `{plan: null}` decodes as no plan.
 */
test("r_sb_01_r_ev_05_decoders_refuse_malformed_bodies", () => {
  eq(decodeStage2Thread(STAGE2_BODY)?.answers.length, 2, "the body decodes");
  eq(decodeStage2Thread({ ...STAGE2_BODY, answers: [{ after: 3, answered: "2026-10-03", text: "x" }] }), null, "after past the questions");
  eq(decodeStage2Thread({ ...STAGE2_BODY, answers: [{ after: 1, answered: "2026-10-03T10:00:00Z", text: "x" }] }), null, "a time of day");
  eq(decodeStage2Thread({ questions: STAGE2_BODY.questions }), null, "answers missing");
  eq(decodePlan({ plan: null }), { plan: null }, "no plan yet");
  eq(decodePlan({}), null, "plan member missing");
  eq(decodePlan({ plan: { ...PLAN_BODY.plan, origin: "invented" } }), null, "unknown origin");
  const bad = { ...PLAN_BODY.plan, tasks: [{ milestones: [{ amount: "1,000", start: "2027-01-04", due: "2027-03-31" }] }] };
  eq(decodePlan({ plan: bad }), null, "a malformed amount");
  eq(decodePlan({ plan: { ...PLAN_BODY.plan, text: 7 } }), null, "a text that is not a string");
  const erased = { ...PLAN_BODY.plan, text: undefined, text_erased: "2026-11-16" };
  eq(decodePlan({ plan: erased })?.plan?.textErased?.text, "2026-11-16", "an erased text decodes with its day");
  eq(decodePlan({ plan: erased })?.plan?.text, undefined, "no text beside its erasure");
  eq(decodePlan({ plan: { ...PLAN_BODY.plan, text_erased: "2026-11-16" } }), null, "a text beside its erasure");
  eq(decodePlan({ plan: { ...erased, text_erased: "2026-11-16T10:00:00Z" } }), null, "an erasure with a time of day");
});

/**
 * R-SB-01, ADR-007 (Daniel, 2026-11-16): a plan whose work plan text was
 * erased says so with the day the erasure was requested. It never shows
 * the text and never reads as a text the cell does not hold.
 */
test("r_sb_01_adr007_plan_part_names_an_erased_text_as_erased", async () => {
  freshDom();
  const p = info("STAGE1", "lead");
  const plan = applicationPlan("lead", "STAGE1");
  const workspace = { ok: true, value: WORKSPACE } as const;
  const erased = decodePlan({ plan: { ...PLAN_BODY.plan, text: undefined, text_erased: "2026-11-16" } });
  assert(erased !== null && erased.plan !== null, "the body decodes");
  const el = applicationSection(p, plan, { workspace, plan: { ok: true, value: erased }, stage2: null });
  assert(el !== null, "the section");
  const root = asFake(el);
  const line = byId(root, "application-plan-text-erased");
  assert(line !== undefined, "the erasure is named");
  const wording = APPLICANT_LABELS["application.plan.text_erased"] ?? "";
  assert(wording !== "" && (line.textContent ?? "").startsWith(wording), "the erased wording");
  eq(byId(root, "application-plan-text-missing"), undefined, "not read as missing");
  eq(byId(root, "application-plan-text"), undefined, "no text element");
});
