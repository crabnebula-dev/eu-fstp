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
import type { ProposalInfo } from "../src/applicant/wire.js";
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
 * admits it after lane m4/proposal-read. `proposal.get_workspace` admits
 * the active team and, once X ended, the former lead, member and guardian
 * (`ReadRule::FormerAuthor`). `stage2.view` admits the active team and
 * the former lead and member only (`ReadRule::FormerTeam`).
 */
function admitted(op: string, role: ProposalRole, state: ProposalState): boolean {
  if (op === "proposal.get_workspace") {
    return true;
  }
  if (op === "stage2.view") {
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
]);

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
    const body: unknown = name === "stage2.view" ? { questions: [{ handle: "R1", asked: "2026-10-01", text: QUESTIONS[0]?.text }] } : WORKSPACE;
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

/**
 * SA-09 rule 7, I-21, R-AC-01: for every team role in every state the
 * section calls only reads its viewer may make, so the page never shows
 * a refusal. It always reads the workspace, and stage 2 from stage 2 on,
 * except for a guardian once the proposal ended.
 */
test("r_ac_01_application_section_calls_only_admitted_reads_for_every_role_and_state", async () => {
  for (const state of PROPOSAL_STATES) {
    for (const role of ROLES) {
      const { root, calls } = await render(state, role);
      for (const c of calls) {
        assert(admitted(c, role, state), `${role} in ${state} calls ${c}, which refuses`);
      }
      const stage2 = STAGE2_ON.has(state) && !(role === "guardian" && isTerminal(state));
      eq(calls, stage2 ? ["proposal.get_workspace", "stage2.view"] : ["proposal.get_workspace"], `${role} in ${state}`);
      assert(root !== null, `${role} in ${state} sees the section`);
      eq(byId(root, "application-error"), undefined, `${role} in ${state}: no error`);
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
 * R-EV-05, TH-08, P-11: from stage 2 on, the stage 2 questions follow
 * under their own heading, by handle and day, and the section says that
 * the team's answers are not shown (no team read gives them).
 */
test("r_ev_05_application_section_in_stage2_adds_the_stage2_part", async () => {
  for (const role of ROLES) {
    const { root } = await render("STAGE2", role);
    assert(root !== null, role);
    const part = byId(root, "application-stage2");
    assert(part !== undefined, `${role}: a stage 2 part`);
    eq(byId(part, "application-stage2-heading")?.localName, "h3", `${role}: its heading`);
    eq(byId(part, "application-stage2-heading")?.textContent, APPLICANT_LABELS["application.stage2.heading"], `${role}: heading text`);
    const items = byId(part, "application-stage2-questions")?.getElementsByTagName("li") ?? [];
    eq(items.length, 1, `${role}: one question`);
    assert(items[0]?.textContent.includes(QUESTIONS[0]?.text ?? "?") === true, `${role}: the question as text`);
    eq(byId(part, "application-stage2-answers")?.textContent, APPLICANT_LABELS["application.stage2.answers"], `${role}: answers note`);
  }
});

/**
 * Daniel, 2026-11-15 (night), R-SB-04: in a terminal state everyone who
 * was on the team still reads the application, and the section points
 * to the copy request. The former guardian gets no stage 2 part, since
 * it has no stage 2 read.
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
    }
  }
});

/**
 * ADR-014, TH-01: submission content is untrusted. Markup in an answer
 * stays text: no element is built from it, and no HTML sink is reached.
 * Long answers keep their line breaks under `fstp-text`.
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
});

/** R-NF-03: an empty answer says so in words, under its question. */
test("r_nf_03_application_empty_answer_is_named", async () => {
  freshDom();
  const p = info("DRAFT", "lead");
  const plan = applicationPlan("lead", "DRAFT");
  const el = applicationSection(p, plan, {
    workspace: { ok: true, value: { title: "", summary: "  ", narrative: "Text" } },
    stage2: null,
  });
  assert(el !== null, "the section");
  const dds = asFake(el).getElementsByTagName("dd").map((d) => d.textContent);
  eq(dds, [APPLICANT_LABELS["application.empty"], APPLICANT_LABELS["application.empty"], "Text"], "empty answers named");
});

/** R-AC-01: a failed workspace read shows its reason inside the section, so the page still loads. */
test("r_ac_01_application_read_failure_stays_inside_the_section", async () => {
  freshDom();
  const p = info("STAGE1", "member");
  const plan = applicationPlan("member", "STAGE1");
  const el = applicationSection(p, plan, {
    workspace: { ok: false, failure: { kind: "failed", reason: "network" } },
    stage2: null,
  });
  assert(el !== null, "the section");
  assert(byId(asFake(el), "application-error") !== undefined, "the reason shows");
  eq(asFake(el).getElementsByTagName("dl").length, 0, "no answers");
});
