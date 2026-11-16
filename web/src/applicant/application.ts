// The "Application" section of the proposal page: the application as
// the team wrote it, read-only (Daniel, 2026-11-15, night: "on this page
// i would like to be able to read the application" and "if i wrote it i
// should be able to read it").
//
// Reads. The section reads the workspace (`proposal.get_workspace`): the
// title, the neutral summary and the narrative, in the order of the
// workspace form. The active team reads it in every state, and everyone
// who was on the team keeps it once the proposal ended
// (`ReadRule::FormerAuthor`). The workspace takes no save after DRAFT,
// and submission freezes it, so after submission it holds the text that
// was submitted. The team's read of the submitted version,
// `review.read_content`, carries the title and the narrative only, not
// the neutral summary, and admits no former guardian. So this section
// reads the workspace and says so in its source line.
//
// Plan. The section reads the plan the team recorded (`proposal.get_plan`,
// lane m4/author-reads) under its own heading: each task's milestones
// with their amounts and days, the total the cell summed, and the work
// plan text when the cell holds it. The browser computes no money.
//
// Stage 2. Once the proposal reached stage 2 the section reads the stage
// 2 thread (`stage2.view`) under its own heading: each question, and
// under it the team's own answers given after it (lane m4/author-reads).
// The guardian records neither a plan nor an answer, and
// `ReadRule::FormerTeam` names the former lead and members only, so the
// section never makes either read for a former guardian (SA-09 rule 7).
//
// Rendering. Every answer, the plan text included, is untrusted
// submission content. It reaches the page only as a text node through
// `h` (ADR-014), never as markup. The answers sit in a description list,
// each under its question, and keep their line breaks (`fstp-text`).

import { h } from "../core/dom.js";
import { type Outcome } from "./client.js";
import { type ProposalRole, type ProposalState, isTerminal, stage2Readable, teamReadsOffered } from "./rules.js";
import { APP, dayTime, failureText, t } from "./ui.js";
import {
  type PlanRead,
  type ProposalInfo,
  type Question,
  type Stage2Answer,
  type Stage2Thread,
  type Workspace,
  decodePlan,
  decodeStage2Thread,
  decodeWorkspace,
} from "./wire.js";

/** Where the section's text comes from, which its source line names. */
export type ApplicationSource =
  /** The current draft, which the team still edits. */
  | "draft"
  /** The workspace as it was submitted. */
  | "submitted"
  /** The workspace as last saved, of a proposal withdrawn before or after submission. */
  | "withdrawn";

/** What the section reads for one viewer, decided before any call. */
export interface ApplicationPlan {
  /** Whether the section reads the workspace. False means no section. */
  readonly workspace: boolean;
  /** Whether the section reads the plan the team recorded. */
  readonly plan: boolean;
  /** Whether the section reads the stage 2 questions and answers. */
  readonly stage2: boolean;
  readonly source: ApplicationSource;
  /** Whether the section links the workspace to edit it (DRAFT only). */
  readonly edit: boolean;
}

/**
 * The reads of the section for a viewer of `role` on a proposal in
 * `state`. Pure. The team reads the workspace in every state, the former
 * team included once the proposal ended. The plan is read in every state
 * and stage 2 from stage 2 on, except by a guardian once the proposal
 * ended. A viewer with no team role reads nothing (SA-09 rule 7).
 */
export function applicationPlan(role: ProposalRole | undefined, state: ProposalState): ApplicationPlan {
  const team = teamReadsOffered(role);
  const formerGuardian = role === "guardian" && isTerminal(state);
  const source: ApplicationSource = state === "DRAFT" ? "draft" : state === "WITHDRAWN" ? "withdrawn" : "submitted";
  return Object.freeze({
    workspace: team,
    plan: team && !formerGuardian,
    stage2: team && stage2Readable(state) && !formerGuardian,
    source,
    edit: team && state === "DRAFT",
  });
}

/** The questions of the workspace form, in its order, with their read-only labels. */
export const APPLICATION_QUESTIONS: readonly (readonly [keyof Workspace, string])[] = Object.freeze([
  ["title", "application.q.title"],
  ["summary", "application.q.summary"],
  ["narrative", "application.q.narrative"],
] as const);

/** One answer: its text as a text node, or a note that it is empty. */
function answer(text: string): HTMLElement {
  return text.trim() === ""
    ? h("dd", { class: "fstp-answer fstp-answer--empty" }, [h("em", {}, [t("application.empty")])])
    : h("dd", { class: "fstp-answer fstp-text" }, [text]);
}

/** The questions and answers of the workspace, in the order of the form. */
export function answerList(w: Workspace): HTMLElement {
  const items: HTMLElement[] = [];
  for (const [key, label] of APPLICATION_QUESTIONS) {
    items.push(h("dt", { class: "fstp-question" }, [t(label)]), answer(w[key]));
  }
  return h("dl", { id: "application-answers", class: "fstp-answers" }, items);
}

/** One of the team's stage 2 answers, as text, with the day it was given. */
function stage2Answer(a: Stage2Answer): HTMLElement {
  return h("div", { class: "fstp-stage2-answer" }, [
    h("p", { class: "fstp-meta" }, [t("application.stage2.answered"), " ", dayTime(a.answered)]),
    h("p", { class: "fstp-text" }, [a.text]),
  ]);
}

/**
 * The stage 2 part: each question asked, and under it the team's own
 * answers given after it and before the next question. An answer given
 * before any question follows the list, so none is dropped.
 */
export function stage2Part(thread: Stage2Thread): HTMLElement {
  const { questions, answers } = thread;
  const under = (n: number): HTMLElement[] => answers.filter((a) => a.after === n).map(stage2Answer);
  const body: HTMLElement[] =
    questions.length === 0
      ? [h("p", {}, [t("stage2.none")])]
      : [
          h(
            "ol",
            { id: "application-stage2-questions", class: "fstp-list" },
            questions.map((q: Question, i: number) =>
              h("li", {}, [
                h("p", { class: "fstp-meta" }, [t("stage2.from", { handle: q.handle }), " ", t("stage2.asked"), " ", dayTime(q.asked)]),
                h("p", { class: "fstp-text" }, [q.text]),
                ...under(i + 1),
              ]),
            ),
          ),
        ];
  const before = under(0);
  if (before.length > 0) {
    body.push(h("div", { id: "application-stage2-other" }, before));
  }
  if (answers.length === 0) {
    body.push(h("p", { id: "application-stage2-answers" }, [t("application.stage2.answers")]));
  }
  return h("section", { id: "application-stage2", "aria-labelledby": "application-stage2-heading" }, [
    h("h3", { id: "application-stage2-heading" }, [t("application.stage2.heading")]),
    ...body,
  ]);
}

/**
 * The plan part: each task with its milestones, their amounts and days,
 * the total the cell summed, and the work plan text as text. The browser
 * computes no money (ADR-006).
 */
export function planPart(plan: PlanRead | null): HTMLElement {
  const body: HTMLElement[] = [];
  if (plan === null) {
    body.push(h("p", { id: "application-plan-none" }, [t("application.plan.none")]));
  } else {
    body.push(h("p", { id: "application-plan-origin", class: "fstp-meta" }, [t(`application.plan.origin.${plan.origin}`)]));
    body.push(
      h(
        "ol",
        { id: "application-plan-tasks", class: "fstp-list" },
        plan.tasks.map((ms, i) =>
          h("li", {}, [
            h("p", {}, [t("plan.task", { task: String(i + 1) })]),
            h(
              "ul",
              { class: "fstp-items" },
              ms.map((m, j) =>
                h("li", { class: "fstp-plan-milestone" }, [
                  t("application.plan.milestone", { milestone: String(j + 1), amount: m.amount }),
                  " ",
                  dayTime(m.start),
                  " ",
                  t("application.plan.until"),
                  " ",
                  dayTime(m.due),
                ]),
              ),
            ),
          ]),
        ),
      ),
    );
    if (plan.total !== undefined) {
      body.push(h("p", { id: "application-plan-total" }, [t("application.plan.total", { amount: plan.total })]));
    }
    body.push(h("h4", { id: "application-plan-text-heading" }, [t("plan.description")]));
    // ADR-007: an erased text reads as erased, never as a missing one.
    body.push(
      plan.textErased !== undefined
        ? h("p", { id: "application-plan-text-erased" }, [t("application.plan.text_erased"), " ", dayTime(plan.textErased)])
        : plan.text === undefined
          ? h("p", { id: "application-plan-text-missing" }, [t("application.plan.text_missing")])
          : plan.text.trim() === ""
            ? h("p", { id: "application-plan-text" }, [h("em", {}, [t("application.empty")])])
            : h("p", { id: "application-plan-text", class: "fstp-text" }, [plan.text]),
    );
  }
  return h("section", { id: "application-plan", "aria-labelledby": "application-plan-heading" }, [
    h("h3", { id: "application-plan-heading" }, [t("application.plan.heading")]),
    ...body,
  ]);
}

/** What the section shows: the reads' values, or why one gave none. */
export interface ApplicationData {
  readonly workspace: Outcome<Workspace> | null;
  readonly plan: Outcome<{ readonly plan: PlanRead | null }> | null;
  readonly stage2: Outcome<Stage2Thread> | null;
}

/** A part whose read failed: its heading and the reason, inside the section. */
function failedPart(id: string, heading: string, failure: Parameters<typeof failureText>[0]): HTMLElement {
  return h("section", { id, "aria-labelledby": `${id}-heading` }, [
    h("h3", { id: `${id}-heading` }, [t(heading)]),
    h("p", { id: `${id}-error` }, [failureText(failure)]),
  ]);
}

/**
 * The section of proposal `p`, or null when the plan reads nothing. A
 * failed read shows its reason inside the section, so the rest of the
 * proposal page still loads.
 */
export function applicationSection(p: ProposalInfo, plan: ApplicationPlan, data: ApplicationData): HTMLElement | null {
  if (!plan.workspace || data.workspace === null) {
    return null;
  }
  const parts: HTMLElement[] = [
    h("h2", { id: "application-heading" }, [t("application.heading")]),
    h("p", { id: "application-source" }, [t(`application.source.${plan.source}`)]),
  ];
  if (plan.edit) {
    parts.push(h("p", {}, [h("a", { id: "application-edit", href: APP.workspace(p.proposal) }, [t("application.edit")])]));
  }
  const w = data.workspace;
  parts.push(w.ok ? answerList(w.value) : h("p", { id: "application-error" }, [failureText(w.failure)]));
  const pl = data.plan;
  if (plan.plan && pl !== null) {
    parts.push(pl.ok ? planPart(pl.value.plan) : failedPart("application-plan", "application.plan.heading", pl.failure));
  }
  const s = data.stage2;
  if (plan.stage2 && s !== null) {
    parts.push(s.ok ? stage2Part(s.value) : failedPart("application-stage2", "application.stage2.heading", s.failure));
  }
  if (isTerminal(p.state)) {
    parts.push(h("p", { id: "application-copy" }, [t("application.copy")]));
  }
  return h("section", { id: "proposal-application", "aria-labelledby": "application-heading" }, parts);
}

/** The applicant call the section makes, injectable for tests. */
export type ApplicationCall = <T>(
  name: "proposal.get_workspace" | "proposal.get_plan" | "stage2.view",
  params: Readonly<Record<string, string>>,
  decode: (v: unknown) => T | null,
) => Promise<Outcome<T>>;

/** Makes the reads `plan` names for proposal `p`, and only those. */
export async function loadApplication(p: ProposalInfo, plan: ApplicationPlan, call: ApplicationCall): Promise<ApplicationData> {
  const params = { proposal: p.proposal };
  const workspace = plan.workspace ? await call("proposal.get_workspace", params, decodeWorkspace) : null;
  const planRead = plan.plan ? await call("proposal.get_plan", params, decodePlan) : null;
  const stage2 = plan.stage2 ? await call("stage2.view", params, decodeStage2Thread) : null;
  return Object.freeze({ workspace, plan: planRead, stage2 });
}
