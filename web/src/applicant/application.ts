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
// Stage 2. Once the proposal reached stage 2 the section reads the stage
// 2 questions (`stage2.view`) under their own heading. That read gives the
// questions only. The team has no read of its own stage 2 answers, so
// the section says that the answers are not shown here. A former guardian
// has no stage 2 read (`ReadRule::FormerTeam` names the lead and the
// members only), so the section never calls it for one (SA-09 rule 7).
//
// Rendering. Every answer is untrusted submission content. It reaches the
// page only as a text node through `h` (ADR-014), never as markup. The
// answers sit in a description list, each under its question, and keep
// their line breaks (`fstp-text`).

import { h } from "../core/dom.js";
import { type Outcome } from "./client.js";
import { type ProposalRole, type ProposalState, isTerminal, stage2Readable, teamReadsOffered } from "./rules.js";
import { APP, dayTime, failureText, t } from "./ui.js";
import { type ProposalInfo, type Question, type Workspace, decodeStage2, decodeWorkspace } from "./wire.js";

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
  /** Whether the section reads the stage 2 questions. */
  readonly stage2: boolean;
  readonly source: ApplicationSource;
  /** Whether the section links the workspace to edit it (DRAFT only). */
  readonly edit: boolean;
}

/**
 * The reads of the section for a viewer of `role` on a proposal in
 * `state`. Pure. The team reads the workspace in every state, the former
 * team included once the proposal ended. Stage 2 is read from stage 2 on,
 * except by a guardian once the proposal ended. A viewer with no team
 * role reads nothing (SA-09 rule 7).
 */
export function applicationPlan(role: ProposalRole | undefined, state: ProposalState): ApplicationPlan {
  const team = teamReadsOffered(role);
  const source: ApplicationSource = state === "DRAFT" ? "draft" : state === "WITHDRAWN" ? "withdrawn" : "submitted";
  return Object.freeze({
    workspace: team,
    stage2: team && stage2Readable(state) && !(role === "guardian" && isTerminal(state)),
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

/** The stage 2 part: the questions asked, and that the answers are not shown here. */
export function stage2Part(questions: readonly Question[]): HTMLElement {
  const body: HTMLElement[] =
    questions.length === 0
      ? [h("p", {}, [t("stage2.none")])]
      : [
          h(
            "ol",
            { id: "application-stage2-questions", class: "fstp-list" },
            questions.map((q) =>
              h("li", {}, [
                h("p", { class: "fstp-meta" }, [t("stage2.from", { handle: q.handle }), " ", t("stage2.asked"), " ", dayTime(q.asked)]),
                h("p", { class: "fstp-text" }, [q.text]),
              ]),
            ),
          ),
        ];
  return h("section", { id: "application-stage2", "aria-labelledby": "application-stage2-heading" }, [
    h("h3", { id: "application-stage2-heading" }, [t("application.stage2.heading")]),
    ...body,
    h("p", { id: "application-stage2-answers" }, [t("application.stage2.answers")]),
  ]);
}

/** What the section shows: the reads' values, or why one gave none. */
export interface ApplicationData {
  readonly workspace: Outcome<Workspace> | null;
  readonly stage2: Outcome<readonly Question[]> | null;
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
  const s = data.stage2;
  if (plan.stage2 && s !== null) {
    parts.push(
      s.ok
        ? stage2Part(s.value)
        : h("section", { id: "application-stage2", "aria-labelledby": "application-stage2-heading" }, [
            h("h3", { id: "application-stage2-heading" }, [t("application.stage2.heading")]),
            h("p", { id: "application-stage2-error" }, [failureText(s.failure)]),
          ]),
    );
  }
  if (isTerminal(p.state)) {
    parts.push(h("p", { id: "application-copy" }, [t("application.copy")]));
  }
  return h("section", { id: "proposal-application", "aria-labelledby": "application-heading" }, parts);
}

/** The applicant call the section makes, injectable for tests. */
export type ApplicationCall = <T>(
  name: "proposal.get_workspace" | "stage2.view",
  params: Readonly<Record<string, string>>,
  decode: (v: unknown) => T | null,
) => Promise<Outcome<T>>;

/** Makes the reads `plan` names for proposal `p`, and only those. */
export async function loadApplication(p: ProposalInfo, plan: ApplicationPlan, call: ApplicationCall): Promise<ApplicationData> {
  const params = { proposal: p.proposal };
  const workspace = plan.workspace ? await call("proposal.get_workspace", params, decodeWorkspace) : null;
  const stage2 = plan.stage2 ? await call("stage2.view", params, decodeStage2) : null;
  return Object.freeze({ workspace, stage2 });
}
