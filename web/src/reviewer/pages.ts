// The assigned reviewers' pages (J6, M4 design section 2.2; lane W4c):
// their assignments, the declaration before reading, the score sheet
// with corrections, the ranking summary and stage 2.
//
// - R-CF-02: the reviewer declares before the full content is read, and
//   sees only the title and the neutral summary until then (Q9).
// - I-03: after a declared conflict the page shows no content and no
//   score sheet. The server refuses both reads anyway.
// - R-CF-02 and I-03: a conflict found while reading is declared on the
//   active assignment, which releases it. The summary and stage 2 pages
//   wait for the declaration and read nothing before it.
// - R-EV-02 and P-01 NOTE 6: one field per criterion, read as an integer
//   from 0 to N by `forms.ts`, never rewritten.
// - I-23: a correction carries its reason.
// - R-EV-05 and NOTE 4: questions or "no questions" in stage 2.

import { isRankingView } from "../committee/models.js";
import { h, type Child } from "../core/dom.js";
import type { I18n, Label } from "../core/i18n.js";
import { readRankingSummary, readScoreCorrection, readScoreSheet, type FieldError } from "./forms.js";
import {
  FormErrors,
  buttonEl,
  contentSection,
  declarationBody,
  declarationForm,
  declarationViewSection,
  formEl,
  frame,
  guarded,
  idRoute,
  isAssignmentSummary,
  isContentView,
  isDeclarationView,
  laterDeclarationSection,
  list,
  ownAssignment,
  pageI18n,
  paragraphs,
  proposalName,
  readOp,
  textArea,
  textField,
  whileBusy,
  writeOp,
  type AssignmentSummary,
  type ContentView,
  type Frame,
  type JudgingPage,
  type PageEnv,
} from "./kit.js";
import { REVIEWER_LABELS } from "./messages.en.js";
import { isScoreSheet, isStage2Thread, type ScoreSheet, type Stage2Thread } from "./models.js";

// ---------------------------------------------------------------------------
// My assignments
// ---------------------------------------------------------------------------

function statusOf(t: I18n, s: AssignmentSummary): Label {
  if (s.awaiting_declaration) {
    return t.label("rev.list.awaiting");
  }
  return s.active ? t.label("rev.list.active") : t.label("rev.list.inactive");
}

async function mountMyAssignments(env: PageEnv): Promise<void> {
  const t = pageI18n(env, REVIEWER_LABELS);
  const f = frame(env, t, t.label("rev.list.title"));
  await guarded(f, async () => {
    const mine = await readOp(env, "me.assignments", {}, list(isAssignmentSummary));
    if (!mine.ok) {
      f.problem(mine.problem);
      f.show([]);
      return;
    }
    const rows = mine.data.filter((s) => s.kind === "reviewer");
    if (rows.length === 0) {
      f.show([h("p", {}, [t.label("rev.list.none")])]);
      return;
    }
    f.show([
      h("table", { id: "assignments-table" }, [
        h("caption", {}, [t.label("rev.list.caption")]),
        h("thead", {}, [
          h("tr", {}, [
            h("th", { scope: "col" }, [t.label("rev.list.col_proposal")]),
            h("th", { scope: "col" }, [t.label("rev.list.col_status")]),
            h("th", { scope: "col" }, [t.label("rev.list.col_pages")]),
          ]),
        ]),
        h(
          "tbody",
          {},
          rows.map((s) =>
            h("tr", { "data-assignment": s.assignment }, [
              h("th", { scope: "row" }, [proposalName(t, s.proposal)]),
              h("td", {}, [statusOf(t, s)]),
              h("td", {}, [
                h("ul", {}, [
                  h("li", {}, [
                    h("a", { href: `/app/assignments/${s.assignment}` }, [t.label("rev.list.open", { id: s.proposal })]),
                  ]),
                  h("li", {}, [
                    h("a", { href: `/app/assignments/${s.assignment}/summary` }, [
                      t.label("rev.list.summary", { id: s.proposal }),
                    ]),
                  ]),
                  // The stage 2 thread opens only while the proposal is in
                  // STAGE2 (review finding U5).
                  ...(s.stage2
                    ? [
                        h("li", {}, [
                          h("a", { href: `/app/assignments/${s.assignment}/stage2` }, [
                            t.label("rev.list.stage2", { id: s.proposal }),
                          ]),
                        ]),
                      ]
                    : []),
                ]),
              ]),
            ]),
          ),
        ),
      ]),
    ]);
  });
}

// ---------------------------------------------------------------------------
// The assignment: declaration, content and score sheet
// ---------------------------------------------------------------------------

type SheetMode = "new" | "scored" | "correct";

/** The message for one score sheet error. */
function sheetError(t: I18n, sheet: ScoreSheet, e: FieldError): Label {
  if (e.field === "reason") {
    return t.label("rev.sheet.err_reason");
  }
  const c = sheet.criteria.find((x) => x.id === e.field);
  const args = { text: c?.text ?? e.field, max: String(c?.max ?? 0) };
  switch (e.reason) {
    case "above_scale":
      return t.label("rev.sheet.err_above_scale", args);
    case "not_an_integer":
      return t.label("rev.sheet.err_not_an_integer", args);
    default:
      return t.label("rev.sheet.err_required", { text: args.text });
  }
}

/**
 * The score sheet, `#score-form`: one text field per P-01 criterion and
 * no other `input`. A recorded score shows read-only until the reviewer
 * starts a correction, which adds the reason field.
 */
function scoreForm(
  env: PageEnv,
  t: I18n,
  f: Frame,
  assignment: string,
  sheet: ScoreSheet,
  mode: SheetMode,
  rerender: (mode: SheetMode) => Promise<void>,
): HTMLElement {
  const fields = sheet.criteria.map((c, i) => {
    const field = textField(`score-${c.id}`, t.label("rev.sheet.criterion", { text: c.text, max: String(c.max) }), {
      inputmode: "numeric",
      spellcheck: "false",
      readonly: mode === "scored",
    });
    const recorded = sheet.current?.values[i];
    if (mode !== "new" && recorded !== undefined) {
      field.control.value = String(recorded);
    }
    return { criterion: c, ...field };
  });
  const children: Child[] = [
    h("h2", { id: "score-heading" }, [t.label(mode === "new" ? "rev.sheet.heading" : "rev.sheet.correct_heading")]),
    h("p", {}, [t.label(`rev.sheet.stage.${sheet.stage}`)]),
    h("p", {}, [t.label("rev.sheet.intro")]),
    ...fields.map((x) => x.root),
  ];
  const reason = mode === "correct" ? textArea("score-reason", t.label("rev.sheet.reason")) : null;
  if (reason !== null) {
    children.push(reason.root);
  }
  const submit =
    mode === "scored"
      ? null
      : buttonEl(
          "score-submit",
          "submit",
          mode === "correct" ? t.label("rev.sheet.correct_submit") : t.label("rev.sheet.submit"),
        );
  const correct = mode === "scored" ? buttonEl("score-correct", "button", t.label("rev.sheet.correct")) : null;
  if (submit !== null) {
    children.push(submit);
  }
  if (correct !== null) {
    children.push(correct);
  }
  const form = formEl("score-form", children);
  form.setAttribute("aria-labelledby", "score-heading");
  const errors = new FormErrors(form, "score-errors", t);
  correct?.addEventListener("click", () => {
    void guarded(f, () => rerender("correct"));
  });
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (submit === null) {
      return;
    }
    void guarded(f, () =>
      whileBusy(submit, async () => {
        const inputs: Record<string, string> = {};
        for (const x of fields) {
          inputs[x.criterion.id] = x.control.value;
        }
        const show = (list: readonly FieldError[]): void => {
          errors.show(
            list.map((e) => {
              const control = e.field === "reason" ? reason?.control : fields.find((x) => x.criterion.id === e.field)?.control;
              return { control: control ?? form, message: sheetError(t, sheet, e) };
            }),
          );
        };
        const current = sheet.current;
        if (mode === "correct" && current !== null && reason !== null) {
          const read = readScoreCorrection(sheet.criteria, inputs, reason.control.value);
          if (!read.ok) {
            show(read.errors);
            return;
          }
          errors.clear();
          f.clearAlert();
          const answer = await writeOp(
            env,
            "review.correct_score",
            { assignment, score: current.score },
            { stage: sheet.stage, values: read.value.values, reason: read.value.reason },
          );
          if (!answer.ok) {
            f.problem(answer.problem);
            return;
          }
          f.status(t.label("rev.sheet.corrected"));
          await rerender("scored");
          return;
        }
        const read = readScoreSheet(sheet.criteria, inputs);
        if (!read.ok) {
          show(read.errors);
          return;
        }
        errors.clear();
        f.clearAlert();
        const answer = await writeOp(
          env,
          "review.score",
          { assignment },
          { stage: sheet.stage, plan: sheet.plan, values: read.value },
        );
        if (!answer.ok) {
          f.problem(answer.problem);
          return;
        }
        f.status(t.label("rev.sheet.recorded"));
        await rerender("scored");
      }),
    );
  });
  return form;
}

/**
 * The form to declare a conflict found while reading (R-CF-02, I-03). A
 * declared conflict releases the assignment, so the page then shows no
 * content and no score sheet.
 */
function declareLater(env: PageEnv, t: I18n, f: Frame, s: AssignmentSummary): HTMLElement {
  return laterDeclarationSection(
    t,
    f,
    (d) => writeOp(env, "review.declare_assignment", { assignment: s.assignment }, declarationBody(d)),
    async () => {
      f.show([]);
    },
  );
}

/**
 * Reads the content and the score sheet and shows both, on an active
 * assignment. The form to declare a conflict found while reading stays
 * with them.
 */
async function showWork(env: PageEnv, t: I18n, f: Frame, s: AssignmentSummary): Promise<void> {
  // A ranked proposal is read through the committee's ranking view, never
  // its content (`visibility.rs`, D11). The ranking of the call names it
  // then, so the page says so and makes no read the route refuses.
  const ranking = await readOp(env, "committee.ranking", { call: s.call }, isRankingView);
  if (ranking.ok && ranking.data.some((r) => r.proposal === s.proposal)) {
    f.state("RANKED");
    f.show([
      h("p", { id: "content-closed" }, [
        t.label("rev.ranked_closed"),
        " ",
        h("a", { href: `/app/calls/${s.call}/ranking` }, [t.label("rev.ranked_link")]),
      ]),
    ]);
    return;
  }
  const later = declareLater(env, t, f, s);
  const content = await readOp(env, "review.read_content", { proposal: s.proposal }, isContentView);
  if (!content.ok) {
    f.problem(content.problem);
    f.show([later]);
    return;
  }
  f.state(content.data.state);
  const view: ContentView = content.data;
  const render = async (wanted: SheetMode | null): Promise<void> => {
    const sheet = await readOp(env, "review.score_sheet", { assignment: s.assignment }, isScoreSheet);
    if (!sheet.ok) {
      f.problem(sheet.problem);
      f.show([contentSection(t, view), later]);
      return;
    }
    // A correction needs a recorded score; without one the sheet is new.
    const mode: SheetMode = sheet.data.current === null ? "new" : (wanted ?? "scored");
    // A recorded score opens the ranking summary (R-EV-08), on its own page.
    const summary =
      sheet.data.current === null
        ? []
        : [
            h("section", { id: "summary-link", "aria-labelledby": "summary-link-heading" }, [
              h("h2", { id: "summary-link-heading" }, [t.label("rev.summary.heading")]),
              h("p", {}, [t.label("rev.summary.lead")]),
              h("p", {}, [
                h("a", { href: `/app/assignments/${s.assignment}/summary` }, [
                  t.label("rev.summary.link", { id: s.proposal }),
                ]),
              ]),
            ]),
          ];
    f.show([
      contentSection(t, view),
      scoreForm(env, t, f, s.assignment, sheet.data, mode, (m) => render(m)),
      ...summary,
      later,
    ]);
  };
  await render(null);
}

async function mountAssignment(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, REVIEWER_LABELS);
  const id = params["assignment"] ?? "";
  const f = frame(env, t, t.label("rev.assignment.loading"));
  await guarded(f, async () => {
    const s = await ownAssignment(env, t, f, "me.assignments", id, "reviewer");
    if (s === null) {
      return;
    }
    f.retitle(t.label("rev.assignment.title", { id: s.proposal }));
    if (!s.awaiting_declaration) {
      if (s.active) {
        await showWork(env, t, f, s);
      } else {
        f.show([h("p", {}, [t.label("kit.inactive")])]);
      }
      return;
    }
    const view = await readOp(env, "review.declaration_view", { proposal: s.proposal }, isDeclarationView);
    if (!view.ok) {
      f.problem(view.problem);
      f.show([]);
      return;
    }
    f.show([
      declarationViewSection(t, view.data),
      declarationForm(
        t,
        f,
        (d) => writeOp(env, "review.declare_assignment", { assignment: s.assignment }, declarationBody(d)),
        async (d) => {
          if (d.conflicted) {
            // I-03: a declared conflict bars the content and every reviewer act.
            f.show([]);
            return;
          }
          f.busy();
          await showWork(env, t, f, s);
        },
      ),
    ]);
  });
}

/**
 * Whether the caller declared no conflict and the assignment is active,
 * so a reviewer act may follow (R-CF-02, I-03). Otherwise the page shows
 * why, with a link to the declaration while one is awaited, and reads
 * nothing more.
 */
function declaredActive(t: I18n, f: Frame, s: AssignmentSummary): boolean {
  if (s.awaiting_declaration) {
    f.show([
      h("p", { id: "declare-first" }, [
        t.label("rev.declare_first"),
        " ",
        h("a", { href: `/app/assignments/${s.assignment}` }, [t.label("rev.declare_first_link", { id: s.proposal })]),
      ]),
    ]);
    return false;
  }
  if (!s.active) {
    f.show([h("p", {}, [t.label("kit.inactive")])]);
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// The ranking summary (R-EV-08)
// ---------------------------------------------------------------------------

async function mountSummary(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, REVIEWER_LABELS);
  const id = params["assignment"] ?? "";
  const f = frame(env, t, t.label("rev.assignment.loading"));
  await guarded(f, async () => {
    const s = await ownAssignment(env, t, f, "me.assignments", id, "reviewer");
    if (s === null) {
      return;
    }
    f.retitle(t.label("rev.summary.title", { id: s.proposal }));
    if (!declaredActive(t, f, s)) {
      return;
    }
    const title = textField("summary-title", t.label("rev.summary.field_title"));
    const neutral = textArea("summary-neutral", t.label("rev.summary.field_neutral"));
    const rationale = textArea("summary-rationale", t.label("rev.summary.field_rationale"));
    const submit = buttonEl("summary-submit", "submit", t.label("rev.summary.submit"));
    const form = formEl("summary-form", [title.root, neutral.root, rationale.root, submit]);
    const errors = new FormErrors(form, "summary-errors", t);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void guarded(f, () =>
        whileBusy(submit, async () => {
          const read = readRankingSummary({
            title: title.control.value,
            neutral_summary: neutral.control.value,
            rationale: rationale.control.value,
          });
          if (!read.ok) {
            errors.show(
              read.errors.map((e) =>
                e.field === "title"
                  ? { control: title.control, message: t.label("rev.summary.err_title") }
                  : e.field === "neutral_summary"
                    ? { control: neutral.control, message: t.label("rev.summary.err_neutral") }
                    : { control: rationale.control, message: t.label("rev.summary.err_rationale") },
              ),
            );
            return;
          }
          errors.clear();
          f.clearAlert();
          const answer = await writeOp(env, "review.ranking_summary", { assignment: s.assignment }, read.value);
          if (!answer.ok) {
            f.problem(answer.problem);
            return;
          }
          f.status(t.label("rev.summary.recorded"));
        }),
      );
    });
    f.show([h("p", {}, [t.label("rev.summary.intro")]), form]);
  });
}

// ---------------------------------------------------------------------------
// Stage 2 (R-EV-05)
// ---------------------------------------------------------------------------

function threadSection(t: I18n, thread: Stage2Thread): HTMLElement {
  const items = thread.entries.map((e) =>
    h("li", {}, [
      h("p", { class: "fstp-thread-author" }, [
        e.kind === "answer"
          ? t.label("rev.stage2.answer")
          : e.author !== null
            ? t.label("rev.stage2.question_by", { author: e.author })
            : t.label("rev.stage2.question"),
      ]),
      ...paragraphs(e.text),
    ]),
  );
  return h("section", { id: "stage2-thread", "aria-labelledby": "stage2-thread-heading" }, [
    h("h2", { id: "stage2-thread-heading" }, [t.label("rev.stage2.thread")]),
    items.length === 0 ? h("p", {}, [t.label("rev.stage2.empty")]) : h("ol", {}, items),
  ]);
}

async function mountStage2(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, REVIEWER_LABELS);
  const id = params["assignment"] ?? "";
  const f = frame(env, t, t.label("rev.assignment.loading"));
  await guarded(f, async () => {
    const s = await ownAssignment(env, t, f, "me.assignments", id, "reviewer");
    if (s === null) {
      return;
    }
    f.retitle(t.label("rev.stage2.title"));
    if (!declaredActive(t, f, s)) {
      return;
    }
    const render = async (): Promise<void> => {
      const thread = await readOp(env, "review.stage2_thread", { assignment: s.assignment }, isStage2Thread);
      if (!thread.ok) {
        f.problem(thread.problem);
        f.show([]);
        return;
      }
      const v = thread.data;
      f.state(v.state);
      const parts: Child[] = [threadSection(t, v)];
      if (v.open) {
        const question = textArea("question-text", t.label("rev.stage2.field_question"));
        const ask = buttonEl("question-submit", "submit", t.label("rev.stage2.ask"));
        const form = formEl("question-form", [question.root, ask]);
        const errors = new FormErrors(form, "question-errors", t);
        form.addEventListener("submit", (ev) => {
          ev.preventDefault();
          void guarded(f, () =>
            whileBusy(ask, async () => {
              const text = question.control.value;
              if (text === "") {
                errors.show([{ control: question.control, message: t.label("rev.stage2.err_question") }]);
                return;
              }
              errors.clear();
              f.clearAlert();
              const answer = await writeOp(env, "stage2.ask", { assignment: s.assignment }, { text });
              if (!answer.ok) {
                f.problem(answer.problem);
                return;
              }
              f.status(t.label("rev.stage2.asked"));
              await render();
            }),
          );
        });
        parts.push(form);
        if (v.own_no_questions) {
          parts.push(h("p", {}, [t.label("rev.stage2.own_none")]));
        } else {
          const none = buttonEl("no-questions", "button", t.label("rev.stage2.no_questions"));
          none.addEventListener("click", () => {
            void guarded(f, () =>
              whileBusy(none, async () => {
                f.clearAlert();
                const answer = await writeOp(env, "stage2.no_questions", { assignment: s.assignment }, {});
                if (!answer.ok) {
                  f.problem(answer.problem);
                  return;
                }
                f.status(t.label("rev.stage2.recorded_none"));
                await render();
              }),
            );
          });
          parts.push(none);
        }
      } else {
        parts.push(h("p", {}, [t.label("rev.stage2.closed")]));
        if (v.state === "STAGE2") {
          const rank = buttonEl("rank-submit", "button", t.label("rev.stage2.rank"));
          rank.addEventListener("click", () => {
            void guarded(f, () =>
              whileBusy(rank, async () => {
                f.clearAlert();
                const answer = await writeOp(env, "review.rank", { assignment: s.assignment }, {});
                if (!answer.ok) {
                  f.problem(answer.problem);
                  return;
                }
                f.status(t.label("rev.stage2.ranked"));
                await render();
              }),
            );
          });
          parts.push(rank);
        }
      }
      f.show(parts);
    };
    await render();
  });
}

/** The assigned reviewers' pages (J6). */
export const REVIEWER_PAGES: readonly JudgingPage[] = [
  { route: idRoute("reviewer.assignments", "/app/me/assignments", []), mount: (env) => mountMyAssignments(env) },
  { route: idRoute("reviewer.assignment", "/app/assignments/{assignment}", ["assignment"]), mount: mountAssignment },
  {
    route: idRoute("reviewer.summary", "/app/assignments/{assignment}/summary", ["assignment"]),
    mount: mountSummary,
  },
  { route: idRoute("reviewer.stage2", "/app/assignments/{assignment}/stage2", ["assignment"]), mount: mountStage2 },
];
