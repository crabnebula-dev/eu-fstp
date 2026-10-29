// The IRC pages (J8, M4 design section 2.2; lane W4c): the member's IRC
// cases, the declaration before reading, the case and the verdict.
//
// - R-CF-02: IRC review is among the acts a conflict bars, so the member
//   declares before reading the nominated proposal.
//   A conflict found while reading is declared on the active
//   assignment, which releases it (I-03).
// - R-IR-03: the case shows the nominated proposal and its outcome, and
//   nothing of the committee's work. The page names no such field, and
//   its check refuses a case that carries one.
// - R-IR-01: the member validates or raises a concern, with no preset.
// - R-IR-02: a concern carries its text, which goes to the applicant.
// - I-17: no identity attribute of the applicant reaches these pages.

import { h, type Child } from "../core/dom.js";
import type { I18n, Label } from "../core/i18n.js";
import {
  FormErrors,
  buttonEl,
  declarationBody,
  declarationForm,
  declarationViewSection,
  formEl,
  frame,
  guarded,
  idRoute,
  isAssignmentSummary,
  isDeclarationView,
  laterDeclarationSection,
  list,
  ownAssignment,
  pageI18n,
  paragraphs,
  proposalName,
  radio,
  readOp,
  textArea,
  whileBusy,
  writeOp,
  type AssignmentSummary,
  type Frame,
  type JudgingPage,
  type PageEnv,
} from "../reviewer/kit.js";
import { readVerdict } from "./forms.js";
import { IRC_LABELS } from "./messages.en.js";
import { isIrcCase, type IrcCase } from "./models.js";

function statusOf(t: I18n, s: AssignmentSummary): Label {
  if (s.awaiting_declaration) {
    return t.label("irc.list.awaiting");
  }
  return s.active ? t.label("irc.list.active") : t.label("irc.list.inactive");
}

async function mountMyCases(env: PageEnv): Promise<void> {
  const t = pageI18n(env, IRC_LABELS);
  const f = frame(env, t, t.label("irc.list.title"));
  await guarded(f, async () => {
    const mine = await readOp(env, "me.irc_cases", {}, list(isAssignmentSummary));
    if (!mine.ok) {
      f.problem(mine.problem);
      f.show([]);
      return;
    }
    const rows = mine.data.filter((s) => s.kind === "irc");
    if (rows.length === 0) {
      f.show([h("p", {}, [t.label("irc.list.none")])]);
      return;
    }
    f.show([
      h("table", { id: "irc-cases-table" }, [
        h("caption", {}, [t.label("irc.list.caption")]),
        h("thead", {}, [
          h(
            "tr",
            {},
            ["irc.list.col_proposal", "irc.list.col_status", "irc.list.col_case"].map((id) =>
              h("th", { scope: "col" }, [t.label(id)]),
            ),
          ),
        ]),
        h(
          "tbody",
          {},
          rows.map((s) =>
            h("tr", { "data-assignment": s.assignment }, [
              h("th", { scope: "row" }, [proposalName(t, s.proposal)]),
              h("td", {}, [statusOf(t, s)]),
              h("td", {}, [
                h("a", { href: `/app/irc-assignments/${s.assignment}` }, [t.label("irc.list.open", { id: s.proposal })]),
              ]),
            ]),
          ),
        ),
      ]),
    ]);
  });
}

function caseSection(t: I18n, c: IrcCase): HTMLElement {
  return h("section", { id: "irc-case", "aria-labelledby": "irc-case-heading" }, [
    h("h2", { id: "irc-case-heading" }, [t.label("irc.case.heading")]),
    h("p", { id: "irc-outcome", "data-outcome": c.outcome }, [t.label(`irc.case.outcome.${c.outcome}`)]),
    h("h3", {}, [c.title]),
    ...paragraphs(c.text),
  ]);
}

function verdictForm(
  env: PageEnv,
  t: I18n,
  f: Frame,
  assignment: string,
  rerender: () => Promise<void>,
): HTMLFormElement {
  const validate = radio("verdict-validate", "verdict", "validate", t.label("irc.verdict.validate"));
  const concern = radio("verdict-concern", "verdict", "concern", t.label("irc.verdict.concern"));
  const text = textArea("concern-text", t.label("irc.verdict.concern_text"));
  const legend = h("legend", {}, [t.label("irc.verdict.legend")]);
  const submit = buttonEl("verdict-submit", "submit", t.label("irc.verdict.submit"));
  const form = formEl("verdict-form", [h("fieldset", {}, [legend, validate.root, concern.root]), text.root, submit]);
  const errors = new FormErrors(form, "verdict-errors", t);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void guarded(f, () =>
      whileBusy(submit, async () => {
        const read = readVerdict({
          verdict: validate.control.checked ? "validate" : concern.control.checked ? "concern" : null,
          concern: text.control.value,
        });
        if (!read.ok) {
          errors.show(
            read.errors.map((e) =>
              e.field === "concern"
                ? { control: text.control, message: t.label("irc.verdict.err_concern") }
                : { control: validate.control, message: t.label("irc.verdict.err_verdict"), after: legend },
            ),
          );
          return;
        }
        errors.clear();
        f.clearAlert();
        const v = read.value;
        const body =
          v.verdict === "validate" ? { verdict: { type: "Validate" } } : { verdict: { type: "Concern", concern: v.concern } };
        const answer = await writeOp(env, "irc.review", { irc_assignment: assignment }, body);
        if (!answer.ok) {
          f.problem(answer.problem);
          return;
        }
        f.status(v.verdict === "validate" ? t.label("irc.verdict.validated") : t.label("irc.verdict.raised"));
        await rerender();
      }),
    );
  });
  return form;
}

/**
 * The form to declare a conflict found while reading the case (R-CF-02,
 * I-03). A declared conflict releases the IRC assignment, so the page
 * then shows no case and no verdict form.
 */
function declareLater(env: PageEnv, t: I18n, f: Frame, s: AssignmentSummary): HTMLElement {
  return laterDeclarationSection(
    t,
    f,
    (d) => writeOp(env, "irc.declare", { irc_assignment: s.assignment }, declarationBody(d)),
    async () => {
      f.show([]);
    },
  );
}

/**
 * Reads the case and shows it on an active IRC assignment, with the
 * verdict form while the proposal is in IRC review. The form to declare
 * a conflict found while reading stays with the case.
 */
async function showCase(env: PageEnv, t: I18n, f: Frame, s: AssignmentSummary, after: IrcCase | null): Promise<void> {
  const later = declareLater(env, t, f, s);
  const read = await readOp(env, "irc.case", { irc_assignment: s.assignment }, isIrcCase);
  if (!read.ok) {
    if (after === null) {
      f.problem(read.problem);
      f.show([later]);
    } else {
      // The verdict is recorded. The case as read before it stays on the page.
      f.show([caseSection(t, after), later]);
    }
    return;
  }
  const c = read.data;
  f.state(c.state);
  const parts: Child[] = [caseSection(t, c)];
  if (c.state === "IRC_REVIEW") {
    parts.push(verdictForm(env, t, f, s.assignment, () => showCase(env, t, f, s, c)));
  }
  parts.push(later);
  f.show(parts);
}

async function mountCase(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, IRC_LABELS);
  const id = params["irc_assignment"] ?? "";
  const f = frame(env, t, t.label("irc.case.loading"));
  await guarded(f, async () => {
    const s = await ownAssignment(env, t, f, "me.irc_cases", id, "irc");
    if (s === null) {
      return;
    }
    f.retitle(t.label("irc.case.title", { id: s.proposal }));
    if (!s.awaiting_declaration) {
      if (s.active) {
        await showCase(env, t, f, s, null);
      } else {
        f.show([h("p", {}, [t.label("kit.inactive")])]);
      }
      return;
    }
    const view = await readOp(env, "review.declaration_view", { proposal: s.proposal }, isDeclarationView);
    const before: Child[] = [];
    if (view.ok) {
      before.push(declarationViewSection(t, view.data));
    } else {
      f.problem(view.problem);
    }
    before.push(
      declarationForm(
        t,
        f,
        (d) => writeOp(env, "irc.declare", { irc_assignment: s.assignment }, declarationBody(d)),
        async (d) => {
          if (d.conflicted) {
            // R-CF-02: a declared conflict bars IRC review.
            f.show([]);
            return;
          }
          f.busy();
          await showCase(env, t, f, s, null);
        },
      ),
    );
    f.show(before);
  });
}

/** The IRC pages (J8). */
export const IRC_PAGES: readonly JudgingPage[] = [
  { route: idRoute("irc.cases", "/app/me/irc-cases", []), mount: (env) => mountMyCases(env) },
  { route: idRoute("irc.case", "/app/irc-assignments/{irc_assignment}", ["irc_assignment"]), mount: mountCase },
];
