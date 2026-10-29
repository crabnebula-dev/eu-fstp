// A creator step page, `/app/programmes/{p}/creator/{step}` for steps 1
// to 10 (R-PG-01, TH-49; M4 design sections 2.2 J1 and 3.2).
//
// - Each field of the step is one `[data-field]` editor, showing the
//   draft value.
// - Template narrative that is not accepted yet is shown as editable text
//   with `[data-action="accept-narrative"]`. It is never applied
//   silently: until a person accepts or edits it, the draft holds no
//   value for the field (`programme-creator.md`, Template library).
// - `#creator-step-save` sends only the fields a person changed, as one
//   `creator.save_fields` against the current revision. The step's check
//   results then show in `#creator-step-checks`, and
//   `#creator-step-status` carries `data-state="saved"`.
// - Step 9 also holds the invitations of the People step.

import { h } from "../../core/dom.js";
import { inviteSection } from "../../people/invite.js";
import { clearProblems, fieldEditor, showProblems, type FieldEditor, type Problem } from "../editor.js";
import { fieldsOf } from "../fields.js";
import { busy, frame, hush, ready, statusRegion, warn } from "../frame.js";
import { labelOr, t } from "../i18n.js";
import { CREATOR_STEPS, canonicalJson, draftValue, nextStep, stepOfResult, type Draft } from "../model.js";
import { anyObject, call, report } from "../ops.js";
import { PATHS, checkText, link, loadDraft, loadReport, queue, stepNav, stepTitle } from "./common.js";

/** One field on the page. */
interface Shown {
  readonly key: string;
  readonly editor: FieldEditor;
  /** Whether the draft holds template narrative for it that awaits acceptance. */
  pending: boolean;
}

/** Mounts step page `step` of programme `p`. */
export function mount(p: string, step: string): void {
  const s = CREATOR_STEPS.find((x) => x.id === step);
  if (s === undefined) return;
  const { main, alert } = frame({ title: stepTitle(s), alertId: "creator-error", nav: stepNav(p, step) });
  const fieldsBox = h("div", { id: "creator-fields" });
  const status = statusRegion("creator-step-status");
  const checks = h("ul", { id: "creator-step-checks", "aria-label": t.label("creator.step.checks") });
  const write = queue();
  let draft: Draft | null = null;
  let shown: Shown[] = [];

  const render = (d: Draft): void => {
    clearProblems(fieldsBox);
    shown = fieldsOf(step).map((f) => {
      const pendingText = Object.hasOwn(d.pendingNarratives, f.key) ? d.pendingNarratives[f.key] : undefined;
      const value = pendingText ?? draftValue(d, f.key);
      const editor = fieldEditor(f, value, { mark: true, prefix: `f.${f.key}` });
      const item: Shown = { key: f.key, editor, pending: pendingText !== undefined };
      if (item.pending) {
        addAccept(item);
      }
      return item;
    });
    fieldsBox.replaceChildren(...shown.map((x) => x.editor.root));
  };

  /** The template note and the accept button of a pending narrative. */
  const addAccept = (item: Shown): void => {
    const note = h("p", { class: "fstp-note" }, [t.label("creator.narrative.pending")]);
    const accept = h("button", { type: "button", "data-action": "accept-narrative" }, [t.label("creator.narrative.accept")]);
    accept.addEventListener("click", () => {
      // The button leaves at once, so it cannot be pressed twice.
      accept.remove();
      note.textContent = t.label("creator.narrative.accepting");
      void write(async () => {
        const d = draft;
        if (d === null) return;
        hush(alert);
        const o = await call("creator.accept_narrative", [p], { base: d.revision, field: item.key }, anyObject);
        if (report(alert, o)) {
          note.textContent = t.label("creator.narrative.pending");
          item.editor.notes.append(accept);
          return;
        }
        const fresh = await loadDraft(p, alert);
        if (fresh !== null) {
          draft = fresh;
        }
        item.pending = false;
        note.textContent = t.label("creator.narrative.accepted");
      });
    });
    item.editor.notes.append(note, accept);
  };

  /** The fields a person changed, or the problems of what they entered. */
  const changes = (): { readonly fields: { field: string; value: unknown }[]; readonly problems: Problem[] } => {
    const fields: { field: string; value: unknown }[] = [];
    const problems: Problem[] = [];
    for (const x of shown) {
      if (!x.editor.touched()) continue;
      const r = x.editor.read();
      if (!r.ok) {
        problems.push(...r.problems);
      } else if (canonicalJson(r.value) !== x.editor.initial || x.pending) {
        fields.push({ field: x.key, value: r.value });
      }
    }
    return { fields, problems };
  };

  const showChecks = async (): Promise<void> => {
    const r = await loadReport(p, alert);
    const mine = r === null ? [] : r.results.filter((x) => stepOfResult(x) === step);
    checks.replaceChildren(
      ...mine.map((x) =>
        h("li", { "data-check": x.check, "data-severity": x.severity }, [
          h("strong", {}, [x.severity === "failure" ? t.label("creator.severity.failure") : t.label("creator.severity.warning")]),
          " ",
          checkText(x.check, x.values, x.field),
        ]),
      ),
    );
    if (mine.length === 0) {
      checks.append(h("li", {}, [t.label("creator.step.no_checks")]));
    }
  };

  const save = h("button", { id: "creator-step-save", type: "button", class: "fstp-primary" }, [t.label("creator.step.save")]);
  save.addEventListener(
    "click",
    busy(save, () =>
      write(async () => {
        const d = draft;
        if (d === null) return;
        hush(alert);
        status.removeAttribute("data-state");
        status.textContent = t.label("creator.step.saving");
        clearProblems(fieldsBox);
        const { fields, problems } = changes();
        if (problems.length > 0) {
          warn(alert, t.label("creator.step.problems"));
          status.setAttribute("data-state", "invalid");
          status.textContent = "";
          showProblems(problems);
          return;
        }
        if (fields.length > 0) {
          const o = await call("creator.save_fields", [p], { base: d.revision, fields }, anyObject);
          if (report(alert, o)) {
            status.setAttribute("data-state", "refused");
            status.textContent = "";
            return;
          }
          const fresh = await loadDraft(p, alert);
          if (fresh === null) {
            status.setAttribute("data-state", "refused");
            status.textContent = "";
            return;
          }
          draft = fresh;
          render(fresh);
        }
        await showChecks();
        status.textContent = t.label("creator.step.saved");
        status.setAttribute("data-state", "saved");
      }),
    ),
  );

  const after = nextStep(step);
  const nav = h("div", { class: "fstp-actions" }, [save]);
  if (after !== null) {
    nav.append(link(PATHS.step(p, after), t.label("creator.step.next"), { id: "creator-step-next" }));
  }
  main.append(h("p", {}, [labelOr(`creator.intro.${step}`, () => t.label("creator.step.intro"))]), fieldsBox);
  if (step === "people") {
    main.append(inviteSection(p, alert));
  }
  main.append(nav, status, h("h2", {}, [t.label("creator.step.checks")]), checks);

  void write(async () => {
    const d = await loadDraft(p, alert);
    if (d === null) return;
    draft = d;
    render(d);
    ready(main);
  });
}
