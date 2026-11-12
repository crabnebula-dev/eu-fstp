// "Knock-out criteria", `/app/programmes/{p}/studio/knock-outs` (lane
// m4/fast-flow; `SPEC/02-domain/roles-and-sod.md` roles table; R-EV-01,
// R-PC-03, I-12).
//
// - The call drafter writes the knock-out criteria (P-09). A programme
//   manager may too. The FSTP coordinator, who runs the check, never
//   holds either role in the same programme (SoD-01), so the person who
//   writes the criteria is never the person who applies them.
// - The page reads the criteria from `creator.get_draft`, each text as
//   the server shows it, and saves them through `creator.save_fields`
//   with this one field. The server stores each text as a public text
//   (ADR-007) and decides the save again: it refuses any other field
//   from a call drafter.
// - On an active programme a save makes a new policy version. A call
//   approved before it returns to DRAFT, and the next published call
//   freezes the new criteria (R-PC-03 NOTE, I-12). The page says so
//   before the save.
//
// Every state comes from a server read, and a refusal shows in the
// page alert with its rule.

import { h } from "../core/dom.js";
import { clearProblems, fieldEditor, showProblems, type FieldEditor } from "../creator/editor.js";
import { fieldOf } from "../creator/fields.js";
import { busy, frame, hush, ready, statusRegion, warn } from "../creator/frame.js";
import { t } from "../creator/i18n.js";
import { draftValue, type Draft } from "../creator/model.js";
import { anyObject, call, report } from "../creator/ops.js";
import { link, loadDraft } from "../creator/pages/common.js";
import { afterApprovalNote } from "./view.js";

/** The field key of P-09. */
export const KNOCK_OUTS = "evaluation.p09_knock_outs";

/** Mounts "Knock-out criteria" of programme `p`. */
export function mountKnockOuts(p: string): void {
  const def = fieldOf(KNOCK_OUTS);
  const { main, alert } = frame({ title: t.label("studio.knock_outs.title"), alertId: "knock-outs-error" });
  if (def === null) return;
  const box = h("div", { id: "knock-outs-field" });
  const status = statusRegion("knock-outs-status");
  const save = h("button", { id: "knock-outs-save", type: "button", class: "fstp-primary" }, [t.label("studio.knock_outs.save")]);
  main.append(
    h("p", { id: "knock-outs-programme" }, [t.label("studio.knock_outs.programme", { programme: p })]),
    h("p", {}, [t.label("studio.knock_outs.intro")]),
    h("p", { "data-note": "separation" }, [t.label("studio.knock_outs.separation")]),
    box,
    h("div", { class: "fstp-actions" }, [save]),
    status,
    h("p", {}, [link("/app/", t.label("studio.knock_outs.home"))]),
  );
  let draft: Draft | null = null;
  let editor: FieldEditor | null = null;

  const render = (d: Draft): void => {
    clearProblems(box);
    editor = fieldEditor(def, draftValue(d, KNOCK_OUTS), { mark: true, prefix: "ko" });
    const note = afterApprovalNote(KNOCK_OUTS, d.status);
    if (note !== null) editor.notes.append(note);
    box.replaceChildren(editor.root);
  };

  save.addEventListener(
    "click",
    busy(save, async () => {
      const d = draft;
      const e = editor;
      if (d === null || e === null) return;
      hush(alert);
      status.removeAttribute("data-state");
      status.textContent = t.label("studio.knock_outs.saving");
      clearProblems(box);
      const r = e.read();
      if (!r.ok) {
        warn(alert, t.label("creator.step.problems"));
        status.setAttribute("data-state", "invalid");
        status.textContent = "";
        showProblems(r.problems);
        return;
      }
      const o = await call("creator.save_fields", [p], { base: d.revision, fields: [{ field: KNOCK_OUTS, value: r.value }] }, anyObject);
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
      status.textContent = t.label(fresh.status === "active" ? "studio.knock_outs.saved_active" : "studio.knock_outs.saved");
      status.setAttribute("data-state", "saved");
    }),
  );

  void (async () => {
    const d = await loadDraft(p, alert);
    if (d === null) return;
    draft = d;
    render(d);
    ready(main);
  })();
}
