// The import review, `/app/programmes/{p}/creator/imports` (I-65; M4
// design sections 2.2 J1 and 3.3).
//
// Every value a document import proposes is shown with its evidence, as
// text only. It takes effect only when a named programme manager
// confirms or edits it, one proposal at a time. There is no bulk action
// (Q30, interim). A proposal that conflicts with the funder profile is
// flagged, never adjusted, and confirming it needs an explicit
// acknowledgement. The document is untrusted data: nothing from it is
// parsed as markup or followed as a link.

import { h } from "../../core/dom.js";
import { clearProblems, fieldEditor, fieldLabel, firstControl, showProblems } from "../editor.js";
import { fieldOf } from "../fields.js";
import { frame, hush, ready, warn } from "../frame.js";
import { t } from "../i18n.js";
import { canonicalJson, proposalOrder, readProposals, type ProposalRow } from "../model.js";
import { anyObject, call, report } from "../ops.js";
import { PATHS, link, loadDraft, queue } from "./common.js";

/** Mounts the import review of programme `p`. */
export function mount(p: string): void {
  const { main, alert } = frame({ title: t.label("creator.imports.title"), alertId: "creator-error" });
  const list = h("ul", { id: "proposals", "aria-labelledby": "proposals-title" });
  const write = queue();

  /** Sends one resolution against the current revision. */
  const sending = new Set<string>();
  const resolve = (row: ProposalRow, resolution: Readonly<Record<string, unknown>>, acknowledged: boolean): Promise<boolean> => {
    // One resolution per proposal: a second press while one is sent does nothing.
    if (sending.has(row.id)) return Promise.resolve(false);
    sending.add(row.id);
    return new Promise<boolean>((done) => {
      void write(async () => {
        hush(alert);
        const d = await loadDraft(p, alert);
        if (d === null) {
          done(false);
          return;
        }
        const o = await call(
          "import.resolve",
          [p, row.id],
          { base: d.revision, conflict_acknowledged: acknowledged, resolution, shown: row.digest },
          anyObject,
        );
        done(!report(alert, o));
      });
    }).finally(() => {
      sending.delete(row.id);
    });
  };

  const item = (row: ProposalRow): HTMLElement => {
    const def = fieldOf(row.field);
    const shown = typeof row.value === "string" ? row.value : (canonicalJson(row.value) ?? "");
    const li = h("li", { "data-proposal": row.id, "data-field": row.field, "data-flagged": row.flagged ? "true" : "false" }, [
      h("h3", {}, [fieldLabel(row.field)]),
      h("p", {}, [
        t.label("creator.imports.proposed"),
        " ",
        h("code", { "data-role": "value", "data-json": canonicalJson(row.value) ?? "null" }, [shown]),
      ]),
      h("blockquote", { "data-role": "evidence" }, row.evidence.length === 0 ? [t.label("creator.imports.no_evidence")] : row.evidence.map((e) => h("p", {}, [e.text]))),
    ]);
    const state = h("p", { role: "status", class: "fstp-status" });
    const done = (resolution: "confirmed" | "edited" | "dismissed"): void => {
      li.setAttribute("data-resolution", resolution);
      actions.replaceChildren();
      editBox.replaceChildren();
      state.textContent =
        resolution === "confirmed"
          ? t.label("creator.imports.confirmed")
          : resolution === "edited"
            ? t.label("creator.imports.edited")
            : t.label("creator.imports.dismissed");
    };
    const actions = h("div", { class: "fstp-actions" });
    const editBox = h("div", { class: "fstp-edit" });
    if (row.resolution !== null) {
      li.append(state);
      done(row.resolution);
      return li;
    }
    let ack: HTMLElement | null = null;
    if (row.flagged) {
      const id = `ack.${row.id}`;
      ack = h("input", { id, type: "checkbox", "data-role": "conflict-ack" });
      li.append(
        h("p", { class: "fstp-note" }, [t.label("creator.imports.flagged")]),
        h("div", { class: "fstp-check" }, [ack, h("label", { for: id }, [t.label("creator.imports.conflict_ack")])]),
      );
    }
    const acknowledged = (): boolean => ack instanceof HTMLInputElement && ack.checked;
    const needsAck = (): boolean => {
      if (row.flagged && !acknowledged()) {
        warn(alert, t.label("creator.imports.ack_needed"));
        if (ack !== null) ack.focus();
        return true;
      }
      return false;
    };
    const confirm = h("button", { type: "button", "data-action": "confirm" }, [t.label("creator.imports.confirm")]);
    const edit = h("button", { type: "button", "data-action": "edit", "aria-expanded": "false" }, [t.label("creator.imports.edit")]);
    const dismiss = h("button", { type: "button", "data-action": "dismiss" }, [t.label("creator.imports.dismiss")]);
    confirm.addEventListener("click", () => {
      if (needsAck()) return;
      void resolve(row, { kind: "confirm", value: row.value }, acknowledged()).then((ok) => {
        if (ok) done("confirmed");
      });
    });
    dismiss.addEventListener("click", () => {
      void resolve(row, { kind: "dismiss" }, acknowledged()).then((ok) => {
        if (ok) done("dismissed");
      });
    });
    edit.addEventListener("click", () => {
      if (def === null || editBox.childElementCount > 0) return;
      const editor = fieldEditor(def, row.value, { mark: false, prefix: `q.${row.id}` });
      const save = h("button", { type: "button", "data-action": "save-edit" }, [t.label("creator.imports.save_edit")]);
      save.addEventListener("click", () => {
        clearProblems(editBox);
        const r = editor.read();
        if (!r.ok) {
          warn(alert, t.label("creator.step.problems"));
          showProblems(r.problems);
          return;
        }
        if (canonicalJson(r.value) === canonicalJson(row.value)) {
          warn(alert, t.label("creator.imports.edit_same"));
          return;
        }
        if (needsAck()) return;
        void resolve(row, { kind: "edit", value: r.value }, acknowledged()).then((ok) => {
          if (ok) done("edited");
        });
      });
      editBox.replaceChildren(editor.root, save);
      edit.setAttribute("aria-expanded", "true");
      firstControl(editor.root)?.focus();
    });
    actions.append(confirm, edit, dismiss);
    li.append(actions, editBox, state);
    return li;
  };

  main.append(
    h("p", {}, [t.label("creator.imports.intro")]),
    h("h2", { id: "proposals-title" }, [t.label("creator.imports.proposals")]),
    list,
    h("p", {}, [link(PATHS.step(p, "funder"), t.label("creator.imports.to_steps"))]),
  );

  void (async () => {
    const o = await call("import.list", [p], undefined, (v) => readProposals(v) !== null);
    if (report(alert, o) || o.kind !== "done") return;
    const rows = proposalOrder(readProposals(o.body) ?? []);
    list.replaceChildren(...rows.map(item));
    if (rows.length === 0) {
      list.append(h("li", {}, [t.label("creator.imports.none")]));
    }
    ready(main);
  })();
}
