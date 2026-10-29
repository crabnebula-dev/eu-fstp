// The private workspace (`proposal.get_workspace`,
// `proposal.save_workspace`; journey J4, I-21).
//
// Only the team reads the workspace, and the draft goes to the workspace
// route and to no other. Every edit is saved through `autosave.ts`: at
// most one save in flight, the latest text last, and a failed save kept
// on the page for the next attempt.

import { h } from "../core/dom.js";
import { type AutosaveStatus, createAutosave } from "./autosave.js";
import { call } from "./client.js";
import { loadProposal } from "./load.js";
import { draftEditable, teamReadsOffered } from "./rules.js";
import { APP, button, frame, run, setStatus, showFailure, statusRegion, t, textArea, textInput } from "./ui.js";
import { decodeAccepted, decodeWorkspace } from "./wire.js";

/**
 * The longest neutral summary. Interim, pending Daniel (Q9 A): the
 * summary is short, since reviewers read it before they declare.
 */
export const SUMMARY_MAX = 500;
/** The longest title. Interim, pending Daniel. */
export const TITLE_MAX = 200;
/** The pause after the last keystroke before a save starts, in milliseconds. */
const AUTOSAVE_DELAY_MS = 600;

/** Mounts the workspace of proposal `id`. */
export function mountWorkspace(id: string): void {
  const f = frame(t("workspace.title"));
  f.main.append(h("p", {}, [h("a", { href: APP.proposal(id) }, [t("proposal.back")])]));
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    if (!teamReadsOffered(p.role)) {
      f.main.append(h("p", {}, [t("team.only")]));
      return;
    }
    const w = await call("proposal.get_workspace", { proposal: id }, undefined, decodeWorkspace);
    if (!w.ok) {
      showFailure(f, w.failure);
      return;
    }
    if (!draftEditable(p.state)) {
      f.main.append(
        h("p", {}, [t("workspace.readonly")]),
        h("h2", {}, [w.value.title === "" ? t("proposal.untitled") : w.value.title]),
        h("p", { class: "fstp-text" }, [w.value.summary]),
        h("p", { class: "fstp-text" }, [w.value.narrative]),
      );
      return;
    }
    const title = textInput("ws-title", t("ws.title"), { maxlength: TITLE_MAX });
    const summary = textArea("ws-summary", t("ws.summary"), {
      hint: t("ws.summary_hint", { max: String(SUMMARY_MAX) }),
      maxlength: SUMMARY_MAX,
      rows: 4,
    });
    const narrative = textArea("ws-narrative", t("ws.narrative"), { rows: 16 });
    title.control.value = w.value.title;
    summary.control.value = w.value.summary;
    narrative.control.value = w.value.narrative;

    const status = statusRegion("ws-status");
    setStatus(status, "idle", t("ws.status.idle"));
    const retry = button("ws-retry", t("ws.retry"));
    retry.hidden = true;

    const saver = createAutosave<{ readonly title: string; readonly summary: string; readonly narrative: string }>(
      {
        save: async (v) => {
          const r = await call(
            "proposal.save_workspace",
            { proposal: id },
            { narrative: v.narrative, summary: v.summary, title: v.title },
            decodeAccepted,
          );
          return r.ok;
        },
        setTimer: (fn, ms) => window.setTimeout(fn, ms),
        clearTimer: (handle) => {
          window.clearTimeout(handle);
        },
        onStatus: (s: AutosaveStatus) => {
          setStatus(status, s, t(`ws.status.${s}`));
          retry.hidden = s !== "failed";
        },
      },
      AUTOSAVE_DELAY_MS,
    );
    const edited = (): void => {
      saver.edit({ title: title.control.value, summary: summary.control.value, narrative: narrative.control.value });
    };
    for (const c of [title.control, summary.control, narrative.control]) {
      c.addEventListener("input", edited);
    }
    retry.addEventListener("click", () => {
      void saver.flush();
    });
    // A browser usually aborts a request sent while the page unloads, so
    // leaving with an unsaved edit asks the user first. The prompt also
    // starts the save, so staying on the page stores the edit.
    window.addEventListener("beforeunload", (e) => {
      if (saver.unsaved()) {
        void saver.flush();
        e.preventDefault();
      }
    });
    const form = h("form", { novalidate: true, "aria-label": t("workspace.title") }, [
      title.root,
      summary.root,
      narrative.root,
    ]);
    // Enter in the title saves now, and never submits the draft as a query.
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      void saver.flush();
    });
    f.main.append(
      h("p", {}, [t("workspace.intro")]),
      form,
      status,
      h("p", {}, [retry]),
    );
  });
}
