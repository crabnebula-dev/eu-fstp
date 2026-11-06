// The Planning Studio pages (`SPEC/12-journey-ui.md` section 8.2;
// `docs/design/05-programme-staff-studio.md`):
//
// - `/app/programmes/{p}/studio`, "Programme set-up": the five studios
//   with each step's validation state, the starting point, the imported
//   values awaiting confirmation (I-65), the final report, the previews
//   and, once active, the calls a change affects (R-PG-04, I-12).
// - `/app/programmes/{p}/studio/approval`, "Approval and publication",
//   the seal ceremony: activation (I-66, I-67), then the approval and
//   publication of calls (R-PC-03), and the return-to-DRAFT note.
// - `/app/programmes/{p}/studio/guide`: the Guide for Applicants preview
//   of `creator.preview` (R-GA-01), as text blocks, never as markup.
//
// Every state comes from a server read. The server decides each
// command again, and a refusal shows in the page alert with its rule.
//
// Interim, pending Daniel: no read lists a programme's calls in DRAFT
// or APPROVED, and `call.draft` does not name the call it drew. The
// approval page lists the published calls `me.roles` names and takes
// the number of any other call. The lead holds this as a blocker.

import { h } from "../core/dom.js";
import { busy, frame, hush, ready, warn } from "../creator/frame.js";
import { t } from "../creator/i18n.js";
import { readPreview, readProposals, type Draft, type ProposalRow, type Report } from "../creator/model.js";
import { anyObject, call, report } from "../creator/ops.js";
import { PATHS, link, loadDraft, loadReport } from "../creator/pages/common.js";
import { myRoles } from "../home/session.js";
import { readCallState, readImpact, programmeCalls, stepStates, type CallRow } from "./model.js";
import {
  STUDIO_PATHS,
  activationPanel,
  callControls,
  callsPanel,
  changePanel,
  gateLine,
  gateOf,
  impactPanel,
  importsPanel,
  programmeStatus,
  studioNav,
} from "./view.js";

/** The draft status as the studio names it. */
function statusOf(d: Draft): "draft" | "requested" | "active" {
  return d.status === "active" ? "active" : d.activationRequested ? "requested" : "draft";
}

/** "Call" and its number, for a call the cell sent no title of. */
function callName(c: string): string {
  return t.label("studio.calls.name", { call: c });
}

/** The secondary line under the page heading. */
function specName(key: string): HTMLElement {
  return h("p", { class: "voyage-label" }, [t.label(key)]);
}

/** Mounts "Programme set-up" of programme `p`. */
export function mountOverview(p: string): void {
  const { main, alert } = frame({ title: t.label("creator.studio.title"), alertId: "studio-error" });
  const status = h("p", { id: "studio-status" });
  const steps = h("div", { id: "studio-steps" });
  const reportBox = h("section", { id: "studio-report", "aria-labelledby": "studio-report-title" });
  const imports = h("div", {});
  main.append(specName("studio.spec_name"), status, steps);

  void (async () => {
    const d = await loadDraft(p, alert);
    if (d === null) return;
    const r = await loadReport(p, alert);
    const s = statusOf(d);
    status.setAttribute("data-status", s);
    status.textContent = t.label("studio.overview.status", { programme: p, status: programmeStatus(s) });
    steps.replaceChildren(studioNav(p, stepStates(r), null));
    if (s === "draft") {
      main.append(
        h("section", { id: "studio-start", "aria-labelledby": "studio-start-title" }, [
          h("h2", { id: "studio-start-title" }, [t.label("studio.overview.start")]),
          h("p", {}, [t.label("studio.overview.start_intro")]),
          h("p", {}, [link(PATHS.start(p), t.label("studio.overview.start_link"))]),
        ]),
      );
    }
    main.append(imports);
    const o = await call("import.list", [p], undefined, (v) => readProposals(v) !== null);
    const rows: ProposalRow[] | null = o.kind === "done" ? readProposals(o.body) : null;
    imports.replaceWith(importsPanel(p, rows));
    reportBox.replaceChildren(
      h("h2", { id: "studio-report-title" }, [t.label("studio.overview.report")]),
      gateLine(r),
      h("p", {}, [link(STUDIO_PATHS.approval(p), t.label("studio.overview.approval_link"))]),
    );
    reportBox.setAttribute("data-gate", gateOf(r));
    main.append(
      reportBox,
      h("section", { id: "studio-previews", "aria-labelledby": "studio-previews-title" }, [
        h("h2", { id: "studio-previews-title" }, [t.label("studio.overview.previews")]),
        h("p", {}, [link(STUDIO_PATHS.guide(p), t.label("studio.overview.guide_link"))]),
      ]),
    );
    if (s === "active") {
      // The impact read runs when asked, since the cell cannot answer it
      // yet for a programme with calls (a blocker of lane studio).
      const show = h("button", { type: "button", "data-action": "show-impact" }, [t.label("studio.impact.show")]);
      const panel = impactPanel(undefined, callName);
      panel.append(show);
      show.addEventListener(
        "click",
        busy(show, async () => {
          const io = await call("creator.impact", [p], undefined, (v) => readImpact(v) !== null);
          panel.replaceWith(impactPanel(io.kind === "done" ? readImpact(io.body) : null, callName));
        }),
      );
      main.append(panel);
    }
    ready(main);
  })();
}

/** Reads the state of each published call in `calls`. A call the read refuses is left out. */
async function callRows(calls: readonly string[]): Promise<CallRow[]> {
  const out: CallRow[] = [];
  for (const c of calls) {
    const o = await call("calls.get", [c], undefined, (v) => readCallState(v) !== null);
    const r = o.kind === "done" ? readCallState(o.body) : null;
    if (r !== null) out.push(r);
  }
  return out;
}

/** Mounts "Approval and publication" of programme `p`. */
export function mountApproval(p: string): void {
  const { main, alert } = frame({ title: t.label("studio.title.approval"), alertId: "studio-error" });
  const activation = h("div", {});
  const calls = h("div", {});
  main.append(
    specName("studio.approval.spec_name"),
    h("p", {}, [link(STUDIO_PATHS.overview(p), t.label("studio.back"))]),
    activation,
    calls,
    changePanel(),
  );

  const wire = (controls: ReturnType<typeof callControls>): void => {
    const number = (): string | null => {
      const v = controls.number instanceof HTMLInputElement ? controls.number.value.trim() : "";
      if (!/^[0-9]{1,20}$/.test(v)) {
        warn(alert, t.label("studio.calls.no_number"));
        return null;
      }
      return v;
    };
    const act = (button: HTMLElement, op: string, done: string): void => {
      button.addEventListener(
        "click",
        busy(button, async () => {
          hush(alert);
          controls.status.textContent = "";
          const c = number();
          if (c === null) return;
          const o = await call(op, [c], {}, anyObject);
          if (report(alert, o)) return;
          controls.status.textContent = t.label(done);
        }),
      );
    };
    act(controls.approve, "call.approve", "studio.calls.approved");
    act(controls.publish, "call.publish", "studio.calls.published");
  };

  void (async () => {
    const d = await loadDraft(p, alert);
    const r: Report | null = d === null ? null : await loadReport(p, alert);
    if (d !== null) activation.replaceWith(activationPanel(p, r, statusOf(d)));
    const roles = await myRoles();
    if (roles.kind !== "roles") return;
    const controls = callControls();
    wire(controls);
    const rows = await callRows(programmeCalls(roles.roles, p));
    calls.replaceWith(callsPanel(roles.roles, p, rows, (c) => roles.roles.titles.get(c) ?? callName(c), controls.root));
    if (d !== null) ready(main);
  })();
}

/** Mounts the Guide for Applicants preview of programme `p`. */
export function mountGuide(p: string): void {
  const { main, alert } = frame({ title: t.label("studio.guide.title"), alertId: "studio-error" });
  const region = h("section", { id: "preview-guide", "aria-labelledby": "preview-guide-title", class: "fstp-preview" });
  main.append(
    h("p", {}, [link(STUDIO_PATHS.overview(p), t.label("studio.back"))]),
    h("p", {}, [t.label("studio.guide.intro")]),
    h("h2", { id: "preview-guide-title" }, [t.label("creator.preview.guide")]),
    region,
  );
  void (async () => {
    const o = await call("creator.preview", [p, "guide"], undefined, (v) => readPreview(v) !== null);
    if (report(alert, o) || o.kind !== "done") {
      region.replaceChildren(h("p", {}, [t.label("creator.preview.unavailable")]));
      return;
    }
    const blocks = readPreview(o.body) ?? [];
    region.replaceChildren(
      ...blocks.map((b) =>
        b.kind === "heading" ? h("h3", {}, [b.text]) : b.kind === "item" ? h("p", { class: "fstp-item" }, [b.text]) : h("p", {}, [b.text]),
      ),
    );
    ready(main);
  })();
}
