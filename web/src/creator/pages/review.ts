// The review step, `/app/programmes/{p}/creator/review` (R-PG-01,
// R-PG-03, I-66; M4 design sections 2.2 J1 and 3.2).
//
// - `#report` lists every result of the validation report. A warning not
//   yet acknowledged at the report's revision has
//   `[data-action="acknowledge"]`. A failure has none: an
//   acknowledgement never clears a failure.
// - `#preview-guide`, `#preview-public` and `#preview-contract` show the
//   previews as text, never as markup.
// - `#request-activation` stays disabled until the report is clean
//   (`activationGate`). The server checks again at the request, and the
//   approval recomputes the report over fresh probes.

import { h } from "../../core/dom.js";
import { busy, frame, hush, ready } from "../frame.js";
import { t } from "../i18n.js";
import { CREATOR_STEPS, activationGate, readPreview, type Report, type ReportResult } from "../model.js";
import { anyObject, call, report } from "../ops.js";
import { checkText, loadDraft, loadReport, queue, stepNav, stepTitle } from "./common.js";

const PREVIEWS = [
  ["guide", "preview-guide"],
  ["public", "preview-public"],
  ["contract", "preview-contract"],
] as const;

/** Mounts the review page of programme `p`. */
export function mount(p: string): void {
  const s = CREATOR_STEPS.find((x) => x.id === "review");
  if (s === undefined) return;
  const { main, alert } = frame({ title: t.label("creator.studio.title"), alertId: "creator-error", nav: stepNav(p, "review") });
  document.title = stepTitle(s);
  main.append(h("h2", { id: "creator-step-heading" }, [stepTitle(s)]));
  const list = h("ul", { id: "report", "aria-labelledby": "report-title" });
  const summary = h("p", { id: "report-summary", role: "status" });
  const status = h("p", { id: "activation-status", role: "status" });
  const request = h("button", { id: "request-activation", type: "button", class: "fstp-primary", disabled: true }, [
    t.label("creator.review.request"),
  ]);
  const write = queue();
  let current: Report | null = null;
  /** Acknowledgements sent or waiting. */
  let inflight = 0;

  const gate = (): void => {
    const results = current?.results ?? [];
    const g = activationGate(results);
    summary.textContent = t.label("creator.review.summary", {
      failures: String(g.failures),
      warnings: String(g.unacknowledged),
    });
    if (current !== null && g.canRequest) {
      request.removeAttribute("disabled");
    } else {
      request.setAttribute("disabled", "");
    }
  };

  const item = (r: ReportResult): HTMLElement => {
    const li = h(
      "li",
      { "data-check": r.check, "data-severity": r.severity, "data-acknowledged": r.acknowledged ? "true" : "false" },
      [
        h("strong", {}, [r.severity === "failure" ? t.label("creator.severity.failure") : t.label("creator.severity.warning")]),
        " ",
        checkText(r.check, r.values, r.field),
      ],
    );
    if (r.severity === "warning" && !r.acknowledged) {
      const ack = h("button", { type: "button", "data-action": "acknowledge" }, [
        t.label("creator.review.acknowledge", { check: checkText(r.check, []) }),
      ]);
      ack.addEventListener("click", () => {
        if (current === null) return;
        // Shown as acknowledged at once, so it cannot be pressed twice.
        ack.remove();
        li.setAttribute("data-acknowledged", "true");
        const acked = { ...r, acknowledged: true };
        replace(r, acked);
        inflight += 1;
        void write(async () => {
          try {
            const rev = current?.revision;
            if (rev === undefined) return;
            hush(alert);
            const o = await call("creator.acknowledge", [p], { revision: rev, warning: r.key }, anyObject);
            if (report(alert, o)) {
              li.setAttribute("data-acknowledged", "false");
              li.append(ack);
              replace(acked, r);
              return;
            }
            // The acknowledgement is a record on the draft, so the report
            // has a new revision. The list is drawn again from the server
            // once no other acknowledgement waits.
            const fresh = await loadReport(p, alert);
            if (fresh !== null && current !== null) {
              current = inflight > 1 ? { revision: fresh.revision, results: current.results } : fresh;
              if (inflight === 1) renderReport();
            }
          } finally {
            inflight -= 1;
          }
        });
      });
      li.append(" ", ack);
    }
    return li;
  };

  const replace = (from: ReportResult, to: ReportResult): void => {
    if (current === null) return;
    current = { revision: current.revision, results: current.results.map((x) => (x === from ? to : x)) };
    gate();
  };

  const renderReport = (): void => {
    const results = current?.results ?? [];
    list.replaceChildren(...results.map(item));
    if (results.length === 0) {
      list.append(h("li", {}, [t.label("creator.review.clean")]));
    }
    gate();
  };

  request.addEventListener(
    "click",
    busy(request, () =>
      write(async () => {
        const rev = current?.revision;
        if (rev === undefined) return;
        hush(alert);
        const o = await call("creator.request_activation", [p], { revision: rev }, anyObject);
        if (report(alert, o)) return;
        status.setAttribute("data-status", "requested");
        status.textContent = t.label("creator.review.requested");
      }),
    ),
  );

  const previews = PREVIEWS.map(([kind, id]) => {
    const region = h("section", { id, "aria-labelledby": `${id}-title`, class: "fstp-preview" });
    return { kind, id, region };
  });

  main.append(
    h("h2", { id: "report-title" }, [t.label("creator.review.report")]),
    summary,
    list,
    h("h2", {}, [t.label("creator.review.previews")]),
    ...previews.map((x) =>
      h("div", {}, [
        h("h3", { id: `${x.id}-title` }, [
          x.kind === "guide"
            ? t.label("creator.preview.guide")
            : x.kind === "public"
              ? t.label("creator.preview.public")
              : t.label("creator.preview.contract"),
        ]),
        x.region,
      ]),
    ),
    h("h2", {}, [t.label("creator.review.activation")]),
    h("p", {}, [t.label("creator.review.activation_intro")]),
    request,
    status,
  );

  void write(async () => {
    const d = await loadDraft(p, alert);
    if (d !== null && d.activationRequested) {
      status.setAttribute("data-status", "requested");
      status.textContent = t.label("creator.review.requested");
    }
    if (d !== null && d.status === "active") {
      status.setAttribute("data-status", "active");
      status.textContent = t.label("creator.review.active");
    }
    current = await loadReport(p, alert);
    renderReport();
    const loaded = d !== null && current !== null;
    for (const x of previews) {
      const o = await call("creator.preview", [p, x.kind], undefined, (v) => readPreview(v) !== null);
      if (o.kind !== "done") {
        x.region.replaceChildren(h("p", {}, [t.label("creator.preview.unavailable")]));
        continue;
      }
      const blocks = readPreview(o.body) ?? [];
      x.region.replaceChildren(
        ...blocks.map((b) =>
          b.kind === "heading" ? h("h4", {}, [b.text]) : b.kind === "item" ? h("p", { class: "fstp-item" }, [b.text]) : h("p", {}, [b.text]),
        ),
      );
    }
    if (loaded) ready(main);
  });
}
