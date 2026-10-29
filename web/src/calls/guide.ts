// The Guide for Applicants of one call (`calls.guide`, R-GA-01, R-LA-08).
//
// The cell sends the Guide as sections of text blocks (see `wire.ts`).
// Each block becomes elements built here, with its text as text nodes.

import { call } from "../applicant/client.js";
import { APP, frame, run, showFailure, t } from "../applicant/ui.js";
import { type GuideBlock, decodeGuide } from "../applicant/wire.js";
import { h } from "../core/dom.js";

function block(b: GuideBlock): HTMLElement {
  switch (b.kind) {
    case "paragraph":
      return h("p", {}, [b.text]);
    case "list":
      return h(
        "ul",
        {},
        b.items.map((i) => h("li", {}, [i])),
      );
    case "table":
      return h("table", {}, [
        h("thead", {}, [h("tr", {}, b.head.map((c) => h("th", { scope: "col" }, [c])))]),
        h(
          "tbody",
          {},
          b.rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, [c])))),
        ),
      ]);
  }
}

/** Mounts the Guide page of call `id`. */
export function mountGuide(id: string): void {
  const f = frame(t("guide.title"));
  f.main.append(h("p", {}, [h("a", { href: APP.call(id) }, [t("guide.back")])]));
  run(f, async () => {
    const r = await call("calls.guide", { call: id }, undefined, decodeGuide);
    if (!r.ok) {
      showFailure(f, r.failure);
      return;
    }
    const sections = r.value.sections.map((s) => h("section", {}, [h("h2", {}, [s.heading]), ...s.blocks.map(block)]));
    if (sections.length === 0) {
      sections.push(h("p", {}, [t("guide.empty")]));
    }
    f.main.append(h("article", { id: "guide" }, sections));
  });
}
