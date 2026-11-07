// The Guide for Applicants of one call (`calls.guide`, R-GA-01, R-LA-08).
//
// The cell sends the page its publication stored, `{call, version,
// digest, html}` (I-53). `wire.ts` parses that page into nodes of the
// Guide subset, and this module builds each node with `h`, its text as
// text nodes. No string reaches an HTML sink (ADR-014). The stored `h1`
// becomes an `h2`, since the page frame holds the one `h1`.

import { call } from "../applicant/client.js";
import { APP, frame, run, showFailure, t } from "../applicant/ui.js";
import { type GuideNode, decodeGuide } from "../applicant/wire.js";
import { h, safeUrl } from "../core/dom.js";

/** The DOM of one Guide node. A link whose target `safeUrl` refuses keeps its text only. */
function build(n: GuideNode): Node | string {
  if (typeof n === "string") {
    return n;
  }
  const children = n.children.map(build);
  if (n.tag === "a") {
    const href = n.href === null ? null : safeUrl(n.href);
    return href === null ? h("span", {}, children) : h("a", { href }, children);
  }
  return h(n.tag === "h1" ? "h2" : n.tag, {}, children);
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
    const nodes = r.value.nodes.map(build);
    if (!r.value.nodes.some((n) => typeof n !== "string")) {
      nodes.push(h("p", {}, [t("guide.empty")]));
    }
    f.main.append(h("article", { id: "guide", "data-version": String(r.value.version), "data-digest": r.value.digest }, nodes));
  });
}
