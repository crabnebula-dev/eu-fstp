// The open calls (`calls.list_open`, journey J4 "find a call").

import { call } from "../applicant/client.js";
import { APP, frame, instantTime, run, showFailure, t } from "../applicant/ui.js";
import { decodeOpenCalls } from "../applicant/wire.js";
import { h } from "../core/dom.js";
import { isSetupRefusal } from "../core/setup.js";

/** Mounts the open-call list. */
export function mountCallList(): void {
  const f = frame(t("calls.list.title"));
  run(f, async () => {
    const r = await call("calls.list_open", {}, undefined, decodeOpenCalls);
    if (!r.ok && r.failure.kind === "refused" && isSetupRefusal(r.failure.code, r.failure.rule)) {
      // ADR-021: before activation the organisation has no open call.
      f.main.append(h("p", { id: "calls-setup-notice", role: "status", class: "callout", "data-setup": "" }, [t("calls.list.setup")]));
      return;
    }
    if (!r.ok) {
      showFailure(f, r.failure);
      return;
    }
    f.main.append(h("p", {}, [t("calls.list.intro")]));
    if (r.value.length === 0) {
      f.main.append(h("p", {}, [t("calls.list.empty")]), h("ul", { id: "calls-list", class: "fstp-list" }));
      return;
    }
    const items = r.value.map((c) => {
      const title = c.title === "" ? t("calls.untitled", { id: c.call }) : c.title;
      const kids = [h("a", { href: APP.call(c.call) }, [title])];
      if (c.deadline !== null && c.zone !== "") {
        kids.push(h("p", { class: "fstp-meta" }, [instantTime(c.deadline, c.zone), " ", t("call.zone", { zone: c.zone })]));
      }
      return h("li", {}, kids);
    });
    f.main.append(h("ul", { id: "calls-list", class: "fstp-list" }, items));
  });
}
