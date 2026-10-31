// The open calls (`calls.list_open`, journey J4 "find a call").

import { call } from "../applicant/client.js";
import { APP, frame, instantTime, run, showFailure, t } from "../applicant/ui.js";
import { decodeOpenCalls } from "../applicant/wire.js";
import { h } from "../core/dom.js";

/** Mounts the open-call list. */
export function mountCallList(): void {
  const f = frame(t("calls.list.title"));
  f.main.append(h("p", {}, [t("calls.list.intro")]));
  run(f, async () => {
    const r = await call("calls.list_open", {}, undefined, decodeOpenCalls);
    if (!r.ok) {
      showFailure(f, r.failure);
      return;
    }
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
