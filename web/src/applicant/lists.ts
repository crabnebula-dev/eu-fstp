// The caller's proposals (`proposal.list_own`) and notices (`me.notices`;
// R-EV-04, R-IR-02).
//
// A notice is listed with its record kind in `data-kind` and a link to
// its proposal. Sending by email within P-08 arrives with M6.

import { h } from "../core/dom.js";
import { call } from "./client.js";
import { APP, dayTime, frame, run, showFailure, stateLabel, t } from "./ui.js";
import { type Notice, decodeNotices, decodeOwnProposals } from "./wire.js";

/** Mounts the list of the caller's proposals. */
export function mountProposals(): void {
  const f = frame(t("proposals.title"));
  run(f, async () => {
    const r = await call("proposal.list_own", {}, undefined, decodeOwnProposals);
    if (!r.ok) {
      showFailure(f, r.failure);
      return;
    }
    if (r.value.length === 0) {
      f.main.append(h("p", {}, [t("proposals.empty")]));
    }
    f.main.append(
      h(
        "ul",
        { id: "proposals-list", class: "fstp-list" },
        r.value.map((p) =>
          h("li", { "data-state": p.state }, [
            h("a", { href: APP.proposal(p.proposal) }, [p.title === "" ? t("proposal.untitled") : p.title]),
            " ",
            h("span", { class: "fstp-meta" }, [stateLabel(p.state)]),
          ]),
        ),
      ),
    );
  });
}

function noticeText(n: Notice): string {
  return n.kind === "ProposalOutcome" || n.kind === "IrcConcern" ? t(`notice.${n.kind}`) : t("notice.other");
}

/** Mounts the list of the caller's notices. */
export function mountNotices(): void {
  const f = frame(t("notices.title"));
  run(f, async () => {
    const r = await call("me.notices", {}, undefined, decodeNotices);
    if (!r.ok) {
      showFailure(f, r.failure);
      return;
    }
    if (r.value.length === 0) {
      f.main.append(h("p", {}, [t("notices.empty")]));
    }
    f.main.append(
      h(
        "ul",
        { id: "notices-list", class: "fstp-list" },
        r.value.map((n) => {
          const kids: (HTMLElement | string)[] = [h("p", {}, [noticeText(n)])];
          if (n.day !== undefined) {
            kids.push(h("p", { class: "fstp-meta" }, [t("notice.day"), " ", dayTime(n.day)]));
          }
          if (n.proposal !== undefined) {
            kids.push(h("p", {}, [h("a", { href: APP.proposal(n.proposal) }, [t("notice.open")])]));
          }
          return h("li", { "data-kind": n.kind }, kids);
        }),
      ),
    );
  });
}
