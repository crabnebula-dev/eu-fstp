// The identity page, `/app/me/identity` (Q2, SoD-07, SoD-09, I-67; M4
// design sections 2.2 J0 and 6.1 item 13).
//
// A tenant admin, and every builder and approver of a draft, verifies
// their identity through the vault, so the I-67 check that an approver
// is no builder under another account can apply. `#identity-status`
// carries `data-status` set to `unverified`, `pending` or `verified`.
// `#verify-identity` starts the vault flow (`me.begin_verification`). The
// vault itself holds the result. This page never sees an identity
// attribute (R-NF-02).

import { h, safeUrl } from "../../core/dom.js";
import { busy, frame, hush } from "../../creator/frame.js";
import { anyObject, call, report } from "../../creator/ops.js";
import { t } from "../i18n.js";
import { readVerification, record, type VerificationStatus } from "../model.js";

function text(s: VerificationStatus): string {
  return s === "verified"
    ? t.label("onboarding.identity_page.verified")
    : s === "pending"
      ? t.label("onboarding.identity_page.pending")
      : t.label("onboarding.identity_page.unverified");
}

/** Mounts the identity page. */
export function mount(): void {
  const { main, alert } = frame({ title: t.label("onboarding.identity_page.title"), alertId: "identity-error" });
  const status = h("p", { id: "identity-status", role: "status", class: "fstp-status" });
  const next = h("p", { id: "identity-next" });
  const verify = h("button", { id: "verify-identity", type: "button", class: "fstp-primary" }, [
    t.label("onboarding.identity_page.verify"),
  ]);
  const show = (s: VerificationStatus): void => {
    status.setAttribute("data-status", s);
    status.textContent = text(s);
    if (s === "verified") {
      verify.setAttribute("hidden", "");
    } else {
      verify.removeAttribute("hidden");
    }
  };
  verify.addEventListener(
    "click",
    busy(verify, async () => {
      hush(alert);
      const o = await call("me.begin_verification", [], {}, anyObject);
      if (report(alert, o) || o.kind !== "done") return;
      show("pending");
      const to = safeUrl(record(o.body)?.["redirect"]);
      next.replaceChildren();
      if (to !== null) {
        next.append(h("a", { href: to }, [t.label("onboarding.identity_page.continue")]));
      }
    }),
  );
  main.append(h("p", {}, [t.label("onboarding.identity_page.intro")]), status, verify, next);
  void (async () => {
    const o = await call("me.get_verification", [], undefined, (v) => readVerification(v) !== null);
    if (report(alert, o) || o.kind !== "done") return;
    const s = readVerification(o.body);
    if (s !== null) show(s);
    main.setAttribute("data-ready", "true");
  })();
}
