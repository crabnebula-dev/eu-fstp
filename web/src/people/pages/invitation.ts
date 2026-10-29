// The invitation landing, `/app/invitation#<token>` (J2, SoD-09; M4
// design section 2.2).
//
// The invitee reads the confidentiality terms, approved wording that no
// terminology override reaches (I-72), and accepts them
// (`people.accept_invitation`). A browser without a session first enrols
// a passkey through the M3 invitation ceremony. The invitee then starts
// identity verification for SoD-09 (`people.begin_verification`). The
// grant itself is a tenant admin's step on the people admin page.
//
// Interim, pending Daniel and lanes W3b and W5:
// - The token travels in the fragment and leaves the address bar once
//   read, so it never reaches a server log as a query. The operations
//   name the invitation by the token, as the M3 enrolment routes do.
// - The passkey enrolment reuses the M3 invitation routes with the same
//   token (`/auth/invitations/{token}/register`).
// - The terms of a Judging role state the programme's P-75 and P-77
//   choices, which the invitation read carries. A choice the read does
//   not carry shows as undecided, and the terms cannot be accepted yet.

import { get, ok, post } from "../../auth/api.js";
import { failureOf, optionsOf, registration } from "../../auth/webauthn.js";
import { h, safeUrl } from "../../core/dom.js";
import { busy, frame, hush, ready, warn } from "../../creator/frame.js";
import { anyObject, call, report } from "../../creator/ops.js";
import { JUDGING_ROLES, invitationToken, readInvitationView, record, type InvitationView } from "../model.js";
import { roleLabel, t } from "../i18n.js";

/** Whether this browser has a session: `GET /auth/sessions` (M3, R-LG-04). */
async function signedIn(): Promise<boolean> {
  return ok(await get("/auth/sessions"));
}

/** Enrols a passkey through the M3 invitation ceremony for `token`, opening a session. */
async function enrol(token: string): Promise<void> {
  const base = `/auth/invitations/${token}/register`;
  const o = await post(`${base}/options`, {});
  if (!ok(o)) throw failureOf(o.status);
  const { challengeId, publicKey } = optionsOf(o.body);
  const c = await registration(publicKey);
  const r = await post(base, { ...c, challenge_id: challengeId });
  if (!ok(r)) throw failureOf(r.status);
}

/** The URL fragment, without `#`, removed from the address bar and the history entry. */
function takeFragment(): string {
  const f = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  if (f !== "") {
    history.replaceState(null, "", location.pathname);
  }
  return f;
}

/**
 * The confidentiality terms for `v`, as approved text, and whether they
 * can be accepted. The terms of a Judging role state the programme's
 * P-75 and P-77 choices (J2). A choice the read does not carry, as on a
 * draft where it is still a gap, is stated as undecided and never as a
 * default. Such terms cannot be accepted until the programme decides.
 */
function terms(v: InvitationView): { readonly el: HTMLElement; readonly complete: boolean } {
  const parts: HTMLElement[] = [
    // TODO(legal): the confidentiality terms are placeholder wording until Daniel supplies them.
    h("p", {}, [t.approved("people.terms.body", { role: roleLabel(v.role), version: String(v.termsVersion) })]),
  ];
  let complete = true;
  if (JUDGING_ROLES.has(v.role)) {
    const p75 =
      v.p75 === true ? t.approved("people.terms.p75_on") : v.p75 === false ? t.approved("people.terms.p75_off") : t.approved("people.terms.p75_undecided");
    const p77 =
      v.p77 === "allowed"
        ? t.approved("people.terms.p77_allowed")
        : v.p77 === "draft_only"
          ? t.approved("people.terms.p77_draft_only")
          : t.approved("people.terms.p77_undecided");
    complete = v.p75 !== null && v.p77 !== null;
    parts.push(h("p", { "data-param": "p75" }, [p75]), h("p", { "data-param": "p77" }, [p77]));
  }
  return { el: h("div", { id: "invitation-terms", "data-complete": complete ? "true" : "false" }, parts), complete };
}

/** Mounts the invitation landing. */
export function mount(): void {
  const token = invitationToken(takeFragment());
  const { main, alert } = frame({ title: t.label("people.invitation.title"), alertId: "invitation-error" });
  if (token === null) {
    warn(alert, t.label("people.invitation.bad_link"));
    return;
  }
  const status = h("p", { id: "invitation-status", role: "status", class: "fstp-status" });
  const verifyBox = h("div", { id: "invitation-verify-box" });

  const showVerify = (): void => {
    const verify = h("button", { id: "invitation-verify", type: "button", class: "fstp-primary" }, [t.label("people.invitation.verify")]);
    const next = h("p", { role: "status", class: "fstp-status" });
    verify.addEventListener(
      "click",
      busy(verify, async () => {
        hush(alert);
        const o = await call("people.begin_verification", [token], {}, anyObject);
        if (report(alert, o) || o.kind !== "done") return;
        next.textContent = t.label("people.invitation.verification_started");
        const to = safeUrl(record(o.body)?.["redirect"]);
        if (to !== null) {
          next.append(" ", h("a", { href: to }, [t.label("people.invitation.verification_continue")]));
        }
      }),
    );
    verifyBox.replaceChildren(h("p", {}, [t.label("people.invitation.verify_intro")]), verify, next);
  };

  main.append(h("p", {}, [t.label("people.invitation.intro")]));

  void (async () => {
    const o = await call("people.get_invitation", [token], undefined, (v) => readInvitationView(v) !== null);
    if (report(alert, o) || o.kind !== "done") return;
    const view = readInvitationView(o.body);
    if (view === null) return;
    const accept = h("button", { id: "invitation-accept", type: "button", class: "fstp-primary" }, [t.label("people.invitation.accept")]);
    accept.addEventListener(
      "click",
      busy(accept, async () => {
        hush(alert);
        try {
          if (!(await signedIn())) {
            status.textContent = t.label("people.invitation.enrolling");
            await enrol(token);
          }
        } catch {
          status.textContent = "";
          warn(alert, t.label("people.invitation.enrol_failed"));
          return;
        }
        const a = await call("people.accept_invitation", [token], { terms_version: view.termsVersion }, anyObject);
        if (report(alert, a)) {
          status.textContent = "";
          return;
        }
        status.setAttribute("data-status", "accepted");
        status.textContent = t.label("people.invitation.accepted");
        accept.remove();
        showVerify();
      }),
    );
    const shown = terms(view);
    const pending = view.state === "invited" && !shown.complete;
    main.append(
      h("h2", {}, [t.label("people.invitation.terms_title", { role: roleLabel(view.role) })]),
      shown.el,
      view.state === "invited" && shown.complete ? accept : h("span", {}),
      status,
      verifyBox,
    );
    if (pending) {
      status.setAttribute("data-status", "undecided");
      status.textContent = t.label("people.invitation.undecided");
    }
    if (view.state !== "invited") {
      status.setAttribute("data-status", "accepted");
      status.textContent = t.label("people.invitation.accepted");
      if (view.state === "accepted") showVerify();
    }
    ready(main);
  })();
}
