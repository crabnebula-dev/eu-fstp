// The consent page of an agent connection, `/app/connect#<handle>`
// (ADR-013 amendment of 2026-11-20, lane L2; ADR-013 "Consent").
//
// `GET /oauth/authorize` sends the browser here with the consent handle
// in the fragment. The page:
//
// 1. takes the handle from the fragment and removes it from the address
//    bar. It keeps the handle in the tab's session storage, so a sign-in
//    in between returns here with it (`auth/next.ts` takes no fragment);
// 2. reads `agents.consent_request` and shows the client name as
//    unverified text, the host the browser goes back to, and every scope
//    in plain words (TW-8). No account is named (I-86);
// 3. approves through `agents.consent` with core `withStepUp`: the
//    step-up dialog runs the passkey ceremony bound to the request (I-78).
//    A magic-link session is refused (I-77) and asked to sign in with a
//    passkey. Only a completed approval leaves the page, to the client's
//    redirect URI with the code;
// 4. denies through `POST /oauth/deny`, which sends the client
//    `access_denied`.
//
// No demo step-up exists on this page. Every text comes from the
// catalogue, and the client's name goes in as text only (ADR-014).

import { post } from "../auth/api.js";
import { get, ok } from "../auth/api.js";
import { h } from "../core/dom.js";
import { busy, frame, hush, ready, warn } from "../creator/frame.js";
import { call } from "../creator/ops.js";
import { t } from "./i18n.js";
import {
  DENY_ROUTE,
  HANDLE_KEY,
  approval,
  consentHandle,
  type ConsentView,
  type Decision,
  denial,
  readConsentView,
  signInPath,
} from "./model.js";

/** The handle of the fragment, removed from the address bar, else the one this tab kept. */
function takeHandle(): string | null {
  const f = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  if (f !== "") {
    history.replaceState(null, "", location.pathname);
    const fresh = consentHandle(f);
    if (fresh !== null) {
      keep(fresh);
    }
    return fresh;
  }
  try {
    return consentHandle(sessionStorage.getItem(HANDLE_KEY));
  } catch {
    return null;
  }
}

/** Keeps `handle` in this tab across a sign-in. Storage may be off: then nothing is kept. */
function keep(handle: string): void {
  try {
    sessionStorage.setItem(HANDLE_KEY, handle);
  } catch {
    // A sign-in then loses the handle, and the agent starts again.
  }
}

function forget(): void {
  try {
    sessionStorage.removeItem(HANDLE_KEY);
  } catch {
    // Nothing was kept.
  }
}

/** Whether this browser has a session: `GET /auth/sessions` (M3, R-LG-04). */
async function signedIn(): Promise<boolean> {
  return ok(await get("/auth/sessions"));
}

/** The description of the consent `v`. */
function describe(v: ConsentView): HTMLElement[] {
  const name = v.name ?? t.label("connect.unnamed");
  const back = v.loopback
    ? t.label("connect.redirect_device", { host: v.redirectHost })
    : t.label("connect.redirect", { host: v.redirectHost });
  const scopes = v.scopes.map((s) => h("li", { "data-scope": s }, [t.label(`connect.scope.${s}`)]));
  return [
    h("p", {}, [t.label("connect.intro")]),
    h("p", { id: "connect-client", "data-client": v.client }, [
      h("strong", {}, [name]),
      " ",
      h("span", { class: "fstp-tag" }, [t.label("connect.unverified")]),
    ]),
    h("p", { id: "connect-redirect" }, [back]),
    h("h2", {}, [t.label("connect.asks")]),
    h("ul", { id: "connect-scopes" }, scopes),
    h("p", {}, [t.label("connect.limits")]),
    h("p", {}, [t.label("connect.prepare_only")]),
    h("p", {}, [t.label("connect.device")]),
  ];
}

/** Acts on `d`: leaves for the client, or says why not. */
function act(d: Decision, alert: HTMLElement, status: HTMLElement): void {
  switch (d.kind) {
    case "redirect":
      forget();
      status.textContent = t.label("connect.going_back");
      location.assign(d.to);
      return;
    case "passkey_needed":
      warn(alert, t.label("connect.passkey_needed"), "I-77");
      return;
    case "step_up_cancelled":
      hush(alert);
      return;
    case "expired":
      forget();
      warn(alert, t.label("connect.expired"));
      return;
    case "refused":
      warn(alert, t.label("connect.not_connected"), d.rule);
      return;
    case "unavailable":
      warn(alert, t.label("connect.unavailable"));
      return;
  }
}

/** Mounts the consent page. */
export function mount(): void {
  const handle = takeHandle();
  const { main, alert } = frame({ title: t.label("connect.title"), alertId: "connect-error" });
  if (handle === null) {
    warn(alert, t.label("connect.bad_link"));
    return;
  }
  const status = h("p", { id: "connect-status", role: "status", class: "fstp-status" });
  void (async () => {
    if (!(await signedIn())) {
      main.append(
        h("p", {}, [t.label("connect.sign_in")]),
        h("p", {}, [h("a", { id: "connect-sign-in", href: signInPath() }, [t.label("connect.sign_in_link")])]),
      );
      ready(main);
      return;
    }
    const o = await call("agents.consent_request", [handle], undefined, (v) => readConsentView(v) !== null);
    const view = o.kind === "done" ? readConsentView(o.body) : null;
    if (view === null) {
      act(o.kind === "refused" && o.rule === "Input" ? { kind: "expired" } : { kind: "unavailable" }, alert, status);
      return;
    }
    const approve = h("button", { id: "connect-approve", type: "button", class: "fstp-primary" }, [
      t.label("connect.approve"),
    ]);
    const deny = h("button", { id: "connect-deny", type: "button" }, [t.label("connect.deny")]);
    approve.addEventListener(
      "click",
      busy(approve, async () => {
        hush(alert);
        const r = await call("agents.consent", [], { consent: handle }, (v) => typeof v === "object" && v !== null);
        act(approval(r), alert, status);
      }),
    );
    deny.addEventListener(
      "click",
      busy(deny, async () => {
        hush(alert);
        const r = await post(DENY_ROUTE, { consent: handle });
        act(denial(r.status, r.body), alert, status);
      }),
    );
    main.append(...describe(view), h("div", { class: "fstp-actions" }, [approve, deny]), status);
    ready(main);
  })();
}
