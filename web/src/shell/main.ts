// The one entry module of the `/app/` shell (M4 design section 3.9,
// ADR-014 "Shell, assets and headers").
//
// The shell of `fstp-web` loads exactly one module. This one joins the
// route tables of every feature and mounts the page of the current path:
//
// 1. the home page `/app/`, "Your work" (interim, see below);
// 2. the creator, onboarding and people pages (lane W4a);
// 3. the call and applicant pages (lane W4b);
// 4. the Judging pages of the coordinator, reviewers, committee and IRC
//    (lane W4c), with the "Proposal status" strip of section 8.3;
// 5. the progress map and the activity log of a proposal (lane j3).
// 6. the mailbox and the prepared action page (lane m6/mailbox).
//
// SA-09: the server serves a page only after its page gate admits it
// (`shell/routes.ts` lists every page, `gen/api.ts` `PAGES` the server's
// table). This module asks the same gate before each in-app navigation,
// after a refused read, and for every in-app link (`shell/gate.ts`).
//
// The tables hold disjoint patterns, so the order only fixes which table
// is asked first. A path that no table holds shows the not-found page.
// Each feature module has no side effect on import, so importing every
// table renders nothing until one page mounts.
//
// Interim, pending Daniel (design section 15.0, 2026-10-31): design
// section 2.2 names no home page. Daniel reported that a person who
// signs in finds no way to their work. So every sign-in lands on the
// home page, which lists the caller's work by role. The shell also reads
// the caller's own roles once per page load (`home/session.ts`). They
// fill the role chip and the role links of the sidebar that every page
// frame puts around its `main` (`home/nav.ts` `appShell`). A person
// without a session on a page that needs one goes to the login page,
// which returns them to that page.
//
// Interim, pending Daniel: the feature folders keep their stand-alone
// entries (`creator/main.ts`, `applicant/main.ts`) for their own tests.
// The shell loads this module only.

import { mountAdminBranding } from "../admin/branding/page.js";
import { mountAdminErasures } from "../admin/erasures/page.js";
import { mountSystemPage } from "../admin/system/page.js";
import { mountAdminProfiles } from "../admin/profiles/page.js";
import { mountTeamPages } from "../admin/team/page.js";
import { mountApplicantPage, mountNotFound } from "../applicant/app.js";
import { h, installTrustedTypesPolicy } from "../core/dom.js";
import { VISUALLY_HIDDEN_CLASS } from "../core/a11y.js";
import { createRouter, rerender, startNavigation } from "../core/router.js";
import { CREATOR_ROUTES, type PageRoute } from "../creator/routes.js";
import { mountHome, paymentReviewCount } from "../home/page.js";
import { mountPostGrant } from "../grant/routes.js";
import { addJudgingStrip } from "../journey/pages.js";
import { JOURNEY_ROUTES } from "../journey/routes.js";
import { MAILBOX_PAGE_ROUTES } from "../mailbox/routes.js";
import { myRoles, startSession } from "../home/session.js";
import { installThemeSwitch, showMailboxCount, showReviewWork } from "../home/nav.js";
import { holdsOperations } from "../home/model.js";
import { mailboxCount } from "../mailbox/pages.js";
import { ONBOARDING_ROUTES } from "../onboarding/routes.js";
import { PEOPLE_ROUTES } from "../people/routes.js";
import { CONNECT_ROUTES } from "../connect/routes.js";
import { SETUP_ROUTES } from "../setup/routes.js";
import { browserEnv, readOp } from "../reviewer/kit.js";
import { decodeFunderProfile, type FunderProfileView } from "../operations/profile.js";
import { mountJudging } from "../reviewer/judging.js";
import { mountSite } from "../site/pages.js";
import { installFooterGuard } from "./brand.js";
import { act, anyObject } from "../grant/kit.js";
import { themeBody } from "./theme.js";
import { setReadRefusalGuard } from "../core/api.js";
import { createGate, gateLinks } from "./gate.js";

/** The creator, onboarding and people routes, checked once when first used. */
const STAFF_ROUTES: readonly PageRoute[] = [
  ...CREATOR_ROUTES,
  ...ONBOARDING_ROUTES,
  ...PEOPLE_ROUTES,
  ...SETUP_ROUTES,
  // Lane L2: the consent page of an agent connection (ADR-013).
  ...CONNECT_ROUTES,
];

let staff: ReturnType<typeof createRouter> | null = null;

/** Mounts a creator, onboarding or people page. False when none has the path. */
function mountStaff(path: string): boolean {
  staff ??= createRouter(STAFF_ROUTES);
  const m = staff.match(path);
  const route = m === null ? undefined : STAFF_ROUTES.find((r) => r.name === m.name);
  if (m === null || route === undefined) {
    return false;
  }
  route.mount(m.params);
  return true;
}

let journey: ReturnType<typeof createRouter> | null = null;

/** Mounts a voyager page: the progress map or the activity log (lane j3). False when none has the path. */
function mountJourney(path: string): boolean {
  journey ??= createRouter(JOURNEY_ROUTES);
  const m = journey.match(path);
  const route = m === null ? undefined : JOURNEY_ROUTES.find((r) => r.name === m.name);
  if (m === null || route === undefined) {
    return false;
  }
  route.mount(m.params);
  return true;
}

let mailbox: ReturnType<typeof createRouter> | null = null;

/** Mounts the mailbox or a prepared action page (lane m6/mailbox). False when none has the path. */
function mountMailboxPage(path: string): boolean {
  mailbox ??= createRouter(MAILBOX_PAGE_ROUTES);
  const m = mailbox.match(path);
  const route = m === null ? undefined : MAILBOX_PAGE_ROUTES.find((r) => r.name === m.name);
  if (m === null || route === undefined) {
    return false;
  }
  route.mount(m.params);
  return true;
}

/** The element the Judging pages render into: the shell's `#app`, else the body. */
function root(): HTMLElement {
  const app = document.getElementById("app");
  return app instanceof HTMLElement ? app : document.body;
}

/** Whether `path` is the home page. */
function isHome(path: string): boolean {
  return path === "/app/" || path === "/app";
}

/** The page gate of SA-09, asked once per path in this page load (`gate.ts`). */
const gate = createGate((path, init) => fetch(path, init));

/** Whether the page on show is the first of this document. */
let first = true;

/**
 * Whether the server answered this document as "Page not found" (SA-09):
 * the shell then carries `<meta name="fstp-page" content="not-found">`.
 */
function servedAsNotFound(): boolean {
  const m = document.querySelector('meta[name="fstp-page"]');
  return m !== null && m.getAttribute("content") === "not-found";
}

/**
 * SA-09: whether the page at `path` may be mounted. The server decided
 * the first page of the document before it served the shell. Every later
 * page asks the same gate. A page the gate closes loads from the server,
 * whose 303 leads to sign-in and back, or home for a page the viewer may
 * not open (SA-09 amendment).
 *
 * The gate's answer for a path is kept for the page load. Every in-app
 * link was asked before it was shown, and every page of Back and Forward
 * was asked when it was opened, so a navigation mounts its page at once,
 * with the URL, and never shows the URL of one page over the heading of
 * the one before (ADR-014, R-NF-03). A page that closed since is still
 * caught: its own read is refused, and the guard below asks again.
 */
async function admitted(path: string): Promise<boolean> {
  if (first) {
    first = false;
    if (servedAsNotFound()) {
      mountNotFound();
      return false;
    }
    return true;
  }
  if ((await gate.check(path)) === "closed") {
    location.assign(path);
    return false;
  }
  return true;
}

/** Mounts the page of `path`. */
async function run(path: string): Promise<void> {
  if (!(await admitted(path))) {
    return;
  }
  if (isHome(path)) {
    mountHome();
    return;
  }
  if (mountSite(path) || mountMailboxPage(path) || mountStaff(path) || mountJourney(path) || mountApplicantPage(path)) {
    return;
  }
  // M9 lane P2: the tenant admin's branding and terminology screens.
  if (await mountAdminBranding(browserEnv(root()), path)) {
    return;
  }
  // Lane m5/retention (P-41, ADR-007): the tenant admin's erasure page.
  if (await mountAdminErasures(browserEnv(root()), path)) {
    return;
  }
  // ADR-028 record of lane L20: the tenant admins' System page.
  if (await mountSystemPage(browserEnv(root()), path)) {
    return;
  }
  // Daniel, 2026-11-15 (late): the tenant admin's funder profiles page.
  if (await mountAdminProfiles(browserEnv(root()), path)) {
    return;
  }
  // SA-11 (Daniel, 2026-11-15 night): the team and member pages.
  if (await mountTeamPages(browserEnv(root()), path)) {
    return;
  }
  // The M5 post-grant pages: grants, contract, payment requests and operations.
  if (await mountPostGrant(browserEnv(root()), path)) {
    return;
  }
  if (await mountJudging(browserEnv(root()), path)) {
    // Section 8.3: a reviewer's or coordinator's proposal page gets the
    // "Proposal status" strip when the journey read gives one (O-58).
    await addJudgingStrip(path);
    return;
  }
  mountNotFound();
}

installTrustedTypesPolicy();
// ADR-030: the theme switch of every sidebar saves the choice for the
// person's account, so it follows them to every device.
installThemeSwitch(async (t) => (await act(browserEnv(root()), "me.set_theme", {}, themeBody(t), anyObject)).ok);
// Daniel, 2026-11-15 (late): a page inside one programme shows the funder
// visibility elements of that programme's pinned profile.
installFooterGuard(async (programme) => {
  const r = await readOp(browserEnv(root()), "programme.funder_profile.view", { programme }, (x): x is FunderProfileView => decodeFunderProfile(x) !== null);
  return r.ok ? decodeFunderProfile(r.data) : null;
});
// SA-09 rule 7: a page whose own read is refused after it loaded, for
// example because the session ended, loads from the server once the gate
// says the page is closed now: its 303 leads to sign-in or home, never to
// the refusal code. A refusal on a page the gate still admits returns to
// the page as before.
let closing: Promise<boolean> | null = null;
setReadRefusalGuard(() => {
  closing ??= (async () => {
    const path = location.pathname;
    if ((await gate.fresh(path)) === "closed") {
      location.assign(path);
      return true;
    }
    return false;
  })().finally(() => {
    closing = null;
  });
  return closing;
});
// SA-09 rule 6: an in-app link shows only once the gate admits its page,
// in the navigation, on the home page, in the mailbox and on every page.
void gateLinks(document.body, gate, location.href);
new MutationObserver((records) => {
  for (const r of records) {
    for (const n of Array.from(r.addedNodes)) {
      if (n instanceof Element) {
        void gateLinks(n, gate, location.href);
      }
    }
  }
}).observe(document.body, { childList: true, subtree: true });
void startSession(location.pathname);
// Lane m6/mailbox: a signed-in person sees the number of messages to act
// on beside the Mailbox link of the top bar.
void myRoles().then(async (a) => {
  // ADR-021: before activation the cell refuses the mailbox read.
  if (a.kind === "roles" && !a.setup) {
    const n = await mailboxCount();
    if (n !== null) {
      showMailboxCount(n);
    }
    // R-PR-08 (lane m5/polish-access): an assigned reviewer with payment lines to decide
    // gets the Operations link, which lists them.
    const reviewer = a.roles.roles.some((b) => b.proposal === null && b.role === "committee_member");
    if (reviewer && !holdsOperations(a.roles)) {
      const k = await paymentReviewCount();
      if (k !== null && k > 0) {
        showReviewWork();
      }
    }
  }
});
// Every `/app/` page renders in this one document (lane m4/site scope
// item 1): `core/router.ts` handles in-app links, Back and Forward. The
// title of each page it opens is spoken in a polite live region of its
// own, outside the page root, so it survives every render and is never
// mistaken for a page's status or alert region (WCAG 2.2 SC 4.1.3).
const announcer = h("p", {
  id: "page-announcer",
  "aria-live": "polite",
  "aria-atomic": "true",
  class: VISUALLY_HIDDEN_CLASS,
});
document.body.append(announcer);
void startNavigation({
  render: run,
  announce: (title) => {
    announcer.textContent = "";
    announcer.append(document.createTextNode(title));
  },
});
// A link from elsewhere to this path with another fragment does not load
// the document again, so the invitation landing mounts again for the new
// fragment.
window.addEventListener("hashchange", () => {
  void rerender();
});
