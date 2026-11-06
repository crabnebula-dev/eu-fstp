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

import { mountApplicantPage, mountNotFound } from "../applicant/app.js";
import { h, installTrustedTypesPolicy } from "../core/dom.js";
import { VISUALLY_HIDDEN_CLASS } from "../core/a11y.js";
import { createRouter, rerender, startNavigation } from "../core/router.js";
import { CREATOR_ROUTES, type PageRoute } from "../creator/routes.js";
import { mountHome } from "../home/page.js";
import { addJudgingStrip } from "../journey/pages.js";
import { JOURNEY_ROUTES } from "../journey/routes.js";
import { startSession } from "../home/session.js";
import { ONBOARDING_ROUTES } from "../onboarding/routes.js";
import { PEOPLE_ROUTES } from "../people/routes.js";
import { browserEnv } from "../reviewer/kit.js";
import { mountJudging } from "../reviewer/judging.js";
import { mountSite } from "../site/pages.js";

/** The creator, onboarding and people routes, checked once when first used. */
const STAFF_ROUTES: readonly PageRoute[] = [...CREATOR_ROUTES, ...ONBOARDING_ROUTES, ...PEOPLE_ROUTES];

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

/** The element the Judging pages render into: the shell's `#app`, else the body. */
function root(): HTMLElement {
  const app = document.getElementById("app");
  return app instanceof HTMLElement ? app : document.body;
}

/** Whether `path` is the home page. */
function isHome(path: string): boolean {
  return path === "/app/" || path === "/app";
}

/** Mounts the page of `path`. */
async function run(path: string): Promise<void> {
  if (isHome(path)) {
    mountHome();
    return;
  }
  if (mountSite(path) || mountStaff(path) || mountJourney(path) || mountApplicantPage(path)) {
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
void startSession(location.pathname);
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
