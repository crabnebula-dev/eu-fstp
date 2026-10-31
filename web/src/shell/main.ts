// The one entry module of the `/app/` shell (M4 design section 3.9,
// ADR-014 "Shell, assets and headers").
//
// The shell of `fstp-web` loads exactly one module. This one joins the
// route tables of every feature and mounts the page of the current path:
//
// 1. the creator, onboarding and people pages (lane W4a);
// 2. the call and applicant pages (lane W4b);
// 3. the Judging pages of the coordinator, reviewers, committee and IRC
//    (lane W4c).
//
// The tables hold disjoint patterns, so the order only fixes which table
// is asked first. A path that no table holds shows the not-found page.
// Each feature module has no side effect on import, so importing every
// table renders nothing until one page mounts.
//
// Interim, pending Daniel: the feature folders keep their stand-alone
// entries (`creator/main.ts`, `applicant/main.ts`) for their own tests.
// The shell loads this module only.

import { mountApplicantPage, mountNotFound } from "../applicant/app.js";
import { installTrustedTypesPolicy } from "../core/dom.js";
import { createRouter } from "../core/router.js";
import { CREATOR_ROUTES, type PageRoute } from "../creator/routes.js";
import { ONBOARDING_ROUTES } from "../onboarding/routes.js";
import { PEOPLE_ROUTES } from "../people/routes.js";
import { browserEnv } from "../reviewer/kit.js";
import { mountJudging } from "../reviewer/judging.js";

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

/** The element the Judging pages render into: the shell's `#app`, else the body. */
function root(): HTMLElement {
  const app = document.getElementById("app");
  return app instanceof HTMLElement ? app : document.body;
}

/** Mounts the page of the current path. */
async function run(): Promise<void> {
  const path = location.pathname;
  if (mountStaff(path) || mountApplicantPage(path)) {
    return;
  }
  if (await mountJudging(browserEnv(root()), path)) {
    return;
  }
  mountNotFound();
}

installTrustedTypesPolicy();
void run();
// A link to the same page with another fragment does not reload it, so
// the invitation landing mounts again for the new fragment.
window.addEventListener("hashchange", () => {
  void run();
});
