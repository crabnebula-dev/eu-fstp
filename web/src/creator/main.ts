// The `/app` entry of the creator, onboarding and people pages (M4
// design section 3.9, ADR-014 "Shell, assets and headers").
//
// The shell of `/app` loads one module. This one routes the paths of
// lane W4a's pages through core `createRouter`, which checks every
// parameter before a page sees it, and mounts the matching page. Any
// other path shows a page that says so.
//
// Interim, pending Daniel and the shell lane: no lane owns an entry that
// joins the route tables of every feature. This module joins the three
// of this lane, so the lead can join it with the others in one place.

import { installTrustedTypesPolicy } from "../core/dom.js";
import { createRouter } from "../core/router.js";
import { h } from "../core/dom.js";
import { ONBOARDING_ROUTES } from "../onboarding/routes.js";
import { PEOPLE_ROUTES } from "../people/routes.js";
import { frame } from "./frame.js";
import { t } from "./i18n.js";
import { CREATOR_ROUTES, type PageRoute } from "./routes.js";

const ROUTES: readonly PageRoute[] = [...CREATOR_ROUTES, ...ONBOARDING_ROUTES, ...PEOPLE_ROUTES];

/** Mounts the page of the current path. */
function run(): void {
  const router = createRouter(ROUTES);
  const m = router.match(location.pathname);
  const route = m === null ? undefined : ROUTES.find((r) => r.name === m.name);
  if (m === null || route === undefined) {
    const { main } = frame({ title: t.label("page.not_found"), alertId: "page-error" });
    main.append(h("p", {}, [t.label("page.not_found_intro")]));
    return;
  }
  route.mount(m.params);
}

installTrustedTypesPolicy();
run();
// A link to the same page with another fragment does not reload it, so
// the invitation landing mounts again for the new fragment.
window.addEventListener("hashchange", run);
