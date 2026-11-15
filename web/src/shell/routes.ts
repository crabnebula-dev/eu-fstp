// Every page route of the `/app/` shell in one list (SA-09).
//
// The server serves an `/app/` page only after its page gate, whose page
// table is `PAGES` of `gen/api.ts` (generated from `fstp_access::PAGES`).
// This list joins the route tables that `shell/main.ts` mounts from, so a
// test (`web/test/pages.test.ts`) can check that the client and the
// server list the same pages, and a new page cannot skip the gate.

import { ADMIN_BRANDING_PAGES } from "../admin/branding/page.js";
import { ADMIN_ERASURE_PAGES } from "../admin/erasures/page.js";
import { ADMIN_PROFILE_PAGES } from "../admin/profiles/page.js";
import { PAGES as APPLICANT_PAGES } from "../applicant/app.js";
import type { RouteDef } from "../core/router.js";
import { CREATOR_ROUTES } from "../creator/routes.js";
import { POST_GRANT_PAGES } from "../grant/routes.js";
import { JOURNEY_ROUTES } from "../journey/routes.js";
import { MAILBOX_PAGE_ROUTES } from "../mailbox/routes.js";
import { ONBOARDING_ROUTES } from "../onboarding/routes.js";
import { PEOPLE_ROUTES } from "../people/routes.js";
import { JUDGING_PAGES } from "../reviewer/judging.js";
import { SETUP_ROUTES } from "../setup/routes.js";
import { PAGES as SITE_PAGES } from "../site/pages.js";

/** The home page, which no route table holds (`shell/main.ts` `isHome`). */
export const HOME_PATTERN = "/app/";

/** Every page route the shell mounts from, the home page aside. */
export function appRoutes(): readonly RouteDef[] {
  const plain = (r: RouteDef): RouteDef => ({ name: r.name, pattern: r.pattern, segments: r.segments });
  return [
    ...SITE_PAGES.map((p) => ({ name: p.name, pattern: p.pattern, segments: {} })),
    ...MAILBOX_PAGE_ROUTES.map(plain),
    ...CREATOR_ROUTES.map(plain),
    ...ONBOARDING_ROUTES.map(plain),
    ...PEOPLE_ROUTES.map(plain),
    ...SETUP_ROUTES.map(plain),
    ...JOURNEY_ROUTES.map(plain),
    ...APPLICANT_PAGES.map(plain),
    ...ADMIN_BRANDING_PAGES.map((p) => p.route),
    ...ADMIN_ERASURE_PAGES.map((p) => p.route),
    ...ADMIN_PROFILE_PAGES.map((p) => p.route),
    ...POST_GRANT_PAGES.map((p) => p.route),
    ...JUDGING_PAGES.map((p) => p.route),
  ];
}

/** Every page pattern of the shell, the home page first. */
export function appPatterns(): readonly string[] {
  return [HOME_PATTERN, ...appRoutes().map((r) => r.pattern)];
}
