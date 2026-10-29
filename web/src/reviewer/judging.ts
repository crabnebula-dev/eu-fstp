// The Judging pages of lane W4c in one route table (M4 design sections
// 2.2 and 3.9): the FSTP coordinator (J5), the assigned reviewers (J6),
// the committee (J7) and the IRC (J8).
//
// Interim, pending the lead's merge: the application entry that the
// `/app/` shell loads is not this lane's file. It calls `mountJudging`
// with the shell's root and the current path, and mounts another
// feature's page when this returns false.

import { createRouter, type Router } from "../core/router.js";
import { COMMITTEE_PAGES } from "../committee/pages.js";
import { COORDINATOR_PAGES } from "../coordinator/pages.js";
import { IRC_PAGES } from "../irc/pages.js";
import type { JudgingPage, PageEnv } from "./kit.js";
import { REVIEWER_PAGES } from "./pages.js";

/** Every Judging page, each with its route below `/app/`. */
export const JUDGING_PAGES: readonly JudgingPage[] = [
  ...COORDINATOR_PAGES,
  ...REVIEWER_PAGES,
  ...COMMITTEE_PAGES,
  ...IRC_PAGES,
];

let router: Router | null = null;

/** The router over the Judging routes, checked once when first used (`core/router.ts`). */
export function judgingRouter(): Router {
  router ??= createRouter(JUDGING_PAGES.map((p) => p.route));
  return router;
}

/**
 * Mounts the Judging page of `path` into `env.root`. Returns false, and
 * renders nothing, when no Judging route matches the path.
 */
export async function mountJudging(env: PageEnv, path: string): Promise<boolean> {
  const m = judgingRouter().match(path);
  if (m === null) {
    return false;
  }
  const page = JUDGING_PAGES.find((p) => p.route.name === m.name);
  if (page === undefined) {
    return false;
  }
  await page.mount(env, m.params);
  return true;
}
