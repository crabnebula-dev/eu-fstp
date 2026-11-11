// The routes of the M5 post-grant pages (lanes L-UI1 and L-UI2): the
// grants, the contract, the payment requests and the operations queues.
// The shell joins this table to the others (`shell/main.ts`).

import { createRouter, type Router } from "../core/router.js";
import { CONTRACT_PAGES } from "../contract/pages.js";
import { OPERATIONS_PAGES } from "../operations/pages.js";
import { PAYMENT_PAGES } from "../payments/pages.js";
import type { JudgingPage, PageEnv } from "../reviewer/kit.js";
import { GRANT_PAGES } from "./pages.js";

/** Every post-grant page, the payment form before the payment page that shares its prefix. */
export const POST_GRANT_PAGES: readonly JudgingPage[] = [...GRANT_PAGES, ...CONTRACT_PAGES, ...PAYMENT_PAGES, ...OPERATIONS_PAGES];

let router: Router | null = null;

/** The router over the post-grant routes, checked once when first used. */
export function postGrantRouter(): Router {
  router ??= createRouter(POST_GRANT_PAGES.map((p) => p.route));
  return router;
}

/** Mounts the post-grant page of `path`. False, and nothing rendered, when no route matches. */
export async function mountPostGrant(env: PageEnv, path: string): Promise<boolean> {
  const m = postGrantRouter().match(path);
  if (m === null) {
    return false;
  }
  const page = POST_GRANT_PAGES.find((p) => p.route.name === m.name);
  if (page === undefined) {
    return false;
  }
  await page.mount(env, m.params);
  return true;
}
