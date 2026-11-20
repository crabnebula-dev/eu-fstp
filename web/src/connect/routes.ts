// The page route of the consent page (ADR-013 amendment of 2026-11-20,
// lane L2). The handle is in the fragment, so the route has no segment.

import type { PageRoute } from "../creator/routes.js";
import { mount } from "./page.js";

/** The routes of the consent page. */
export const CONNECT_ROUTES: readonly PageRoute[] = [
  { name: "connect.consent", pattern: "/app/connect", segments: {}, mount: () => mount() },
];
