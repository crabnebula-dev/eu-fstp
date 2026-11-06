// The routes of the voyager pages: the progress map and the activity log
// of one proposal (`docs/design/02-voyager-route-diary.md`; R-JV-01,
// R-JV-05). The links to them live in `links.ts`, so the home page and
// the proposal page load no more than the links.

import type { PageRoute } from "../creator/routes.js";
import { mountActivity, mountProgress } from "./pages.js";

export { JOURNEY_PATHS, type JourneyLink, journeyLinks, journeyNav } from "./links.js";

/** A proposal id segment: a decimal id of 1 to 20 digits. */
function isProposalId(s: string): boolean {
  return /^[0-9]{1,20}$/.test(s);
}

const PROPOSAL = { proposal: isProposalId };

/** The page routes of the voyager surface. */
export const JOURNEY_ROUTES: readonly PageRoute[] = Object.freeze([
  {
    name: "journey.progress",
    pattern: "/app/proposals/{proposal}/progress",
    segments: PROPOSAL,
    mount: (p: Readonly<Record<string, string>>) => mountProgress(p["proposal"] ?? ""),
  },
  {
    name: "journey.activity",
    pattern: "/app/proposals/{proposal}/activity",
    segments: PROPOSAL,
    mount: (p: Readonly<Record<string, string>>) => mountActivity(p["proposal"] ?? ""),
  },
]);
