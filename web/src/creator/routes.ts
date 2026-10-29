// The page routes of the creator (e2e contract `APP`, interim beyond
// the paths design section 2.2 names). Each route checks its parameters
// before a page sees them.

import type { RouteDef } from "../core/router.js";
import { isCreatorStep, isProgrammeId } from "./model.js";
import { mount as approvals } from "./pages/approvals.js";
import { mount as imports } from "./pages/imports.js";
import { mount as review } from "./pages/review.js";
import { mountNew, mountStart } from "./pages/start.js";
import { mount as step } from "./pages/step.js";

/** A route and the page it mounts. */
export interface PageRoute extends RouteDef {
  readonly mount: (params: Readonly<Record<string, string>>) => void;
}

const programme = { programme: isProgrammeId };

/** The routes of the creator pages. */
export const CREATOR_ROUTES: readonly PageRoute[] = [
  { name: "creator.new", pattern: "/app/creator/new", segments: {}, mount: () => mountNew() },
  { name: "creator.approvals", pattern: "/app/admin/approvals", segments: {}, mount: () => approvals() },
  {
    name: "creator.start",
    pattern: "/app/programmes/{programme}/creator/start",
    segments: programme,
    mount: (p) => mountStart(p["programme"] ?? ""),
  },
  {
    name: "creator.imports",
    pattern: "/app/programmes/{programme}/creator/imports",
    segments: programme,
    mount: (p) => imports(p["programme"] ?? ""),
  },
  {
    name: "creator.step",
    pattern: "/app/programmes/{programme}/creator/{step}",
    segments: { programme: isProgrammeId, step: isCreatorStep },
    mount: (p) => {
      const s = p["step"] ?? "";
      if (s === "review") {
        review(p["programme"] ?? "");
      } else {
        step(p["programme"] ?? "", s);
      }
    },
  },
];
