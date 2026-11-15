// The page routes of the set-up wizard and the set-up progress page
// (`docs/design/11-programme-setup-wizard.md`). Each route checks its
// parameters before a page sees them.

import { isProgrammeId } from "../creator/model.js";
import type { PageRoute } from "../creator/routes.js";
import { isDraftStage } from "./model.js";
import { mountProgress, mountStage, mountStart } from "./pages.js";

/** The routes of the wizard. The stage segment never reads `progress`. */
export const SETUP_ROUTES: readonly PageRoute[] = [
  { name: "setup.start", pattern: "/app/setup/new", segments: {}, mount: () => mountStart() },
  {
    name: "setup.progress",
    pattern: "/app/programmes/{programme}/setup/progress",
    segments: { programme: isProgrammeId },
    mount: (p) => mountProgress(p["programme"] ?? ""),
  },
  {
    name: "setup.stage",
    pattern: "/app/programmes/{programme}/setup/{stage}",
    segments: { programme: isProgrammeId, stage: isDraftStage },
    mount: (p) => {
      const stage = p["stage"] ?? "";
      if (isDraftStage(stage)) mountStage(p["programme"] ?? "", stage);
    },
  },
];
