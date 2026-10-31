// The page routes of the people pages (e2e contract `APP`, interim).

import { isProgrammeId } from "../creator/model.js";
import type { PageRoute } from "../creator/routes.js";
import { mount as admin } from "./pages/admin.js";
import { mount as invitation } from "./pages/invitation.js";

/** The routes of the people pages. */
export const PEOPLE_ROUTES: readonly PageRoute[] = [
  {
    name: "people.admin",
    pattern: "/app/programmes/{programme}/people",
    segments: { programme: isProgrammeId },
    mount: (p) => admin(p["programme"] ?? ""),
  },
  { name: "people.invitation", pattern: "/app/invitation", segments: {}, mount: () => invitation() },
];
