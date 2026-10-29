// The page routes of onboarding, the tenant settings and the identity
// page (design section 2.2 names `/app/admin/onboarding/{step}`; the
// other paths are interim readings of the e2e contract `APP`).

import type { PageRoute } from "../creator/routes.js";
import { isOnboardingStep, isSetting } from "./model.js";
import { mount as identity } from "./pages/identity.js";
import { mount as settings } from "./pages/settings.js";
import { mount as step } from "./pages/step.js";
import { mount as summary } from "./pages/summary.js";

/** The routes of the onboarding pages. */
export const ONBOARDING_ROUTES: readonly PageRoute[] = [
  { name: "onboarding.summary", pattern: "/app/admin/onboarding/summary", segments: {}, mount: () => summary() },
  {
    name: "onboarding.step",
    pattern: "/app/admin/onboarding/{step}",
    segments: { step: isOnboardingStep },
    mount: (p) => {
      const s = p["step"] ?? "";
      if (isOnboardingStep(s)) step(s);
    },
  },
  {
    name: "onboarding.setting",
    pattern: "/app/admin/settings/{param}",
    segments: { param: isSetting },
    mount: (p) => {
      const s = p["param"] ?? "";
      if (isSetting(s)) settings(s);
    },
  },
  { name: "onboarding.identity", pattern: "/app/me/identity", segments: {}, mount: () => identity() },
];
