// The routes of the applicant and call pages (M4 design sections 2.2 J4
// and 3.9). This module has no side effect: the shell's entry module
// calls `mountApplicantPage` with the current path.
//
// Interim, pending the lead and lane W4e: no shared entry module exists
// yet. `main.ts` in this folder is a stand-alone entry that mounts these
// pages only. A shared entry can call `mountApplicantPage` and fall
// through to other features when it returns false.

import { mountCall } from "../calls/call.js";
import { mountGuide } from "../calls/guide.js";
import { mountCallList } from "../calls/list.js";
import { h } from "../core/dom.js";
import { createRouter, type RouteDef, type Router } from "../core/router.js";
import { mountEligibility } from "./eligibility.js";
import { mountNotices, mountProposals } from "./lists.js";
import { mountGuardian, mountNegotiation } from "./negotiation.js";
import { mountPlan } from "./plan.js";
import { mountProposal } from "./proposal.js";
import { mountStage2 } from "./stage2.js";
import { mountSubmit } from "./submit.js";
import { mountTeam } from "./team.js";
import { frame, t } from "./ui.js";
import { isId } from "./wire.js";
import { mountWorkspace } from "./workspace.js";

const CALL = { call: isId };
const PROPOSAL = { proposal: isId };

/** The page routes, each with its mount. */
const PAGES: readonly (RouteDef & { readonly mount: (params: Readonly<Record<string, string>>) => void })[] = [
  { name: "calls.list", pattern: "/app/calls", segments: {}, mount: () => mountCallList() },
  { name: "calls.call", pattern: "/app/calls/{call}", segments: CALL, mount: (p) => mountCall(p["call"] ?? "") },
  { name: "calls.guide", pattern: "/app/calls/{call}/guide", segments: CALL, mount: (p) => mountGuide(p["call"] ?? "") },
  { name: "proposals.list", pattern: "/app/proposals", segments: {}, mount: () => mountProposals() },
  {
    name: "proposal.view",
    pattern: "/app/proposals/{proposal}",
    segments: PROPOSAL,
    mount: (p) => mountProposal(p["proposal"] ?? ""),
  },
  {
    name: "proposal.workspace",
    pattern: "/app/proposals/{proposal}/workspace",
    segments: PROPOSAL,
    mount: (p) => mountWorkspace(p["proposal"] ?? ""),
  },
  {
    name: "proposal.plan",
    pattern: "/app/proposals/{proposal}/plan",
    segments: PROPOSAL,
    mount: (p) => mountPlan(p["proposal"] ?? ""),
  },
  {
    name: "proposal.team",
    pattern: "/app/proposals/{proposal}/team",
    segments: PROPOSAL,
    mount: (p) => mountTeam(p["proposal"] ?? ""),
  },
  {
    name: "proposal.eligibility",
    pattern: "/app/proposals/{proposal}/eligibility",
    segments: PROPOSAL,
    mount: (p) => mountEligibility(p["proposal"] ?? ""),
  },
  {
    name: "proposal.submit",
    pattern: "/app/proposals/{proposal}/submit",
    segments: PROPOSAL,
    mount: (p) => mountSubmit(p["proposal"] ?? ""),
  },
  {
    name: "proposal.stage2",
    pattern: "/app/proposals/{proposal}/stage2",
    segments: PROPOSAL,
    mount: (p) => mountStage2(p["proposal"] ?? ""),
  },
  {
    name: "proposal.negotiation",
    pattern: "/app/proposals/{proposal}/negotiation",
    segments: PROPOSAL,
    mount: (p) => mountNegotiation(p["proposal"] ?? ""),
  },
  {
    name: "proposal.guardian",
    pattern: "/app/proposals/{proposal}/guardian",
    segments: PROPOSAL,
    mount: (p) => mountGuardian(p["proposal"] ?? ""),
  },
  { name: "notices", pattern: "/app/notices", segments: {}, mount: () => mountNotices() },
];

let router: Router | null = null;

/**
 * Mounts the applicant or call page of `path`. False when no page of
 * these features has that path.
 */
export function mountApplicantPage(path: string): boolean {
  router ??= createRouter(PAGES);
  const m = router.match(path);
  if (m === null) {
    return false;
  }
  const page = PAGES.find((p) => p.name === m.name);
  if (page === undefined) {
    return false;
  }
  page.mount(m.params);
  return true;
}

/** Mounts the page that says an address names no page. */
export function mountNotFound(): void {
  const f = frame(t("app.not_found"));
  f.main.append(h("p", {}, [t("app.not_found_text")]));
}
