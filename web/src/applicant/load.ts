// Reads every applicant page shares.

import { call } from "./client.js";
import { isTerminal } from "./rules.js";
import { type Frame, showFailure } from "./ui.js";
import { type ProposalInfo, decodeOwnProposals, decodeProposal } from "./wire.js";

/**
 * Reads proposal `id` (`proposal.view`). Each read appends `ContentRead`
 * at the cell (R-AU-01). On a refusal or a failure the page's alert says
 * why, and the result is null.
 *
 * A proposal that reached a terminal state ended its team's Receiving
 * bindings (`roles-and-sod.md`), so `proposal.view` refuses it under
 * R-AC-01. The team still reads its final state, such as WITHDRAWN or
 * NOT_SELECTED, from its own list (`proposal.list_own`), which holds
 * only the caller's own proposals (R-SB-03, R-EV-04). Only a terminal
 * state is taken from the list. Any other answer keeps the refusal.
 */
export async function loadProposal(f: Frame, id: string): Promise<ProposalInfo | null> {
  const r = await call("proposal.view", { proposal: id }, undefined, decodeProposal);
  if (r.ok) {
    return r.value;
  }
  if (r.failure.kind === "refused" && r.failure.rule === "R-AC-01") {
    const own = await call("proposal.list_own", {}, undefined, decodeOwnProposals);
    const mine = own.ok ? own.value.find((p) => p.proposal === id) : undefined;
    if (mine !== undefined && isTerminal(mine.state)) {
      return mine;
    }
  }
  showFailure(f, r.failure);
  return null;
}
