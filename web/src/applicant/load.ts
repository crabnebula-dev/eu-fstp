// Reads every applicant page shares.

import { call } from "./client.js";
import { type Frame, showFailure } from "./ui.js";
import { type ProposalInfo, decodeProposal } from "./wire.js";

/**
 * Reads proposal `id` (`proposal.view`). Each read appends `ContentRead`
 * at the cell (R-AU-01). On a refusal or a failure the page's alert says
 * why, and the result is null.
 */
export async function loadProposal(f: Frame, id: string): Promise<ProposalInfo | null> {
  const r = await call("proposal.view", { proposal: id }, undefined, decodeProposal);
  if (!r.ok) {
    showFailure(f, r.failure);
    return null;
  }
  return r.value;
}
