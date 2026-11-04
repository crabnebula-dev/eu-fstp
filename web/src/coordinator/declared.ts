// The proposals on which the FSTP coordinator recorded a declaration of
// no conflict in this document (R-CF-02; lane m4/site scope item 2).
//
// No read tells the coordinator's own declaration, and the content route
// refuses until it is recorded. So the intake queue keeps each knock-out
// check in a disclosure, "After your declaration", which is open for a
// proposal declared here. The state is held in `core/store.ts`: plain
// frozen data, in memory only, never in browser storage.

import { createStore } from "../core/store.js";

const DECLARED = createStore<{ readonly proposals: readonly string[] }>({ proposals: [] });

/** Records that the caller declared no conflict on `proposal`. */
export function markDeclared(proposal: string): void {
  DECLARED.update((s) => (s.proposals.includes(proposal) ? s : { proposals: [...s.proposals, proposal] }));
}

/** Whether the caller declared no conflict on `proposal` in this document. */
export function declaredHere(proposal: string): boolean {
  return DECLARED.get().proposals.includes(proposal);
}
