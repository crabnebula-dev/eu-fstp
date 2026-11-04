// The published titles of the calls the caller's roles reach, for page
// titles such as "Ranking for <call>" (lane m4/site scope item 2).
//
// The shell reads `me.roles` once per document (`session.ts`) and puts
// the titles here. A page that names a call reads the title it has now,
// and follows the store, so its heading changes in place when the read
// answers. This module imports no operation table, so a page that never
// loads the shell reads no extra module. The state is plain frozen data
// in `core/store.ts`, in memory only.

import { createStore } from "../core/store.js";

const TITLES = createStore<Readonly<Record<string, string>>>({});

/** Records the titles of the caller's calls, from the caller's own `me.roles` (I-86). */
export function setCallTitles(titles: ReadonlyMap<string, string>): void {
  const next: Record<string, string> = {};
  for (const [call, title] of titles) {
    next[call] = title;
  }
  TITLES.update(() => next);
}

/** The published title of `call`, when the shell read it. */
export function callTitle(call: string): string | undefined {
  const t = TITLES.get();
  return Object.hasOwn(t, call) ? t[call] : undefined;
}

/** Calls `f` each time the titles change. Returns the function that stops it. */
export function followTitles(f: () => void): () => void {
  return TITLES.subscribe(() => f());
}
