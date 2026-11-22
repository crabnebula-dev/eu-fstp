// The claim of a draft started without an account,
// `/app/calls/{call}/claim` (ADR-032, Daniel 2026-11-22).
//
// The draft page keeps the resume token and the call in this browser
// (`auth/anondraft.ts`). After registration or sign-in, this page:
//
// 1. starts the account's own draft in the call (`proposal.create`),
//    unless an earlier visit started it already for the same token;
// 2. moves the anonymous draft into it (`proposal.claim_draft`), which
//    deletes the anonymous draft, so its link stops working;
// 3. forgets the token and opens the new proposal's workspace.
//
// Without a session the shell sends the person to sign in and back here.
// A claim the cell refuses leaves the new, empty proposal open, and says
// so in plain words.

import { forget, isToken, kept } from "../auth/anondraft.js";
import { h } from "../core/dom.js";
import { navigate } from "../core/router.js";
import { call } from "./client.js";
import { APP, frame, run, showAlert, showFailure, t } from "./ui.js";
import { decodeAccepted, decodeCreated, isId } from "./wire.js";

/** The local storage key of a proposal started for a token not yet claimed. */
const STARTED_KEY = "fstp.anondraft.started";

/** The proposal started earlier for `token`, or null. */
function startedFor(token: string): string | null {
  try {
    const raw = globalThis.localStorage.getItem(STARTED_KEY);
    if (raw === null || raw.length > 256) return null;
    const v: unknown = JSON.parse(raw);
    if (typeof v !== "object" || v === null) return null;
    const o = v as Record<string, unknown>;
    const p = o["proposal"];
    return o["token"] === token && typeof p === "string" && isId(p) ? p : null;
  } catch {
    return null;
  }
}

function rememberStarted(token: string, proposal: string): void {
  try {
    globalThis.localStorage.setItem(STARTED_KEY, JSON.stringify({ proposal, token }));
  } catch {
    // Storage refused: a retry starts a new draft.
  }
}

function forgetStarted(): void {
  try {
    globalThis.localStorage.removeItem(STARTED_KEY);
  } catch {
    // Nothing kept.
  }
}

/** Mounts the claim page of call `id`. */
export function mountClaim(id: string): void {
  const f = frame(t("claim.title"));
  const draft = kept();
  if (draft === null || draft.call !== id || !isToken(draft.token)) {
    f.main.append(
      h("p", {}, [t("claim.none")]),
      h("p", {}, [h("a", { href: APP.proposals }, [t("claim.proposals")])]),
    );
    return;
  }
  run(f, async () => {
    f.main.append(h("p", { role: "status" }, [t("claim.working")]));
    let proposal = startedFor(draft.token);
    if (proposal === null) {
      const created = await call("proposal.create", { call: id }, {}, decodeCreated);
      if (!created.ok) {
        showFailure(f, created.failure);
        return;
      }
      proposal = created.value;
      rememberStarted(draft.token, proposal);
    }
    const claimed = await call(
      "proposal.claim_draft",
      { proposal },
      { token: draft.token },
      decodeAccepted,
    );
    if (claimed.ok) {
      forget();
      forgetStarted();
      navigate(APP.workspace(proposal), { replace: true });
      return;
    }
    if (claimed.failure.kind === "refused") {
      // The draft is gone, expired or for another call: the new proposal
      // stays, empty, and the link is of no further use.
      forget();
      forgetStarted();
      showAlert(f, t("claim.gone"));
      f.main.append(h("p", {}, [h("a", { href: APP.workspace(proposal) }, [t("claim.open")])]));
      return;
    }
    showFailure(f, claimed.failure);
  });
}
