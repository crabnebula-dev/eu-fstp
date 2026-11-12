// The page routes of the platform mailbox (lane m6/mailbox,
// `docs/handoff/mailbox-design.md` section 4): the mailbox and the page
// of one prepared action, which `pending.rs` names in every MCP answer.

import type { PageRoute } from "../creator/routes.js";
import { mountMailbox, mountPendingAction } from "./pages.js";

/** A decimal id segment of 1 to 39 digits. */
function isId(s: string): boolean {
  return /^(0|[1-9][0-9]{0,38})$/.test(s);
}

/** The routes of the mailbox pages. */
export const MAILBOX_PAGE_ROUTES: readonly PageRoute[] = Object.freeze([
  { name: "mailbox.list", pattern: "/app/mailbox", segments: {}, mount: () => mountMailbox() },
  {
    name: "mailbox.pending",
    pattern: "/app/pending/{pending}",
    segments: { pending: isId },
    mount: (p: Readonly<Record<string, string>>) => mountPendingAction(p["pending"] ?? ""),
  },
]);
