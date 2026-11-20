// The English catalogue of the consent page (R-NF-04, ADR-013 amendment
// of 2026-11-20, lane L2). Every user-visible string of `web/src/connect`
// comes from here.
//
// Interim, pending Daniel (ADR-013 "Consent texts"): the scope texts are
// the e2e cell's, moved here as the production texts. The client name is
// the agent's own text, shown as unverified.

import type { CatalogueInput } from "../core/i18n.js";

const LABELS: Readonly<Record<string, string>> = {
  "connect.title": "Connect an agent",
  "connect.intro": "An AI agent asks to act for you on this platform.",
  "connect.unnamed": "An agent with no name",
  "connect.unverified": "unverified",
  "connect.redirect": "After you decide, you go back to {host}.",
  "connect.redirect_device": "After you decide, you go back to {host}. This address is on your own device.",
  "connect.asks": "It asks to",
  "connect.limits": "The agent can do no more than your roles allow. It never sees identity details or bank details.",
  "connect.prepare_only":
    "High-risk actions, such as publishing a call, stay prepare-only. You confirm each one in the platform.",
  "connect.device": "Connecting an agent links a new device, so the platform asks you to confirm it with your passkey.",
  "connect.approve": "Approve",
  "connect.deny": "Deny",
  "connect.going_back": "Going back to the agent.",
  "connect.bad_link": "This connection link is not valid. Start the connection again from your agent.",
  "connect.expired": "This connection request is no longer valid. Start the connection again from your agent.",
  "connect.sign_in": "Sign in to the platform in this browser first. You come back to this page after that.",
  "connect.sign_in_link": "Sign in",
  "connect.passkey_needed":
    "Connecting an agent needs a session that signed in with a passkey. Sign in with your passkey, then approve again.",
  "connect.not_connected": "The platform did not connect the agent.",
  "connect.unavailable": "The platform is not available. Try again in a moment.",
  "connect.scope.calls:read": "Read calls, their Guides and deadlines.",
  "connect.scope.proposals:read": "Read the proposals you may read.",
  "connect.scope.proposals:draft": "Draft and edit proposals for you. Submitting stays yours.",
  "connect.scope.proposals:binding": "Complete binding proposal actions where the programme allows agents to.",
  "connect.scope.stage2:draft": "Draft stage 2 answers for you.",
  "connect.scope.review:read": "Read your review assignments.",
  "connect.scope.review:draft": "Draft scores and comments for you.",
  "connect.scope.ranking:read": "Read the ranking view you may see.",
  "connect.scope.findings:read": "Read findings you may see.",
  "connect.scope.creator:draft":
    "Read and edit programme drafts you work on. Prepare invitations, role changes and activation requests that you confirm in the platform.",
  "connect.scope.calls:draft": "Draft and edit calls, and prepare a publication that you confirm in the platform.",
  "connect.scope.audit:read": "Read audit views you may see.",
  "connect.scope.tenant:draft":
    "Read your organisation's funder profiles and check brand colours. Prepare changes to funder profiles, brand tokens and interface labels. Nothing changes until you confirm each change in the platform.",
};

/** The English catalogue of the consent page. */
export const CATALOGUE: CatalogueInput = { locale: "en", labels: LABELS, approved: {} };
