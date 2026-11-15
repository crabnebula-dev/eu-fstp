// The setup gate of ADR-021 (decided by Daniel on 2026-11-14), as the
// pages see it.
//
// Until a second tenant administrator approves the activation of the
// organisation (SoD-18), the cell refuses every call outside onboarding
// with code `refused` and rule `ADR-021`. A page that meets that refusal
// shows a plain notice that the organisation is still being set up,
// never the rule id and never a failure.

/** The rule the cell names when the setup gate refuses a call. */
export const SETUP_RULE = "ADR-021";

/** The plain notice of a page the setup gate closes. */
export const SETUP_NOTICE =
  "This organisation is still being set up. Its pages open once a second tenant administrator has approved its activation.";

/** Whether a refusal with `code` and `rule` comes from the setup gate. */
export function isSetupRefusal(code: string, rule: string | null | undefined): boolean {
  return code === "refused" && rule === SETUP_RULE;
}
