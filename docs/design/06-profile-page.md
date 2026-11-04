# 06. Profile page (`/app/me`)

Status: draft, updated with Daniel's decisions of 2026-11-01. Prototype: `profile.html`. Passkey enrolment before first sign-in is in `auth-enrol.html`.

## Purpose and audience

Every signed-in person. One page with two parts: Profile and Security. It is reached from the Account avatar, never as the landing page after sign-in.

## Profile

| Element | Detail | Key |
| --- | --- | --- |
| Display handle | Read only, monospace, for example `meridian-social-lab` | `me.profile.handle` |
| Verification status | Badge with glyph: "Identity verified", "Not verified" or "Verification pending" | `me.profile.verification.*` |
| Roles held | List of role and programme pairs in words | `me.profile.roles` |
| Display name preference | Handle, or organisation name from the vault | `me.profile.display_pref` |
| Language | English, French, German, then "More languages available from your tenant". Each option carries its own `lang`. | `me.profile.locale` |
| Theme | Light, Dark, Same as my device. Sets `data-theme` on `html`. | `me.profile.theme.*` |
| Time zone | IANA zones of the EU and EEA plus UTC (ADR-015 zone table) | `me.profile.timezone` |
| Vault link | "Your name, organisation and affiliations are kept in the identity vault, not here." Link to the vault origin. | `me.profile.vault_note` |

Name, organisation and affiliations are never shown on this page (R-CF-03, I-83). They live in the vault database.

## Security

### Passkeys

Table: Name, Registered, Last used, Action. "Remove" is a danger button with an accessible name naming the passkey. Removing needs a step-up with another passkey (ADR-014 `stepup.ts` on `step_up_required`). The last passkey cannot be removed. The button then reads "Add another passkey first".

"Add a passkey" starts WebAuthn registration.

### Sessions

Table: Device and browser, Last seen, Action. The current session carries a "This session" badge. Each row has "Sign out". Below: "Sign out all sessions" as a danger button.

### Recovery

"Lost all your passkeys? Recovery runs through the identity vault." Link to the vault origin. The platform holds no recovery secret.

## States

- Saved: success callout "Preferences saved." with `role="status"`.
- Step-up cancelled: warning callout "The passkey was not removed. Confirmation was cancelled."
- Unverified identity: neutral badge and the line "You verify your identity in the vault when a step needs it."

## Copy keys

`me.title`, `me.on_this_page`, `me.profile.*`, `me.security.title`, `me.security.passkeys`, `me.security.passkey.remove`, `me.security.passkey.add`, `me.security.passkey.last_one`, `me.security.stepup_note`, `me.security.sessions`, `me.security.this_session`, `me.security.sign_out`, `me.security.sign_out_all`, `me.security.recovery`, `me.saved`, `me.stepup_cancelled`.

## Accessibility notes

- An in-page nav links to both parts.
- Table captions are present but visually hidden.
- Every Remove and Sign out button names its row in the accessible name.

## Proposal history PDF step-up (Q7)

Daniel's decision, 2026-11-01. The grantee confirms with a passkey (ADR-014 step-up) before the proposal history PDF downloads, because it collects a whole proposal history in one portable file. O-59 still applies: no approval is needed. The auditor follows the existing export policy.

## Spec IDs

R-NF-03, R-NF-04, R-CF-03, I-83, ADR-014 step-up seam, ADR-015 zone table.

## Open points

- Whether the theme choice is stored per account or per device. Recommendation: per account, so it follows the person.
