# Authentication

Accounts are per tenant (I-20). Each cell authenticates its own users. No login is shared across tenants.

## Login methods

| Method | Who | Notes |
| --- | --- | --- |
| Passkeys (WebAuthn) | Everyone | Default. Phishing-resistant |
| EUDI Wallet | Everyone, where the tenant enables it | Uses the relying party mode in P-45 |
| OPAQUE password | Everyone, where the tenant enables it | The server never sees the password |
| Email magic link | Applicants and grantees only | Fallback for people without a passkey device |

Tenants choose which methods are enabled (P-70). Passkeys are always available.

NOTE: Identity verification (P-18) and signing (P-30) are separate. P-18 lists only identity verification routes. Advanced signature is a fallback signing route of P-30, never a verification method (decided by Daniel 2026-11-01).

## Strong methods

Passkeys and the EUDI Wallet count as phishing-resistant. OPAQUE and magic links do not.

- **I-77** Accounts holding any Drafting, Judging, Operations or tenant admin role log in with a phishing-resistant method only.
- Magic-link sessions can draft and submit proposals and payment requests. They cannot perform any high-risk action.
- Logins to an account that I-77 covers require user verification on the authenticator (decided 2026-10-28).

## First passkey

An account's first passkey is added only inside one of three logged ceremonies (decided 2026-10-28):

1. An invitation, issued by a tenant admin with a step-up, or by provisioning for a cell's first tenant admin.
2. Self-registration of a new Receiving account, after email proof in the same ceremony. A passkey enrolled at self-registration is enrolled within it. Whether self-registration may end without a passkey, where P-70 enables magic links, is open (ADR-008).
3. Completion of an account recovery (Account recovery).

Outside these ceremonies, an account can add only a further passkey, which is a high-risk action (table below). A magic-link session never adds one. An account without a passkey gets its first one through recovery.

## High-risk actions and step-up (I-78)

High-risk actions need a fresh step-up with a phishing-resistant method within P-71, even inside an active session:

| Action | Why |
| --- | --- |
| Granting or changing a role in the Drafting, Judging or Operations groups, or tenant admin | Adding management personnel |
| Tenant export, vault export, and any download containing identity attributes | Exporting data |
| Adding a passkey, linking a device, or signing in the desktop client | Linking a new device. The desktop client is deferred (B-04) |
| Changing the account email address or login methods | Account takeover path |
| Changing bank details | Payment diversion, already held under I-33 |
| Approving or releasing a payment | Money movement |
| Activating a programme or publishing a call | Binding public commitments |
| Publishing a template to other tenants | Data leaving the cell |
| Approving break-glass access | Operator access to content |
| Approving an account recovery | Changes another account's login methods (decided 2026-10-28) |

- **I-78** No high-risk action completes without a phishing-resistant step-up within P-71.
- An account without a phishing-resistant method cannot perform a high-risk action. It gets a passkey only through a ceremony under First passkey (decided 2026-10-28).
- One step-up authorises one command, bound to a digest of that command (decided 2026-10-28). P-71 freshness is checked when the command is admitted and again when it completes.
- Every step-up requires user verification on the authenticator (decided 2026-10-28).
- Every step-up is logged with the action it authorised.
- Creating a programme counts as activating it, so it needs the step-up (confirmed 2026-10-25).

## Account recovery

- Applicants and grantees recover through a verified email, then must add a new passkey.
- **I-79** An account holding any role outside the Receiving group is never recovered by email alone. Recovery needs approval by a tenant admin other than the account holder, followed by a new passkey enrolment.
- A tenant admin is recovered by another tenant admin. With only one admin, recovery needs the platform operator's verified process, which is logged and shown to the tenant.
- Approving a recovery is a high-risk action and needs a step-up (decided 2026-10-28).
- Completing a recovery revokes every earlier credential of the account and ends all of its sessions (decided 2026-10-28).
- On a self-hosted install, the platform operator is the organisation that hosts the cell (decided 2026-10-28). Its verified process for a sole tenant admin is a host console command. The command runs as root, needs access to the cell's key custody, and is followed by a new passkey enrolment. Each use is logged and shown to every tenant admin.

## Sessions

- Session tokens are opaque, bound to the cell, and stored server side.
- Idle and absolute session lifetimes follow P-72.
- Users can see and end their active sessions and devices.
- Ending a role binding ends the sessions that relied on it.

## Crates

WebAuthn and OPAQUE involve parsing and protocol code close to cryptography. Their crates are chosen in ADR-001 (candidates: webauthn-rs for WebAuthn, opaque-ke for OPAQUE). If built in-house instead, the CBOR and COSE parsers need fuzz targets from the first commit.

NOTE: OPAQUE as specified uses classical groups. Passkeys and the EUDI Wallet are likewise classical today. Post-quantum login protects little extra, since a login secret captured now cannot be replayed later once rotated.
