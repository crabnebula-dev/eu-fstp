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

## Strong methods

Passkeys and the EUDI Wallet count as phishing-resistant. OPAQUE and magic links do not.

- **I-77** Accounts holding any Drafting, Judging, Operations or tenant admin role log in with a phishing-resistant method only.
- Magic-link sessions can draft and submit proposals and payment requests. They cannot perform any high-risk action.

## High-risk actions and step-up (I-78)

High-risk actions need a fresh step-up with a phishing-resistant method within P-71, even inside an active session:

| Action | Why |
| --- | --- |
| Granting or changing a role in the Drafting, Judging or Operations groups, or tenant admin | Adding management personnel |
| Tenant export, vault export, and any download containing identity attributes | Exporting data |
| Adding a passkey, linking a device, or signing in the desktop client | Linking a new device |
| Changing the account email address or login methods | Account takeover path |
| Changing bank details | Payment diversion, already held under I-33 |
| Approving or releasing a payment | Money movement |
| Activating a programme or publishing a call | Binding public commitments |
| Publishing a template to other tenants | Data leaving the cell |
| Approving break-glass access | Operator access to content |

- **I-78** No high-risk action completes without a phishing-resistant step-up within P-71.
- An account without a phishing-resistant method is asked to add one before its first high-risk action.
- Every step-up is logged with the action it authorised.

## Account recovery

- Applicants and grantees recover through a verified email, then must add a new passkey.
- **I-79** An account holding any role outside the Receiving group is never recovered by email alone. Recovery needs approval by a tenant admin other than the account holder, followed by a new passkey enrolment.
- A tenant admin is recovered by another tenant admin. With only one admin, recovery needs the platform operator's verified process, which is logged and shown to the tenant.

## Sessions

- Session tokens are opaque, bound to the cell, and stored server side.
- Idle and absolute session lifetimes follow P-72.
- Users can see and end their active sessions and devices.
- Ending a role binding ends the sessions that relied on it.

## Crates

WebAuthn and OPAQUE involve parsing and protocol code close to cryptography. Their crates are chosen in ADR-001 (candidates: webauthn-rs for WebAuthn, opaque-ke for OPAQUE). If built in-house instead, the CBOR and COSE parsers need fuzz targets from the first commit.

NOTE: OPAQUE as specified uses classical groups. Passkeys and the EUDI Wallet are likewise classical today. Post-quantum login protects little extra, since a login secret captured now cannot be replayed later once rotated.
