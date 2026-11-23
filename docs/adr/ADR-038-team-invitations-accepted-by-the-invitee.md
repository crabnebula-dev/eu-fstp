# ADR-038: Team invitations accepted by the invitee

Status: Accepted. Daniel decided the rule on 2026-11-23 for finding F-079. The details below are lane readings of the M10 fix lane `m10/team-accept`, for Daniel to confirm. Drafted 2026-11-23.

The number is the next free one after ADR-037.

## Context

Finding F-079 (M10 review H-07b and H-08, section A-1): `proposal.add_member` bound any account to a proposal team without that account's consent. The refusal rule then told the lead whether the named account was a reviewer, an admin, in an excluded class, or shared an identity with staff. A bound account also became a target for vault questions about the team.

Daniel decided on 2026-11-23: a person accepts an invitation before any binding and before any vault question about them, as staff do. In short:

1. The lead invites. The invitation creates no binding and asks the vault nothing about the invitee.
2. The answer to the lead is the same whatever the invitee is.
3. The invitee sees the invitation after signing in and accepts or declines. Only on acceptance do the eligibility checks run and the binding get made. A refusal then is shown to the invitee. The lead learns only "not joined".
4. Invitations expire and can be withdrawn by the lead. Open invitations are bounded per proposal and per lead.
5. Name the invitee by email or by account id, from what the spec says.
6. Guardians join under the same acceptance rule.

The rules this decision keeps:

- `roles-and-sod.md` "Receiving bindings": a binding starts "when the person is added to the proposal". The person is added when they accept.
- SoD-01, SoD-03, SoD-05, SoD-06, I-06 and I-36 hold at the binding, as before. They now run when the invitee accepts.
- I-17, TH-07, TH-08, R-AN-01, R-CF-03: no answer to the lead names what an account is.
- ADR-007: the invitation address is a sealed text. Ledger bodies hold its reference only.
- ADR-008 "Second derivation": a guardian may still join in NEGOTIATION once the vault no longer shows the lead 18 or older.

## Invariant check

No invariant forbids the decision. The guards of the Receiving binding are unchanged. They move from the lead's command to the invitee's acceptance, so they now run with the consent of the person they ask about. The spec does not make guardians a different case: a guardian holds a Receiving binding like a team member (`roles-and-sod.md` roles table and "Receiving bindings").

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| Naming the invitee | By email. The spec names neither email nor account id for a team invitation. The team page already posts `{email}`, and no applicant read shows an account id | Daniel 2026-11-23, item 5 |
| Matching | An invitation shows to a signed-in account whose login email equals the invitation address, compared in ASCII lower case after trimming. Nothing resolves the address to an account before then | Item 3 |
| Address at rest | A confidential text of the proposal, salted (ADR-007). The ledger record holds its `TextRef`. The text store answers one bit for "is this the text" (`TextStore::text_equals`), so the acceptance needs no read clearance on a proposal the invitee is not on yet | ADR-007, I-21 |
| Domain commands | `InviteToTeam` and `WithdrawTeamInvitation` by the lead. `AcceptTeamInvitation` and `DeclineTeamInvitation` by any account, with the address match attested by the shell. Records `TeamInvited` and `TeamInvitationClosed` | I-84 |
| What the invitation asks | Nothing about the invitee. A guardian invitation in NEGOTIATION asks the vault about the lead, as `AddGuardian` did | Item 1, ADR-008 |
| What the acceptance asks | The Receiving binding's questions about the accepting account, after its consent: `InExcludedClass` and `SameIdentityAsAny` | Item 3 |
| Refusals to the lead | An invitation is refused only for facts of the lead, the proposal or the input: actor, state, the bounds, a malformed address. No refusal reads the invitee | Item 2 |
| The lead's view | Each invitation reads `open`, `joined` or `not_joined`. A decline, a withdrawal and an expiry all read `not_joined`. A refused acceptance leaves the invitation open | Item 3 |
| Refusals to the invitee | An unknown invitation, one addressed to someone else, a closed one and an expired one get one refusal, `not_found` with rule `Input`. A binding guard refuses with its own rule, to the invitee only | Items 2 and 3 |
| Expiry | 14 days from the invitation. An expired invitation cannot be accepted or declined | Item 4 |
| Bounds | At most 10 open invitations per proposal, and at most 20 open invitations by one lead across proposals. Open means neither closed nor expired | Item 4 |
| Mail | None. The lead tells the person, who signs in and sees the invitation. The existing invitation mail looks up the address's account and enrols a new one, which takes longer for an unknown address. That timing would tell the lead whether the address has an account | Item 2 |
| Old commands | `AddTeamMember` and `AddGuardian` stay in the domain, so old ledgers replay and the domain property tests and model checks keep their bare binding step. No registry operation, tool or seed issues them now. The raw command route still admits them (open point 5) | I-23 |

### Operations

| Operation | Route | Who | Body |
| --- | --- | --- | --- |
| `proposal.add_member` | `POST /proposals/{proposal}/team` | lead | `{email}` |
| `proposal.add_guardian` | `POST /proposals/{proposal}/guardian` | lead | `{email}` |
| `proposal.team_invitations` | `GET /proposals/{proposal}/team/invitations` | lead | none |
| `proposal.withdraw_team_invitation` | `DELETE /proposals/{proposal}/team/invitations/{invitation}` | lead | none |
| `me.team_invitations` | `GET /me/team-invitations` | any account, own only | none |
| `me.accept_team_invitation` | `POST /me/team-invitations/{invitation}/accept` | any account | none |
| `me.decline_team_invitation` | `POST /me/team-invitations/{invitation}/decline` | any account | none |

Each is web only. None has an MCP tool.

## Consequences

- No account joins a team without accepting. A lead learns nothing about an address from an invitation, its answer or its state, beyond the invitee's own choice to join or not.
- A person without an account registers with the invited address first, then sees the invitation.
- The lead must tell the person out of band. A mail notice is a later decision for Daniel. It needs a send path that takes the same time for every address. The existing `role-invitation` template wording names "a role in a funding programme" and could carry it.
- Two more domain records. The core state keeps every invitation, so replay rebuilds the open ones.

## Open points for Daniel

1. Confirm 14 days, 10 per proposal and 20 per lead.
2. Whether the invitee's list should name the call. It names the role and the expiry only.
3. Whether to send a mail notice, and through which send path.
4. Whether to retire `AddTeamMember` and `AddGuardian` from the domain, with their tests and model checks.
5. The raw command route `POST /api/v1/commands` of the cell still admits `AddTeamMember` and `AddGuardian` from a session, so a lead can still bind an account by its id there. A guard on that route closes it, but the over-PostgreSQL M2 suites (`seam_m2_*_suite_over_pg`) send these commands through that route, from the SoD machine and the review machine's setup. Closing it needs those suites taught the invitation flow first, or the domain commands retired.

## Record

| Item | Value | Recorded |
| --- | --- | --- |
| Third-party crates or packages added | None | 2026-11-23 |
| Domain | `fstp_domain::proposal::team`: commands `InviteToTeam`, `WithdrawTeamInvitation`, `AcceptTeamInvitation`, `DeclineTeamInvitation`; records `TeamInvited`, `TeamInvitationClosed`; id `TeamInvitationId` | 2026-11-23 |
| Registry | `RETIRED` holds `AddTeamMember` and `AddGuardian`. Port kinds `InviteTeamMember`, `InviteGuardian`, `WithdrawTeamInvitation`, `AcceptTeamInvitation`, `DeclineTeamInvitation`. Read kinds `ListTeamInvitations`, `ListMyTeamInvitations` | 2026-11-23 |
| Port | `TextStore::text_equals`, in the cell's text store and the fake | 2026-11-23 |
| Pages | `/app/team-invitations`, the invitation list on the team page, and a home callout while an invitation waits | 2026-11-23 |
| Demo seed | The guardian of a minor-flagged draft is invited by the lead and accepts, both through the API | 2026-11-23 |
| Fuzz seeds | Four `command_decode` and two `record_decode` seeds, pinned by `m10_f079_codec_seeds_hold_the_team_invitation_kinds` | 2026-11-23 |
| Tests | `m10_f079_th07_an_invitation_binds_nobody_and_asks_the_vault_nothing_before_acceptance`, `m10_f079_th08_the_lead_learns_nothing_about_the_invited_account`, `m10_f079_an_expired_or_withdrawn_invitation_cannot_be_accepted` and their neighbours in `fstp-api-testkit` and `fstp-domain-testkit` | 2026-11-23 |
