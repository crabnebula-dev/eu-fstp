# ADR-008: Authentication implementation

Status: Accepted 2026-10-28 (Daniel Thompson-Yvetot).

Labels such as `Q10` refer to the questions in `docs/handoff/m3-design.md` section 21. Each decision below names its basis:

- **Answered** means Daniel answered the question on 2026-10-28 (design section 21.0).
- **Interim, pending Daniel** means the design's interim reading (section 17.2) is written in as the proposed decision. Daniel has not answered it yet.

Daniel accepted this ADR on 2026-10-28. The interim readings in it are built as written, but each stays interim, pending Daniel, until he answers it. A later answer that changes one amends this ADR first, then the code (design section 18).

## Context

- **I-77** Accounts holding any Drafting, Judging, Operations or tenant admin role log in with a phishing-resistant method only.
- **I-78** No high-risk action completes without a phishing-resistant step-up within P-71.
- **I-79** An account holding any role outside the Receiving group is never recovered by email alone.
- **I-20** The platform stores no link between tenant accounts in different tenants.
- **SoD-07** A tenant admin granting a role to their own account requires approval by a second tenant admin.
- **SoD-08** Platform operator staff hold no roles in SaaS cells. Content access requires break-glass approval by the tenant and is logged.
- `SPEC/03-architecture/authentication.md` lists the methods, the high-risk table, recovery and sessions. It says the WebAuthn and OPAQUE crates "are chosen in ADR-001", and that in-house CBOR and COSE parsers need fuzz targets from the first commit.
- webauthn-rs depends on the openssl crate as far as the design could tell, and no ADR allows it. OPAQUE needs prime-order group arithmetic that aws-lc-rs does not expose (design G11).
- P-70 sets the enabled login methods. P-71 (5 minutes) and P-72 (30 minutes idle, 12 hours absolute) are marked "(proposed)" in `policy-parameters.md`.

Options considered for the WebAuthn implementation (Q10):

| Option | Description | Outcome |
| --- | --- | --- |
| A | In-house WebAuthn subset and magic links in M3. OPAQUE later. EUDI Wallet login in M4 | Chosen. Answered (Q10 A) |
| B | Add opaque-ke and its group crates under an ADR now | Rejected |
| C | Use webauthn-rs | Rejected. Its openssl dependency is outside ADR-001 |

## Decision summary

| Topic | Decision | Basis |
| --- | --- | --- |
| WebAuthn | In-house subset in `fstp-webauthn`, no third-party crate | Answered (Q10 A) |
| Methods in M3 | Passkeys and magic links. OPAQUE later. EUDI Wallet login and verification in M4 | Answered (Q10 A) |
| First passkey | Only inside the invitation, self-registration and recovery ceremonies | Answered (Q15) |
| Step-up | One step-up per command, bound to its action digest | Answered (Q15) |
| Recovery approval | `ApproveRecovery` is high-risk | Answered (Q15) |
| Recovery completion | Revokes every old credential and ends every session of the account | Answered (Q15) |
| User verification | Required for management logins and for every step-up | Answered (Q15) |
| Self-hosted sole admin | A host console command is the operator's verified process | Answered (Q15) |
| Manual identity checks | The tenant admin records them in M3. An Operations role "identity verifier" replaces this later | Answered (Q14 B now, A later) |
| First tenant admin verification | The platform operator verifies the first tenant admin of each tenant. Two operator staff take part, the verification is logged, and it is shown to the tenant. That admin then records the checks of others | Answered (Daniel, 2026-10-28) |
| Recorder without a verified identity | Refused. The operator verification gives the first tenant admin a verified identity, so this no longer blocks a tenant's first record | Interim, pending Daniel. No longer blocking |
| Minor flag details | The deadline of the call of IRC review, a conflict goes to a manual check, and GRANTED derives the flag again. Late verification stays interim | Answered 2026-10-29, except late verification |
| First admin delivery | Split across two staff and two channels now. A tenant-sealed token once M4 onboarding exists | Answered (Q35, both recommendations, 2026-10-28) |
| Sessions on a binding end | Every session of the account ends | Interim, pending Daniel (Q16) |
| Login email | Sealed in the cell, keyed lookup | Interim, pending Daniel (Q22) |
| Break-glass | Approval, scope, expiry, gate path and logging in M3. Content views in M4 | Interim, pending Daniel (Q21) |
| High-risk additions | `Assign`, `Unassign`, `SetLoginPolicy`, `ApproveSelfGrant`. `ApproveRecovery` is not among them: it is high-risk under the answered Q15 row above | Interim, pending Daniel (Q38) |
| SoD-07 approval | Digest-bound, single-use, expires P-71 after its step-up | Interim, pending Daniel (Q40) |
| Constants | Invitation 72 hours and break-glass at most 4 hours as ADR constants. P-71 and P-72 as proposed | Interim, pending Daniel (Q37) |

## Methods in M3

| Method | Strength | M3 status |
| --- | --- | --- |
| Passkey (WebAuthn) | Phishing-resistant | Built. Always enabled (P-70) |
| Magic link | Weak | Built, for accounts that hold no role outside Receiving. Delivery goes through the outbox, so production use waits for M6 |
| EUDI Wallet | Phishing-resistant | M4, with EUDI verification. The `Method` enum reserves it, and P-70 refuses it until then |
| OPAQUE | Weak | Later. It needs an ADR-001 addition for its group arithmetic first |

- `fstp-auth` holds the login policy, sessions, step-up, recovery, magic links and the ceremonies. It is a pure crate.
- `admit_method` applies I-77 at login. `admit_session` applies it again on every request, inside `Gate::admit`.
- Holdings count active, scheduled and suspended bindings of the Drafting, Judging and Operations groups, plus tenant admin. Voided bindings do not count. A binding whose end is scheduled counts until its end instant.
- A grant of a Drafting, Judging, Operations or tenant admin role ends that account's weak sessions in the same batch.

### Magic links

- Offered only to accounts that hold no role outside Receiving. `POST /auth/magic/request` gives the same response whether or not the account exists.
- The token is random, single-use and stored only as a digest. `GET /auth/magic` shows a confirm page, and only `POST /auth/magic/consume` starts the session.
- A magic-link session can draft and submit. It can never perform a high-risk action, even after a step-up (`authentication.md`, design section 17.1 item 9).
- The magic-link lifetime is not set by the design. See Open points.

### Login email

Interim, pending Daniel (Q22). The login email is a `TextRef` sealed in the cell. Lookup uses `HMAC-SHA-256` under the cell's `Lookup` key over the normalised address. That key is per cell and rotates with erasure. I-17 canary tests treat the email as identity-revealing.

## WebAuthn subset

`fstp-webauthn` is pure and does no I/O. It implements only what the platform uses.

- **Attestation.** Format `none` only. No attestation statement is parsed or trusted. Daniel confirmed this for M3 on 2026-10-29.
- **Algorithms.** ES256, EdDSA (Ed25519) and RS256 with a modulus of at least 2048 bits. Verification uses aws-lc-rs through `fstp-crypto` (ADR-001 Tier A).
- **CBOR.** A strict subset: definite lengths, shortest form, no tags, no floats, no duplicate map keys, depth at most 4, input at most 64 KiB. Anything else is refused.
- **Parsers and fuzz targets.** `cbor_decode`, `cose_key_decode`, `authenticator_data_decode`, `client_data_decode` (through `fstp-json`), `attestation_object_decode`, `assertion_verify` and `registration_verify`. Each exists from the crate's first commit (`.claude/CLAUDE.md`).
- **Expectations.** `RegistrationExpect` and `AssertionExpect` fix the RP id, the origin, the challenge, user presence, user verification and the sign count rule.
- **User verification.** UV is required for every login of an account with holdings and for every step-up. Applicant passkeys request UV, and the cell records whether it was given.
- **Sign counts.** A count that goes down while counters are non-zero refuses the login and records `CredentialSuspect`.
- **Challenges.** Each challenge is random, single-use and bound to its purpose. A challenge is consumed only by an insert into `auth_log`, never by an update.
- **Credential ids.** Stored only as keyed digests under the cell's `CredLookup` key, which rotates with erasure.
- **Browser side.** The pages use the browser's `parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and `toJSON`. The TypeScript holds no in-house WebAuthn parser.
- **Control plane.** `fstp-control` uses the same crate for staff passkeys, with the control-plane host as RP id.
- The ADR-001 amendment closes its "Open points" line on authentication crates with this choice.

## Relying party id

- The RP id of a cell is the exact tenant host, `<cell host>`. `RelyingParty::new` refuses a registrable parent domain.
- A parent-domain RP id would let one passkey serve several tenant hosts. That would be a link between tenants (I-20). `i20_rp_id_is_the_exact_cell_host` and the Playwright test `i20-passkey-not-offered-across-tenants.spec.ts` check it.
- The vault origin `id.<cell host>` is not a relying party. It has no login and no session (ADR-009).
- Session cookies carry the cell id, and every other cell refuses them before any lookup.
- **Custom domains (risk R12).** Passkeys bind to their RP id, so a move to a custom domain in M9 (I-71) cannot reuse them. This ADR fixes that the RP id never changes silently. M9 amends this ADR with a re-enrolment ceremony before any host move.

## Sessions

- The cookie is `__Host-fstp`, with `Secure`, `HttpOnly`, `SameSite=Strict` and `Path=/`. Its value is the cell id followed by the token.
- Tokens are 32 random bytes. The cell stores only their SHA-256 digest.
- State-changing routes check the `Origin` header and accept only JSON bodies.
- Idle and absolute lifetimes follow P-72. A session ends only through an insert into `auth_log.session_end`.
- **Binding ends.** Interim, pending Daniel (Q16). No session records which binding it relied on. Every session of the account that started before the end instant ends at that instant. For a scheduled end, the gate refuses the session from the instant on, and `EndSessionsAtBindingEnd` records it afterwards.
- R-LG-04 routes: `GET /auth/sessions`, `DELETE /auth/sessions/{id}`, `GET /auth/devices` and `DELETE /auth/devices/{id}`. Removing a device is the high-risk action `ChangeLoginMethods`.

## Ceremonies and the first passkey

Answered (Q15). A first passkey is accepted only inside one of three logged ceremonies:

1. **Invitation.** A tenant admin issues an invitation with a step-up, or provisioning issues the first admin's. The token is single-use, stored as a digest and valid for 72 hours (constant below).
2. **Self-registration** of a new Receiving account. Email proof first. A passkey enrolled at self-registration is enrolled in the same ceremony. Whether self-registration may end without one, where P-70 enables magic links, waits for Daniel (Open points).
3. **Recovery completion** (section Recovery).

- An ordinary session, weak or strong, can add another passkey only through the high-risk action `AddPasskey`. A magic-link session never can.
- `authentication.md` states these ceremonies in its section "First passkey" (decided 2026-10-28). An account without a passkey gets its first one through recovery.

### First admin delivery

Answered (Q35). On 2026-10-28 Daniel accepted both recommendations: split delivery across two staff and two channels now, then a token sealed to a tenant-generated key once M4 onboarding exists.

- **SaaS now.** The cell, not the control plane, draws the first-admin token as two random halves. Enrolment needs both.
  - One staff member delivers the first half to the tenant contact recorded at contract.
  - A second staff member delivers the second half to the tenant's contract signatory, over a different channel.
  - Each half is shown to one staff member only. The control plane relays the first half and keeps no copy. It never learns the account id or the full token.
  - Enrolment records `FirstAdminEnrolled`. Every later tenant admin sees it in the admin list and the audit view.
  - Residual risk: two colluding staff members (risk R17).
- **SaaS once M4 onboarding exists.** The cell seals the token to a public key that the tenant generates at onboarding, so no staff member ever sees it. The sealing format follows ADR-001 and the hybrid rule (I-75). It is fixed in an amendment of this ADR before M4 onboarding ships.
- **Self-hosted.** `fstp-cell` writes the token once to a root-only file on first start. `fstp-cell first-admin` prints it on the host console. No default credential exists (R-NF-05).

## Step-up

Answered (Q15): one step-up authorises exactly one command.

- `POST /auth/stepup/options {command}` returns a challenge.
  - `action_digest = SHA-256(canonical(command) || command_id)`.
  - `challenge = SHA-256("fstp-stepup-v1" || cell || session || action_digest || nonce)`.
- `POST /auth/stepup` verifies a passkey assertion with UV over that challenge. It records `StepUpGranted { id, action_digest }`, so every step-up is logged with the action it authorised.
- The action request names the step-up id. `Gate::admit` checks it, and the command's batch records `StepUpConsumed { id }`.
- The gate admits a high-risk action only when all of these hold:
  - the session's method is not a magic link;
  - the step-up exists and belongs to this session;
  - it matches the action digest;
  - it used a phishing-resistant method with UV;
  - it is no older than P-71;
  - it is unused.
- Freshness is `now - asserted_at <= P-71`. It is checked at admission and again at commit. A tenant value above the default is refused, because P-71 may only shorten.
- **Single use is held twice.** The fold refuses a second consumption. The database refuses it too, through the primary key of `auth_log.stepup_consumed`. The ledger-writing role holds INSERT and SELECT only (ADR-007).
- Every route needs a risk class. `Route::new` has no default, and a route without a class does not compile.

### High-risk table

`HighRiskAction` is the single table. The variants and source rows are those of design section 8.4.

- Every domain kind that `CommandKind::high_risk()` marks must be in the table.
- `ApproveRecovery` matches the `authentication.md` row "Approving an account recovery" (decided 2026-10-28, Q15).
- Every other entry must be a domain high-risk kind or sit on the explicit list `STRICT_ADDITIONS`, each with its source row: `Assign`, `Unassign`, `ApproveSelfGrant` and `SetLoginPolicy`. These four are interim, pending Daniel (Q38).
- `i78_high_risk_table_matches_spec_and_domain` checks the table against a transcription of the spec table and against `CommandKind::high_risk()`. W0 re-derives it from the commit that closes M2.

## SoD-07 approval

Interim, pending Daniel (Q40) for the lifetime. The structure follows SoD-07 and TH-05.

- The second tenant admin issues `ApproveSelfGrant { grant_digest }` with a step-up, as `ManagementRoleChange`.
- `grant_digest` is SHA-256 over the canonical `GrantRole` without its `second_admin` field, followed by its command id.
- `decide` records `SelfGrantApproved { approval, approver, grant_digest, expires_at }`. `expires_at` is P-71 after the approval's step-up.
- `attest` sets `Ctx::second_tenant_admin` only when an unconsumed approval matches the grant's digest, was given by a different current tenant admin, and has not expired.
- The grant's batch records `SelfGrantApprovalUsed`. One approval admits one grant.
- The granting admin still needs their own step-up for the grant itself.

## Recovery

Answered (Q15). Approving a recovery is high-risk. Completion revokes every credential and ends every session of the account.

| Account | Path | Steps |
| --- | --- | --- |
| Holds Receiving roles only, or no role | `EmailThenPasskey` | Email proof, then a new passkey in the same ceremony |
| Holds a role outside Receiving, and another tenant admin exists | `SecondAdmin` | Email proof. Then `ApproveRecovery` by a different current tenant admin with a step-up. Then a new passkey from a one-time enrolment token |
| Sole tenant admin, SaaS | `OperatorProcess` | Email proof. Then an operator ticket for the case reference with two staff approvals. Then a new passkey. Logged and shown to the tenant |
| Sole tenant admin, self-hosted | `HostConsole` | A host console command, run as root, that needs custody access. Then a new passkey. Logged and shown to every tenant admin |

- `recovery::complete` recomputes the path from holdings at completion. A role granted during an open email recovery makes that recovery fail (I-79).
- When both approver and holder are verified, `SameIdentityAsAny` must be false. A vault outage refuses the approval, so the check fails closed.
- The operator ticket is composite-signed by the control plane and names only the cell's opaque case reference, never an account id (I-20).
- `HostConsole` is the reading of "the platform operator's verified process" for a self-hosted cell, whose operator is the hosting organisation. Daniel accepted it (Q15).

## Manual identity checks

Answered (Q14): B in M3, A later. P-18 includes "document upload with manual check". R-ID-02 records the verifier. `roles-and-sod.md` section "Manual identity checks" states the rules (decided 2026-10-28), and this section implements them.

- **Recorder in M3.** A current tenant admin records a manual verification outcome. The vault records that admin as the verifier.
- **Later.** An Operations role "identity verifier" replaces the tenant admin as recorder (Daniel, Q14 A later). Interim, pending Daniel: the same two rules bind it, and only the permission rule of the ticket changes. Daniel's answer named the two rules as the guard for the tenant admin in M3.
- **Rule 1.** No recorder verifies their own account (Daniel's wording, 2026-10-28). The cell refuses the ticket, and the vault refuses the write.
- **Rule 2.** No recorder verifies an account that shares their identity (Daniel's wording, 2026-10-28). The readings marked "Proposed" or "Interim" below are this draft's, not Daniel's. They stay in this ADR and do not enter `roles-and-sod.md` until he answers.
  - Proposed: the vault evaluates the rule over effective facts, including the facts the new verification would reveal.
  - Proposed: a vault outage refuses the record (fail closed, `overview.md` NOTE 2).
  - Answered (Daniel, 2026-10-28): the platform operator verifies the first tenant admin, who then records the checks of others (section "First tenant admin verification" below). This replaces the strict interim that refused every unverified recorder, under which a tenant's first record was impossible.
  - Interim, pending Daniel: any other recorder without a verified identity is still refused, because the vault cannot evaluate rule 2 for them. With the first admin verified, this no longer blocks a tenant's first record.
- **What is recorded.** `VerificationRecorded { account, method, document_type, checks, at, verifier }`. No document number or image is stored (R-ID-02).
- **Document key.** A verification puts the document key into an immediate rotation of the Vault chain (ADR-004 part 2, Erasure construction; P-19, R-ID-03). The verification fact becomes provisional only after that rotation completes. `DocumentErased` is appended only after the destroy receipt for the old root epoch.
- **Where the outcome travels.** Proposed reading of Q7 A and the `overview.md` section "Operations other than queries": the recorder reviews the upload and enters the outcome on the vault origin, under a write ticket of kind `VerificationRecorded` (ADR-009). No identity attribute enters the application. This changes design section 6.7, which sends the outcome through a cell route.
- **I-17 guard (derived from I-17).** The cell issues that ticket only to a recorder who holds no Judging binding, whether active, scheduled or suspended. A Judging-role holder would otherwise read identity attributes outside the I-17 window.
- **Release window.** `overview.md` allows releases to an Operations role holder "only for a proposal in NEGOTIATION or later". Showing an uploaded document to a recorder is a release. Strict interim: the cell issues a `VerificationRecorded` ticket only for a subject whose proposal is in NEGOTIATION or later. Every other review waits for Daniel (Open points).
- **Logging.** Issuing the ticket is a ledger record, and the vault logs the review in its own chain (R-AU-01).
- `TODO(legal)`: L-02, for any manual check of a minor or a guardian before NEGOTIATION.

### First tenant admin verification

Answered (Daniel, 2026-10-28). `roles-and-sod.md` section "Manual identity checks" states the rule.

- The platform operator verifies the first tenant admin of each tenant. Two operator staff take part.
- The verification is logged and shown to the tenant. Proposed: every later tenant admin sees it in the admin list and the audit view, as with `FirstAdminEnrolled`.
- That admin then records the manual identity checks of others, under rules 1 and 2. They never record their own check, or the check of an account that shares their identity.
- Proposed mechanism, fixed by amendment before W2b merges. The first admin uploads a document on the vault origin (`DocumentUpload`). Two staff members review it under an operator ticket with two staff approvals, as in the `OperatorProcess` recovery path. The ticket names only the cell's opaque case reference, never an account id (I-20). The vault records `VerificationRecorded` with the operator process as verifier and both staff references.
- The operator ticket is composite-signed, so this path waits on the moduletto ML-DSA-65 pull request (ADR-001 A2). Until then, composite signing refuses with a typed error and no operator verification is recorded in production.
- Proposed reading of SoD-08, for Daniel to confirm: staff take no role binding, and they see only the document the first admin uploads for this check. The first admin's own request for the check counts as the tenant's approval, and the check is logged.
- Proposed reading for a self-hosted cell: its operator is the hosting organisation, as for `HostConsole` (Q15). The same two-person rule applies to the hosting organisation's staff. This waits for Daniel.

### Minor flag details

Daniel answered Q13 A on 2026-10-28: the vault collects an over-18 attestation before NEGOTIATION, and a one-bit query lets the NEGOTIATION gate admit a proposal whose lead has an effective verified adult attestation, or a verified guardian consent. `functional.md` R-ID-04, `state-machine.md` NOTE 14 and `overview.md` NOTE 7 state only that.

Daniel answered three of the four readings on 2026-10-29. `state-machine.md` NOTE 14 records them. Late verification stays interim, pending Daniel.

- **Which deadline.** Decided 2026-10-29: the deadline of the call in which the proposal passes IRC review. A deferred proposal that re-enters under a later call (`state-machine.md` NOTE 8) uses that later call's deadline.
- **Late verification.** Interim, pending Daniel. An attestation verified at or before that deadline counts. One verified later counts only if its attributes give the lead's age at that deadline.
- **Override.** Decided 2026-10-29: when the vault holds a verified adult attestation and a verification that shows the lead under 18 at that deadline, neither wins. The conflict goes to a manual identity check (G9, "Manual identity checks" above). Proposed reading: until the check resolves it, `IsVerifiedAdultAtDeadline` does not answer, so the gate fails closed (`overview.md` NOTE 2) and the proposal stays where it is.
- **Second derivation.** Decided 2026-10-29: the guard into GRANTED asks `IsVerifiedAdultAtDeadline` again. When it finds the lead not adult, guardian consent collection opens in NEGOTIATION: `AddGuardian` is allowed and the cell issues the guardian's write ticket. A GRANTED decision records a new rules version. A verification in NEGOTIATION that shows the lead under 18 at the deadline then needs a verified guardian consent before GRANTED.

## Break-glass

Interim, pending Daniel (Q21). SoD-08 and TH-18 apply.

- Operator staff hold no binding in any cell.
- A break-glass request names one staff member, a scope of read actions and an end time at most 4 hours ahead (constant below).
- A tenant admin approves it with a step-up (`ApproveBreakGlass`). The cell records `BreakGlassApproved { grant, staff, scope, until }`.
- Staff reach the cell with a staff assertion signed by the control plane. The cell verifies it against a pinned key. Staff authenticate to the control plane with passkeys.
- The gate treats staff as a separate principal kind, `Principal::BreakGlass(GrantId)`. It admits them only for read actions inside the recorded scope and time.
- Every use is a `BreakGlassRead` record and appears in the tenant's audit view. `EndBreakGlass` ends a grant early.
- Content views for operators arrive with the M4 interfaces.
- Proposed reading: a self-hosted cell pins no staff assertion key, so it admits no break-glass principal.

## Constants

| Constant | Value | Basis |
| --- | --- | --- |
| Invitation lifetime | 72 hours | ADR constant with no P- id. Interim, pending Daniel (Q37) |
| Break-glass maximum | 4 hours | ADR constant with no P- id. Interim, pending Daniel (Q37) |
| P-71 step-up freshness | 5 minutes, tenant may only shorten | Marked "(proposed)" in `policy-parameters.md`. Interim, pending Daniel (Q37) |
| P-72 session lifetimes | 30 minutes idle, 12 hours absolute | Marked "(proposed)" in `policy-parameters.md`. Interim, pending Daniel (Q37) |
| SoD-07 approval lifetime | P-71 from the approval's step-up | Interim, pending Daniel (Q40) |
| Vault ticket lifetime | 5 minutes | ADR-009 |
| CBOR limits | Depth 4, 64 KiB | This ADR |
| RSA modulus floor | 2048 bits | This ADR |
| Session token | 32 random bytes | This ADR |

## Consequences

- No third-party authentication crate enters the tree. The cost is in-house CBOR, COSE and WebAuthn code near cryptography (risk R6). The strict subset, the fuzz targets and H-21 carry that risk.
- Magic links work only in tests until M6 delivers email.
- A magic-link account gains a passkey only through a ceremony. The `EmailThenPasskey` path serves that case.
- Every high-risk command costs one passkey assertion. If assignment lists make this heavy, Q38 offers a batched step-up per list.
- The first verified recorder now exists: the platform operator verifies each tenant's first tenant admin (Daniel, 2026-10-28). That path needs a composite-signed operator ticket, so production recording starts only once the moduletto ML-DSA-65 pull request lands (ADR-001 A2).
- The release window still confines a tenant recorder's reviews to subjects whose proposal is in NEGOTIATION or later. SoD-09 therefore still refuses Drafting and Judging grants in production to every account the operator did not verify. I-18 stays claimed over seeded facts (`09-milestones.md` NOTE 2).
- **No production proposal enters NEGOTIATION in M3 under the release-window interim.** Every proposal is minor-flagged unless its lead has an effective verified over-18 attestation (`state-machine.md` NOTE 14). Verifying either an attestation or a guardian needs a manual check before NEGOTIATION, since EUDI verification arrives in M4. The release window allows reviews only in NEGOTIATION or later. So no proposal passes IRC_REVIEW to NEGOTIATION in production. This is stricter than Q13 A and Q14 B intend, not a weakening, but it defeats both in M3 production.
- The open point "Reviews outside NEGOTIATION" therefore blocks any production claim of Q13 A and Q14 B. Until Daniel answers it, M3 claims both only over seeded facts.
- A verification fact also becomes provisional only after its Vault chain rotation completes. That rotation cannot pass ADR-004 erasure step 5 until Daniel settles how a Vault keystore snapshot is verified (ADR-012 open points).

## Tests

Each test names its ID, as `.claude/CLAUDE.md` requires. Design section 14.4 lists them in full.

- I-77: `i77_m_auth`, `i77_management_login_requires_phishing_resistant_method_over_http`, `i77_scheduled_end_ends_sessions_at_its_instant`, `i77_role_grant_ends_weak_sessions_in_the_same_batch`, Playwright `i77-management-login.spec.ts`, `i77_teeth_weak_session_admitted_is_caught`.
- I-78: `i78_high_risk_table_matches_spec_and_domain`, `i78_every_high_risk_route_and_command_needs_a_fresh_step_up`, `i78_route_without_risk_class_does_not_compile`, `i78_stepup_proof_cannot_be_built_outside_the_gate`, `i78_stepup_logged_with_action_digest`, `i78_p71_may_only_shorten`, `i78_m_stepup`, `i78_database_refuses_a_second_step_up_consumption`, `i78_teeth_stale_step_up_accepted_is_caught`.
- SoD-07: `sod_07_self_grant_needs_second_admin_approval_of_the_same_digest`.
- I-79: `i79_m_recover`, `i79_non_receiving_never_recovered_by_email_alone`, `i79_approver_differs_steps_up_and_is_not_the_same_identity`, `i79_sole_admin_needs_operator_ticket_shown_to_tenant`, `i79_teeth_path_checked_at_request_only_is_caught`.
- I-20: `i20_rp_id_is_the_exact_cell_host`, Playwright `i20-passkey-not-offered-across-tenants.spec.ts`.
- New with this ADR, to be written before the code they constrain:
  - `r_id_02_recorder_cannot_verify_own_account_or_same_identity`, including the interim refusal of any other recorder without a verified identity;
  - `r_id_02_first_tenant_admin_verified_by_two_operator_staff_and_shown_to_tenant`, proposed with the first tenant admin verification;
  - `i17_verification_review_ticket_refused_to_judging_holder`;
  - `i17_verification_review_ticket_only_in_negotiation_or_later`.

## Open points

- **First tenant admin verification details.** The mechanism, the SoD-08 reading and the self-hosted reading under "First tenant admin verification" are proposals. Each is fixed by amendment before W2b merges.
- **Reviews outside NEGOTIATION (blocking for any production claim of Q13 and Q14).** SoD-09 checks Drafting and Judging holders at binding time, with no proposal involved. Guardian checks (Q12 A) and manual over-18 checks (Q13 A) fall before NEGOTIATION. Each needs a person to see identity data outside the release window of `overview.md`. Options: a separate review operation on the vault origin with its own logged ticket, or no manual review outside NEGOTIATION, leaving those cases to EUDI in M4.
- **Minor flag details.** Daniel answered which deadline, override and second derivation on 2026-10-29. Late verification still waits for him.
- **Later Judging grants.** A recorder who later takes a Judging binding already saw what they reviewed. Daniel decides whether such a grant is refused in programmes where the recorder reviewed a subject.
- **Risk class of recording.** Recording a verification is not in the `authentication.md` high-risk table. It is not added silently. Daniel decides whether it joins `STRICT_ADDITIONS`.
- **Unset lifetimes.** The magic-link token, the recovery enrolment token, a recovery case and the staff assertion have no lifetime in the design. Each is fixed by amendment before W2b merges. `SPEC/` sets none of them: P-71 and P-72 cover step-ups and sessions only. Proposed by lane F-CYCLE2 on 2026-11-13, Interim, pending Daniel, and built as such in `fstp_cell_core::lifetimes`:
  - magic-link token: 15 minutes;
  - recovery enrolment token: 24 hours;
  - recovery case: 72 hours, as the invitation lifetime;
  - staff assertion of the operator process: 15 minutes.
  - email proof of a self-registration: 15 minutes, as a magic link (proposed by lane F-CYCLE3 on 2026-11-13).
  - email proof of a recovery case: the case lifetime, 72 hours (proposed by lane m3/login-m2http on 2026-11-13).
- **Login email index, magic links and recovery (lane m3/login-m2http, 2026-11-13).** Interim, pending Daniel. The keystore owner holds the `Lookup` keyed digest group. Its HMAC key is derived by HKDF from the group secret, so each batch that erases a login email replaces it (decision 27). The index lives with the keystore in process memory until the W2e keystore tables land. A self-registration binds its proven address, and an invitation binds the address its issuer names in the `email` member of the command body. Magic links and recovery email proofs go to the login email through the proof mail port until M6 delivers. Recovery body forms: `POST /auth/recovery {email}` answers 202 for every address. `.../{case}/email {token}` takes the email proof and answers the one-time enrolment token. `.../{case}/complete` takes an operator ticket (`{ticket}`), asks for creation options (`{enrolment}`), or completes with the registration and the enrolment token. The verified operator ticket is held in process memory until a record form exists. The completion's new session starts one microsecond after the completion's instant. P-70 reaches the cell as a start option (`StartOptions::login_methods`), since no record carries it.
- **Operator process checks.** The staff-side checks of `OperatorProcess` are not designed. Proposed: mirror the first-admin split, with one staff member confirming with the tenant contact and a second with the contract signatory. The channels are named in the operator procedure.
- **Self-registration without a passkey (question for Daniel).** May self-registration end without a passkey where the tenant enables magic links (P-70)? Proposed reading: yes. The account is then magic-link only, as R-LG-01 and the `authentication.md` methods table allow for applicants. `authentication.md` gives it its first passkey through recovery, which is the `EmailThenPasskey` ceremony. Until Daniel answers, `authentication.md` ceremony 2 is worded so that it neither requires nor excludes a passkey at self-registration. Built by lane F-CYCLE3, Interim, pending Daniel: `POST /auth/signup` takes the passkey members as optional. With them it creates the account and its first passkey. Without them it fails closed with 501 until Daniel answers. Lane m3/login-m2http built the login email index, so a passkey-less account could now sign in by magic link. The proof goes to the cell's mail port, which a production cell does not wire before M6 delivery.
- **Spec wording (Q28).** `authentication.md` now carries the Q15 answers. The other wording proposals of Q28 stay with Daniel. One more is proposed here: the `authentication.md` section "Crates" still names webauthn-rs and opaque-ke as candidates. ADR-001 amendment A4 rejects both. Proposed wording: "WebAuthn is built in-house (ADR-001 A4, ADR-008), with fuzz targets for its CBOR and COSE parsers from the first commit. OPAQUE waits for an ADR-001 addition that covers its group arithmetic." Daniel accepted A4 on 2026-10-28. The paragraph is not edited until he accepts this wording.

## Record

| Item | Value | Recorded |
| --- | --- | --- |
| Third-party crates added by this ADR | None | 2026-10-28 |
| `fstp-webauthn` fuzz targets in `deps/fuzz-required.txt` | Record at first use | Record at first use |
| ADR-001 "Open points" line on authentication crates | Closed by the ADR-001 amendment, accepted 2026-10-28 | 2026-10-28 |
