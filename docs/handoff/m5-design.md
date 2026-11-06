# M5 design: contracts, signing, payment requests and closure

Milestone M5 in `SPEC/09-milestones.md`: "Contracts and payment requests in record-only payment mode". Exit criteria:

- I-30 to I-33 are green;
- a call cycle runs through to PAID.

Daniel's additions of 2026-11-06:

- M5 must carry a speedrun video of the whole process: programme setup, application, agreement signing, documentation of work done with a payment request, and closure of the programme.
- R-RP-04 moves from M9 into M5, so the five Horizon Europe funder outputs are generated at closure. I-44 is claimed with them.
- The Guide PDF (R-GA-02) lands in M5 (M4 Q28).
- Online signing builds on a vendored copy of LibPDF-js/core (ADR-016, Proposed). Signing cryptography still comes from ADR-001.

Deferred and out of scope: bank execution (B-11), external MCP integrations (B-10), email dispatch of notices (M6, so I-40 is claimed there), reallocation (R-PR-11, I-63).

Status: draft for Daniel's review. Labels such as `L-SIGN` or `Q2` exist only in this document. Every `I-`, `R-`, `P-`, `SoD-` and `ADR-` identifier is quoted from the repository. Crate, type, op and table names are design proposals.

Sources read: `SPEC/README.md`, `09-milestones.md`, `02-domain/{invariants,contracts,payment-requests,state-machine,roles-and-sod,policy-parameters,contractual-notices}.md`, `01-requirements/functional.md`, `03-architecture/{funder-reporting,overview,authentication}.md`, `docs/design/10-post-grant-screens.md`, `docs/handoff/m4-design.md` (sections 6.3 and 15), `docs/handoff/m4-demo.md`, ADR-001, ADR-003, and the code of `fstp-domain` (`grant.rs`, `payment.rs`, `amendment.rs`, `command.rs`), `fstp-engine/src/sweep.rs`, `fstp-access/src/registry.rs` (`LATER`), `fstp-pki` and the e2e cell.

---

## 1. What M5 builds

### 1.1 What already exists

The M2 domain core already decides most M5 commands. M5 mostly adds the contract subsystem, the checks, the vault facts, the ops and the screens.

| Exists in `fstp-domain` | M5 adds |
| --- | --- |
| `DetermineAmount`, `AcceptGrant`, `ApproveGrant`, `ContractFact { Effective }`, `grant_preconditions` | Ops for them (all in `LATER`), and the contract port that issues `ContractFact` |
| `StartExecution`, `Complete`, `CloseMilestone`, `Terminate` | Sweep wiring for the two System rows, ops for the two human rows |
| `RequestPayment` to `ConfirmPaid`, I-05 typestate, I-58 to I-60, I-64 | UNDER_REVIEW and CHECKS_FAILED, checks and snapshots (I-32), hardship kind, I-31 and I-33 release guards |
| `RecordDeliverable` (I-15 record) | The checks that issue it |
| `ProposeAmendment`, `RouteAmendment`, `ActivateAmendment` | Amendment contract versions (I-30), last on the lane plan |

### 1.2 The speedrun path

Each row is one scene of the video. "M4" rows already run.

| # | Step | Person | M5 work |
| --- | --- | --- | --- |
| 1 | Build and activate SuperSAFE | Programme manager, second tenant admin | M4 |
| 2 | Publish the call with the Guide, HTML and PDF | Programme manager | Guide PDF |
| 3 | Draft and submit a proposal | Applicant | M4 |
| 4 | Knock-out, scoring, ranking, IRC to NEGOTIATION | Coordinator, reviewers, committee, IRC | M4 |
| 5 | Verify identity, determine amount, accept, approve | Lead, reviewer, programme manager | Ops |
| 6 | Draft contract, agree a clause change, send | Programme manager, lead | Contract subsystem |
| 7 | Lead signs, signatory countersigns, GRANTED | Lead, Contract signatory | Signing |
| 8 | Clock to first milestone start, IN_EXECUTION | Demo clock | Sweep |
| 9 | Enter bank details; finance verifies; hold elapses | Lead, Finance approver | Vault, I-33 |
| 10 | Payment request with evidence; one check fails; resubmit | Lead | Checks, I-32 |
| 11 | Line review, payment approval, release, paid | Reviewer, Finance approver, Payment releaser | I-05, I-31 |
| 12 | Hardship request with vault evidence | Lead, Finance approver | Hardship, I-31 |
| 13 | Close milestones; COMPLETED | Programme manager, sweep | I-64 |
| 14 | Generate the five funder outputs; approve | Programme manager, approver (Q3) | R-RP-04, I-44 |

---

## 2. Readings

Each reading follows the source-of-truth order in `.claude/CLAUDE.md`. Each is interim until Daniel confirms it.

1. **Who creates a party's signature.** `contracts.md` says signatures are created in the signer's wallet or at a QTSP, "never by the platform". The server therefore builds the CMS structure and digest, but the signature value comes from the wallet or QTSP. The platform's own key signs only tenant seals (P-47): sealed drafts and contractual notices. This keeps the brief's split without weakening the spec.
2. **Line review actor.** `payment-requests.md` and the M2 code give line review to assigned reviewers. Design 10 gives it to the finance approver. The spec wins: assigned reviewers accept lines, the finance approver records PAYMENT_APPROVED.
3. **First bank details count as a change (I-33).** Every write of bank details, the first one included, needs verification and P-36 before a release. This is the strict reading. The demo advances the clock.
4. **Resubmission after CHECKS_FAILED.** A resubmission withdraws the failed request and records the new one in one ledger entry. Its pending amounts return first, so I-58 holds (design 10: "a new request reference").
5. **Decline before signature (R-NG-04).** Declining is `Withdraw` (NEGOTIATION to WITHDRAWN) plus contract TERMINATED. The unsigned draft is sealed and kept (`contracts.md`).
6. **Record-only release.** RELEASED records a payment record file with the request reference, amount and payee reference, and no bank details. The releaser reads the bank details on the vault origin for that one request, after a step-up.
7. **Periodic reporting data.** The cell computes every figure per pseudonymous recipient reference. The vault origin joins legal form and country at download, for an Operations role holder after a step-up (I-86, download row of `authentication.md`).
8. **Contract renderer timing.** The M4 public pages note says the contract preview waits for "a contract renderer (M8)". M5 builds that renderer, so the preview lands in M5.
9. **Channels.** Every new M5 op is web only, and MCP answers `Deny(NotExposed)`, as M4 Q32 A did for high-risk ops. This keeps the matrix small for M5.
10. **Hardship lines.** Until Q4 is answered, a hardship request has lines on milestones like any request. I-58 and I-31 then both bound it.

---

## 3. Online signing with LibPDF

### 3.1 The split

Node.js never runs on a cell host (ADR-003 amendment of 2026-10-28). The vendored LibPDF therefore runs only in the signer's browser, in a module Worker. The server stays the authority and treats every byte the browser sends as untrusted.

| Step | Where | What |
| --- | --- | --- |
| 1 | Server, `fstp-pdf` | Renders contract version N as revision 0, deterministically (R-CT-01). It declares one empty signature field per party, each with a pre-rendered appearance stream. No object streams, no xref streams, no filters on structural objects |
| 2 | Server | Records `ContractSent` with the SHA-256 of revision 0 (aws-lc-rs). The version is now frozen |
| 3 | Browser, LibPDF | Loads the current revision, sets the party's field value to a new signature dictionary (`/SubFilter /ETSI.CAdES.detached`, fixed-size `/Contents` placeholder), saves incrementally and patches `/ByteRange`. It sends only the appended bytes. It does no hashing, no signing and no font work |
| 4 | Server, `fstp-pdf` | Concatenates the stored revision and the increment, so the prefix is exact by construction. The strict increment verifier accepts exactly one new signature dictionary, the party's field object with `/V` added, one xref section and a trailer whose `/Prev` and `/Root` match. Anything else is refused |
| 5 | Server, `fstp-crypto` and `fstp-pki` | Computes the `/ByteRange` digest with aws-lc-rs, then encodes the PAdES baseline B-B signed attributes in DER (in-house `fstp-pki::cms`) |
| 6 | Signer, at the wallet or QTSP | The signer authorises. The `SignaturePort` returns the signature value and certificate chain |
| 7 | Server, `fstp-sigval` | Verifies the value with aws-lc-rs and validates the chain under the in-house procedure (`contracts.md` Signature). It parses certificates through the Tier B formats crates (ADR-001 Uses, "Qualified signatures") |
| 8 | Server | Writes the CMS `SignedData` into `/Contents`, stores the new revision write-once, and records `SignatureApplied` |

Seals use steps 1, 4 to 5 and 8 without a browser. The signature value then comes from the tenant seal key in cell custody (ADR-004), through aws-lc-rs.

Why the browser prepares at all: Daniel asked for LibPDF as the signing base. The design keeps LibPDF out of the trust base. A faulty or hostile increment gains nothing, because step 4 defines the increment exactly.

### 3.2 Signature routes (P-30)

`SignaturePort` has three routes: `WalletQes`, `QtspRemoteQes` and `Advanced`. The advanced route needs a programme manager approval with a reason first (`contracts.md` cascade step 3).

- Test and demo: a fake adapter on the control base plays the wallet and the QTSP. It holds a test CA made with aws-lc-rs and signs with it, as the fake passkey port does for login. A fake trusted list names that CA.
- Production: each route refuses with a typed error until a real adapter and trusted-list source exist (Q2). Nothing falls back to a platform-made signature.

### 3.3 Guide PDF (R-GA-02)

`fstp-guide` renders the canonical Guide document through `fstp-pdf` at publication. The record `GuidePdfRendered { call, version, digest }` joins the publication entry. Re-rendering the stored canonical document gives the same bytes, so calls published in M4 get their PDF on first read. LibPDF plays no part in it.

The PDF is tagged (structure tree, `/MarkInfo`, `/Lang`). A PDF/UA conformance check needs a validator that no ADR allowlists yet, so M5 claims tagged structure only. Full validation goes to M10.

### 3.4 One font

`fstp-pdf` embeds one font under the SIL Open Font License 1.1, in full and without subsetting. Its glyph widths come from an in-house TrueType table reader, which gets a fuzz target. The font asset needs its own short ADR (ADR-017) before lane L-PDF embeds it. The signature appearance streams reuse that font from revision 0.

---

## 4. Data model and records

### 4.1 Contract records (`fstp-contract`, ledger envelope `Contract`)

The engine composes `ContractEffective` and the core `ContractFact { Effective }` into one entry, as M4 change D2 does for activation.

| Record | Fields | Rule |
| --- | --- | --- |
| `ContractDrafted` | contract, proposal, version, template (P-29), plan, determination, parties, base digest | R-CT-01, I-49 |
| `ClauseChange` | contract, version, clause, diff text ref, proposer role, status | R-CT-04 |
| `ContractSent` | contract, version, revision 0 digest | Asks `grant_preconditions` |
| `AdvancedApproved` | contract, version, party, approver, reason | P-30 step 3 |
| `SignatureApplied` | contract, version, party, route, revision, revision digest, signer certificate digest, validation report digest | I-30 |
| `ContractEffective` | contract, version, final digest | Countersignature last; asks `grant_preconditions` again |
| `VersionSuperseded` | contract, old version, new version | Amendment EFFECTIVE |
| `ContractTerminated` | contract, version, reason, sealed draft digest if unsigned | `contracts.md` Rules |

Parties come from the contract: the lead, each team member the programme requires, the guardian of a minor (R-CT-02), and the Contract signatory. SIGNED_BY_GRANTEE holds once every grantee-side party has a `SignatureApplied`.

### 4.2 Domain changes (`fstp-domain`)

- `RequestPayment` gains `kind` (milestone or hardship) and per-line evidence: location, release, SPDX licence and report text refs (P-34). A hardship request carries an opaque vault evidence reference.
- New System command `RecordChecks { request, phase, results, snapshot }`. Phase "submission" moves SUBMITTED to UNDER_REVIEW or CHECKS_FAILED. Phase "acceptance" must have passed before the line decision that makes a request ACCEPTED (I-32).
- `ResubmitPaymentRequest` (reading 4).
- `ApprovePayment` on a hardship request asks the vault `HardshipEvidenceVerified` (Q1, Q4).
- `ReleasePayment` gains two guards: released plus this request stays within the effective contract amount (I-31), and the vault answers `BankReleasable` (I-33, Q1). Both fail closed.
- `PaymentReleased` gains the digest of the record-only payment record file.
- The sweep (`fstp-engine/src/sweep.rs`) keeps its two kinds and adds `StartExecution` and `Complete`, both taken from `fstp_domain::due`.

### 4.3 Storage

| Store | Content | Guard |
| --- | --- | --- |
| `doc.blob` in the cell database | Every PDF revision, sealed draft, report and payment record file, keyed by SHA-256 | The `app` role has INSERT and SELECT only, as ADR-015 does for journey rows. A second insert of a digest with other bytes fails (I-30) |
| Ledger | The records above, each digest in the audit chain (I-24) | Append-only (I-23) |
| Vault | Bank details, bank verifications, disputes, hardship evidence | Sealed under hybrid-wrapped data keys (ADR-001 Uses) |
| Ledger, envelope `Report` | `ReportGenerated { report, kind, scope, snapshot digest, template version, document digest }`, `ReportApproved { report, approver }` | R-RP-01, R-RP-03 |

---

## 5. Ops, reads, channels and separation of duties

Every op is web only (reading 9). "HR" marks a high-risk op that needs a step-up within P-71 (I-78).

| Op | Actor | Command or record | SoD and guards |
| --- | --- | --- | --- |
| `grant.determine_amount` | Assigned reviewer | `DetermineAmount` | I-03, I-13, I-14, I-34 |
| `grant.accept`, `grant.approve` | Lead; programme manager | `AcceptGrant`, `ApproveGrant` | Name the current determination (NOTE 9) |
| `contract.draft` | Programme manager | `ContractDrafted` | I-49 under the Horizon Europe profile |
| `contract.propose_change`, `contract.decide_change` | Lead or programme manager; the other side | `ClauseChange` | R-CT-04 |
| `contract.send` | Programme manager | `ContractSent` | No open clause change |
| `contract.prepare_signature`, `contract.complete_signature` | Each party | `SignatureApplied` | Party of this version; SoD-03 for the signatory |
| `contract.request_advanced`, `contract.approve_advanced` | Party; programme manager | `AdvancedApproved` | Reason required |
| `contract.decline` | Lead | `Withdraw` plus `ContractTerminated` | Before any grantee signature |
| `grant.terminate` | Programme manager | `Terminate` plus `ContractTerminated` | Reason required |
| `milestone.close` | Programme manager | `CloseMilestone` | Reason required |
| `payment.save`, `payment.submit`, `payment.resubmit`, `payment.withdraw` | Lead | `RequestPayment`, `ResubmitPaymentRequest`, `WithdrawPaymentRequest` | I-58, I-59, I-62 |
| `payment.review_line`, `payment.request_changes` | Assigned reviewer | `AcceptLine`, `RequestPaymentChanges` | I-32, I-60, SoD-12 |
| `payment.approve` (HR) | Finance approver | `ApprovePayment` | Hardship evidence bit |
| `payment.release` (HR) | Payment releaser | `ReleasePayment` | I-05, SoD-04, I-31, I-33 |
| `payment.confirm_paid` | Finance approver | `ConfirmPaid` | Record-only |
| `payment.close` | Programme manager | `ClosePaymentRequest` | O-51 |
| `report.generate`, `report.approve` | Programme manager; approver of Q3 | `ReportGenerated`, `ReportApproved` | Approver is not the generator; I-44 |

Vault origin ops, never in the API or MCP (I-86):

| Op | Actor | Effect |
| --- | --- | --- |
| `vault.bank.set` (HR) | Lead | New bank detail version; starts the hold (I-33) |
| `vault.bank.verify` | Finance approver | Verification record: method, checks, verifier, time, no document numbers (R-ID-02 style) |
| `vault.bank.dispute` | Lead | Freezes releases for the grant; alerts the finance approver queue |
| `vault.bank.view_for_release` (HR) | Payment releaser | Shows the payee details of one RELEASED request (reading 6) |
| `vault.hardship.submit`, `vault.hardship.verify` | Lead; finance approver | Hardship evidence and its verification |
| `vault.report.download` (HR) | Holder of an Operations role | Periodic reporting data with joined attributes (reading 7) |

Reads: `grant.overview`, `contract.view` (versions, signatures, hashes), `payment.form` (amount, paid, pending, available per milestone and task, R-PR-07), `payment.status`, the reviewer, approval and release queues, `report.list` and `report.view`. `me.roles` gains the Operations queues of `home-operations.html`. Finance and operations roles read under "grants only" (journey matrix).

---

## 6. Screens per role (`docs/design/10-post-grant-screens.md`, binding)

| Role | Screens |
| --- | --- |
| Lead (grantee) | `negotiation.html`, `contract-drafted.html`, `contract-view.html` (sign, decline, request advanced), `payment-request-form.html`, `payment-status.html`, `payment-checks-failed.html`, the vault bank and hardship pages |
| Assigned reviewer | Amount determination on the negotiation case, `payment-request-review.html` |
| Programme manager | `contract-drafted.html`, `contract-advanced-approval.html`, `contract-terminal.html`, milestone closure on the grant overview, `funder-report.html`, `report-generation-failure.html` |
| Contract signatory | `home-signatory.html`, `contract-signatory.html` |
| Finance approver | `home-operations.html` approval queue, payment approval, vault bank verification and hardship verification |
| Payment releaser | `payment-release.html`, with the SoD-04 blocked row and the I-33 hold row |
| Report approver (Q3) | `report-approval.html` |
| Auditor | `audit-log.html`, `funder-report.html` read only |
| Public | Guide PDF link on the call page |

The signing page loads the LibPDF Worker. It shows the formal state beside each badge (I-96). Amounts are server-formatted (ADR-006).

---

## 7. Demo cell additions

The rule is the click-through check: each person reaches their work by clicking from sign-in.

- **Speedrun scene.** `GET /demo/speedrun` gives a fresh cell with an active organisation and every person of section 1.2 enrolled and bound through production commands. No programme exists yet. The demo page lists each person with "Sign in as" and one line on what they do.
- **Checkpoint scenes.** `GET /demo/grant?at=` with `NEGOTIATION_READY`, `SENT`, `EFFECTIVE`, `IN_EXECUTION`, `UNDER_REVIEW`, `PAID` and `ALL_CLOSED`, for retakes.
- **Fake trust services.** `/demo/sign/authorise` on the control base plays the wallet and QTSP consent page with one "Authorise signature" button.
- **Fake forge.** `/demo/forge/` serves public synthetic repositories with licence files. One release answers 404 for the CHECKS_FAILED scene. The e2e cell egress reaches only this forge.
- **Vault origin.** The e2e cell serves the vault origin, which M4 did not. The finance approver verifies bank details there.
- **Clock.** Links for "advance to first milestone start" and "advance P-36".

The Playwright journey `e2e/speedrun` runs the whole path from sign-in links only. It is the M5 exit test for "call cycle through to PAID".

---

## 8. Tests first, per invariant

Each test names its ID. Each property test lands red before the code it constrains.

| ID | Tests |
| --- | --- |
| I-30 | Property over random contract command sequences: a signed version's digest never changes; each later revision has every earlier revision as exact byte prefix; content changes after `ContractSent` are refused except as a new version; EFFECTIVE needs every party of that version. Storage test: a second `doc.blob` insert with other bytes fails. Fuzz: the increment verifier refuses every increment that touches another object |
| I-31 | Property over random requests, hardship requests, line decisions, releases and amendments: released total never exceeds the effective contract amount. A direct guard test at `ReleasePayment` |
| I-32 | Acceptance refused without passed checks and both snapshots. A check failure yields CHECKS_FAILED with reasons (R-PR-02). An upstream change after a snapshot leaves the recorded evidence unchanged (TH-24) |
| I-33 | Property over random clock, bank write, verification and dispute events: no release before verification and P-36 after the latest write, none while a dispute is open. Vault unavailable refuses the release (fail closed) |
| I-05, SoD-04 | Rerun through the ops and HTTP channel |
| I-16 | Rerun over the record-only payment adapter: the port has no transfer method, no bank credential type exists in the cell, release writes only a record |
| I-39 | Rerun with payment ops while the update and licence services are down |
| I-44 | Every figure of each output equals an independent ledger fold at the snapshot; a seeded mismatch fails generation and lists it |
| I-15, I-58, I-60, I-62, I-64 | Reruns through the API |
| I-78, I-86 | Step-up on every HR op; no reply of any API or MCP op holds bank details or vault evidence |
| R-CT-01, R-GA-02, I-53 | Byte-identical regeneration of contracts and the Guide PDF; a published Guide PDF never changes |
| I-93, I-97 | New diary entries (signed, released, paid) pass the visibility function and hold no free text |

The authorisation matrix gains every op of section 5 (M4 Q34 B).

---

## 9. Dependencies and ADRs

| Item | Status | Effect |
| --- | --- | --- |
| ADR-016, vendored LibPDF | Proposed (this lane) | Gates lane L-LIBPDF |
| ADR-017, the PDF font asset | To write in lane L-PDF | Gates the font embedding |
| ADR-001 record, Tier B `der`, `spki`, `x509-cert`, `cms` | First use in `fstp-sigval` | Versions and tree recorded; I-74 release gate applies |
| ADR-003 amendment, Jazzer.js (M4 Q33 B) | Not yet written | Until it lands, TypeScript targets run under the in-house harness of `web/fuzz` |
| Spec change, two vault queries (Q1) | Pending Daniel | Gates `L-VAULT` |

No new crate or npm package beyond these rows.

---

## 10. Lanes

At most three lanes run at once (medium mode). Each lane owns its files. A lane starts when its dependencies have merged into `main`. The order puts the happy path of the speedrun first.

| Lane | Builds | Owns | Needs |
| --- | --- | --- | --- |
| L-DOM | Section 4.2 and the invariant property tests for I-31, I-32, I-33 | `crates/fstp-domain/src/{payment,grant,command,record,rules,refusal,oracle}.rs`, `codec/`, `crates/fstp-domain-testkit/src/reference/`, `crates/fstp-engine/src/sweep.rs` | None |
| L-PDF | `fstp-pdf` writer, increment verifier, TrueType reader, `fstp-pki::cms`, fuzz targets, ADR-017 | `crates/fstp-pdf/**`, `crates/fstp-pki/src/cms.rs`, `crates/fstp-pki/fuzz/`, `docs/adr/ADR-017-*` | None |
| L-LIBPDF | Vendored import, reductions, signing Worker, TypeScript fuzz targets (ADR-016) | `web/vendor/libpdf/**`, `web/src/sign/**`, `web/fuzz/pdf_*` | ADR-016 accepted |
| L-CON | `fstp-contract`, the `Contract` envelope, `doc.blob`, `SignaturePort` with fake adapter, `fstp-sigval`, I-30 tests | `crates/fstp-contract/**`, `crates/fstp-sigval/**`, `crates/fstp-engine/src/contract.rs`, `crates/fstp-pgstore/migrations/` (next number), ADR-001 record rows | L-DOM, L-PDF |
| L-API | Ops and reads of section 5, `LATER` emptied, matrix rows | `crates/fstp-access/src/{registry,reads,replies}.rs`, `crates/fstp-api-core/src/**` | L-DOM, L-CON |
| L-UI1 | Negotiation, contract and signing screens | `web/src/grant/**`, `web/src/contract/**` | L-API, L-LIBPDF |
| L-UI2 | Payment, finance, release and closure screens | `web/src/payments/**`, `web/src/operations/**` | L-API |
| L-CHK | Checks runner, egress rules, SPDX detection, snapshots | `crates/fstp-checks/**`, `crates/fstp-cell/src/egress.rs` | L-DOM |
| L-VAULT | Bank details, hardship evidence, the two queries, vault origin pages | `crates/fstp-vault*/**`, `web/src/vault/**` | Q1 |
| L-RPT | Funder outputs, `Report` envelope, Guide PDF | `crates/fstp-report/**`, `crates/fstp-guide/src/pdf.rs` | L-PDF, L-DOM |
| L-DEMO | Section 7 and the Playwright speedrun | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/**`, `e2e/speedrun/**`, `docs/handoff/m5-demo.md` | All above |
| L-AMD | Amendment contract versions and SUPERSEDED | `crates/fstp-contract/src/amendment.rs`, amendment ops | L-CON, L-API |
| L-EXIT | Reruns of I-05, I-16, I-39, exit audit | `docs/handoff/m5-exit-audit.md`, rerun test files | All above |

Waves: L-DOM, L-PDF and L-LIBPDF first. Then L-CON, L-CHK and L-RPT. Then L-API, L-VAULT and L-UI1. Then L-UI2, L-DEMO and L-AMD. L-EXIT closes. The speedrun reaches PAID after L-UI2 with the fakes. Hardship, the bank hold and the reports follow in the same wave.

---

## 11. Security notes

- **Untrusted PDF bytes.** The increment verifier is the only Rust code that reads PDF bytes from a browser. It has bounded sizes, no recursion beyond a fixed depth and a fuzz target from its first commit.
- **Deliverable fetches.** The checks fetch URLs that grantees supply. They go through the cell egress with private, loopback and link-local ranges refused, a size cap and a time cap. Fetched content is untrusted data. It is hashed and never passed to a model as instructions (`SPEC/04-llm-assessment/assessment.md`).
- **Bank details.** They never leave the vault origin except on the releaser's view of one request. Changing them is HR, and the hold applies to every write (reading 3).
- **Seal key.** The tenant seal key stays in custody and signs only seal digests that `fstp-contract` or the notice builder computed.

---

## 12. Questions for Daniel

Only questions that block a lane are listed. Every other point is a reading in section 2.

**Q1. Two vault queries (blocks L-VAULT and the I-33 and hardship guards).** The vault query set is decided (`overview.md`). I-33 and hardship need two more one-bit answers.

- A: Add `BankReleasable(grant, at, P-36)`, which is yes only when the latest bank detail write is verified, P-36 has elapsed since it and no dispute is open, and `HardshipEvidenceVerified(request)`. Both through a spec change, as for M4 Q35.
- B: The cell records bank write and verification times itself, with no attributes, and asks only one query for disputes.
- Recommendation: A. The hold stays where the facts live, and the cell learns one bit.

**Q2. Production trust services in M5 (blocks the production claim, not the video).** Signing needs a wallet or QTSP adapter and a trusted-list source. Seals need a seal certificate.

- A: M5 ships the ports with fakes for test and demo, and production refuses with a typed error. Real adapters follow in a later lane.
- B: M5 adds one remote-signing adapter for a named QTSP and EU trusted-list parsing.
- Recommendation: A. The video and the exit test run on fakes, as M4 does for passkeys. B needs a QTSP contract and an XML parser with its own fuzz target. `TODO(legal)`: which signature and seal levels the SuperSAFE MoU needs.

**Q3. Who approves funder documents (blocks L-RPT, R-RP-03).** The spec names "a named Operations role".

- A: A Financial signatory, who is not the generator.
- B: A Legal signatory.
- C: Either signatory.
- Recommendation: A. The documents report money paid and committed, which matches the Financial signatory's role.

**Q4. Shape of a hardship contribution (blocks the hardship part of L-DOM).** I-31 counts hardship against the contract amount. The spec does not say whether hardship lines claim milestones.

- A: Hardship lines claim milestones of partly delivered work, so I-58 and I-31 both bound them, and the request carries vault evidence.
- B: Hardship is one amount against the contract outside any milestone, bounded by I-31 alone.
- Recommendation: A. It keeps "proportional to delivered work" checkable. `TODO(legal)`: L-11, how hardship is reported under Annex 1.

### 12.1 Daniel's answers (2026-11-06)

| Question | Answer | Effect on this design |
| --- | --- | --- |
| Q1, two new vault queries | Yes | `BankReleasable` and `HardshipEvidenceVerified` join the decided query set through a spec change. Each answers one bit and names no account |
| Q2, production signing in M5 | Fakes now, production later | M5 ships fake wallet, QTSP and trusted-list adapters for tests and the demo. Production refuses with a typed error until a real QTSP adapter and EU trusted-list parsing land. Signature levels per the MoU stay `TODO(legal)` |
| Q3, who approves funder documents (R-RP-03) | A Financial signatory | The approver is a Financial signatory who did not generate the document |
| Q4, shape of a hardship contribution | Milestone lines | Hardship lines claim milestones of partly delivered work, so I-58 and I-31 both bound them. `TODO(legal)` under L-11 |
| Payment request line review | Assigned reviewers | The spec and the M2 code stand. Design 10 is corrected: the finance approver approves the release, not the line review |
| I-33 hold | Every write | Every bank-detail write starts the re-verification hold and the P-36 wait, the first entry included |
| MCP in M5 | Read-only tools | The grantee and finance rows of the capability table get read-only MCP tools for contract and payment status. Every M5 command stays web only and MCP refuses it as not exposed (I-85). No bank detail, identity or vault value is returned (I-86) |
