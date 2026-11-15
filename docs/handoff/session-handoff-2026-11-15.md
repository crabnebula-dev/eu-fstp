# Session handoff, 2026-11-15

For the lead session that takes over from the session of 2026-11-11 to 2026-11-15. Read `.claude/CLAUDE.md` first, then this file.

## Working rules Daniel set in this session

- Spend the laptop's time building. No authorisation matrix runs on the laptop, not even narrowed ones. No local M-ACTIVATE model checks unless a lane touches activation. No full demo Playwright suite per lane.
- Lanes verify with fmt, clippy, the touched crates' tests, the gen-ts check and the six web commands. Lanes run only their own new Playwright specs.
- Push a merge as soon as its lane gates pass. Run the lead's combined gate after the push and fix forward.
- At most three lanes at a time, unless Daniel asks for more. Lane test and matrix threads default to 2 (`.lanes/.cargo/config.toml`, `.lanes/testlock.sh`).
- Daniel's demo: `FSTP_DEMO_STATE=$PWD/target/demo-daniel FSTP_DEMO_PORT=8640 tools/demo/run.sh start|stop`, front door http://127.0.0.1:8641/demo. Restart it after each push that changes the product. Lanes never touch ports 8640 to 8643.
- When development is done, run CI once with the matrices, then patch what it names. The CI matrix parts still run on every push. A change to make them manual-only was refused by the permission system and waits on Daniel.

## Decided in this session

ADRs and SPEC amendments on main: ADR-021 (setup gate until activation), ADR-022 with SA-06 (tenant admin override of I-67), ADR-023 with SA-07 (coordinator unmasks parties, I-17 amended). Also decided, to be built:

| Item | Decision |
| --- | --- |
| Q-I79 | Record a second admin's approval as evidence on any recovery path (the cell changes) |
| SoD-08 break-glass | `BreakGlassApproved { grant, staff, scope, until }` |
| ADR-007 erasure causes 1 and 4 | A tenant admin requests all four causes; the system reminds at retention expiry |
| R-NF-08 sealed blobs | Record the layout (12-byte nonce, then ciphertext and tag) in ADR-004 |
| I-52 | Domain generators supply Guide facts; the fold is strict |
| Ledger seams | Compare after set-up; positions relative to the scenario start |
| I-66/I-67 generator gaps | Production adds restart (keeps saved work), narrative edit after save and import removal; the reference drops field effects of invitations, withdrawals and import resolutions; invalid policy refused at save counts; Guide section gap seeded via template; reference aligned to D3 (docs/handoff/m4-design.md, last section) |
| Wizard | Exact email only; Operations roles as planned rows; invitations carry dates |
| `tenant.complete` | SoD-07 (second admin) before the step checks |
| r_nf_08 caller nonce | `approval_challenge` listed in NOT_SEALS (done) |
| Audit log readers | Tenant admins and the programme's FSTP coordinator read it read-only, beside the auditor (lane `m4/audit-readers`, SA-08) |
| R-PC-03 in the reference | Every publisher is refused while the call is unapproved (approved, merged) |
| Matrix: guard refusal versus expected step-up | Accepted (evening). A guard refusal agrees with an expected step-up, as design 3.7 step 5 runs the dry run first. Restore the change held in 5eaea99a |
| Devstack and Node | ADR-003 amended: the `devstack` CI part may compile the auth pages with tsc before `cargo test` |
| ADR-021 | Account security set open to all before activation; request_activation checks conditions, no `OnboardingCompleted` record; `/p` pages answer an HTML "not published yet" page |
| ADR-022 | Readings accepted; a building tenant admin gets an "override available" mailbox item |
| ADR-023 | No notice to the unmasked person; a declared conflict is allowed and flagged in the record and audit read; purpose stays 500 characters; unmask works on DRAFT proposals too |
| Wizard | Planned rows email at once; Operations invitees accept role-only terms |
| Cell routes | AddPasskey digest over the command id accepted; identity release stays lead-only |
| P-41 reminder | A timeline event kind at the end of P-41 per action, and a mailbox message to tenant admins linking to the erasure request |

## Lanes at the time of handoff

| Worktree | Branch | State |
| --- | --- | --- |
| (merged, pushed) | `m4/audit-publish-import`, `m3/cell-routes`, `m4/ops-roles-agents`, `m4/audit-readers`, `m4/internal-seams`, `m3/decisions-a` | On main at handoff: audit log and its readers; add passkey, vault tickets, applied self-grants; agents, roles and pending reads; the last API-core seams (journal folds the ledger, sealed workspace store, text reads under clearance); Q-I79, SoD-08 break-glass, ADR-007 causes, ADR-004 sealed layout. Known-red is down to 16 entries |
| `.lanes/decB` | `m4/decisions-b` | Created, not started: I-52, ledger seams, I-66/I-67 creator commands |
| `.lanes/finish` | `m3/finish-gaps` | Created, not started: `i24_system_tasks` seed, wizard name at stage 1 and approver count, cell erasure gaps, CellBackup scan, devstack specs |
| (merged, pushed dc606d38) | `m4/page-gate` | SA-09 page gate |
| `.lanes/i66` (running) | `m4/i66-gaps` | I-66/I-67 generator gaps per m4-design last section |
| (merged, pushed a77c0c65) | `m5/retention` | P-41 reminder from the last payment confirmation, mailbox message, `/app/admin/erasures` page; P-70 in SetLoginPolicy; level 2 key records |
| (merged, pushed 782dc5ad) | `m3/erase-prod` | Witness revocation record, batch erasure approval, keyd sign-key slots, edge route table polling, S3 list and delete |
| `.lanes/m9` (running) | `m9/answers` | Milestone publicity opt-in, P-57 periods, tenant copies of funder profiles, programme footer in /app, companion key rotation reminder, profile read for all programme staff |
| (queued) | `m4/acme` | In-house fuzzed ACME client (ADR-009 Q30) |
| (queued) | `m4/ci-fixes-2` | After the CI run on current main: remaining matrix ops, other reds it names, and `CellObjects` out of erasure step 2 (ADR-004 night decision) |
| `.lanes/devstack` (running) | `m3/devstack-scenarios` | `/test/scenario/negotiation` and an active programme for the last 9 devstack specs |

The briefs for decB and finish are in the transcript of this session. In short, each item in the two tables above.

## After the lanes

Start the two lanes not yet run (`.lanes/decB`, `.lanes/finish`), one after the other or both, with lean gates. Their scope is in the decision table above and in the `m3/finish-gaps` list: wizard name at stage 1 and approver count, cell erasure gaps, CellBackup scan, devstack specs. The `i24_system_tasks` seed is already refreshed.

Open points from the merged lanes: `Workspaces` and the R-NG-06 acknowledgement have no PostgreSQL port in `fstp-cell` yet; no HTTP route serves break-glass staff reads yet (M4 operator views); the P-41 retention reminder has no timeline source; the Ticket key is handed in, not kept in the keystore.

1. Merge decB and finish when done, push, restart the demo.
2. One CI run with the full matrices. Patch what it names.
3. Update `README.md` status, `docs/handoff/m3-exit-audit.md` and the M9 audit.

## Open questions for Daniel (not blocking)

- P-41 (lane m5/retention, interim): no email at retention end, mailbox only; a grant with no PAID request gets no retention start; the erasures page erases only grants whose retention ended (TODO(legal): which records P-41 covers); the cell gate does not class `EraseTexts` as high-risk yet (step-up enforced in the API core).
- ADR-021: the admin's own set and the fail-closed port default (not asked yet).
- ADR-023: legal basis and retention of the purpose text (TODO(legal)); whether another FSTP coordinator of the programme counts as unmaskable staff (interim: yes).
- ADR-023 notice: Daniel chose no notice; the GDPR transparency TODO(legal) stays.
- M10 Mythos run: Daniel can run it any time, and chose to wait until all phase 1 development is done (2026-11-15). Daniel has access to Claude Mythos 5.2. Before it: record that model, update the threat model, freeze one commit.
- Not finishable here: M7 live-model evaluation, M10 Mythos run, M11 pilot, M12 calibration.
