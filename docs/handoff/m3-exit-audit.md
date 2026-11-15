# M3 exit audit

Written on 2026-11-13 by the lead, against `main` after the lanes of that night merged. It maps each M3 exit criterion of `SPEC/09-milestones.md` to its tests and their state. M3 is **not closed**: a milestone closes only when its exit criteria pass in CI, and some still fail.

The exit criteria: I-16 to I-20, I-24, I-38, I-39 and I-77 to I-83 green; isolation tests green; hosting provider named in ADR-005 (NOTE 2).

## 1. Summary

Updated late on 2026-11-13, after the decision lanes of section 7 merged. Local targeted runs only; CI has not yet judged this state.

| Criterion | State on `main` | What remains |
| --- | --- | --- |
| I-16 | Green | None |
| I-17 | Green | None |
| I-18 | Green | None |
| I-19 | Green | None |
| I-20 | Green (vault-change ids keyed per cell, item 4) | None |
| I-24 | Green (the production AnchoredStore and anchorer behind `prod_store_batch`) | Design 5.3 names `PgRecordStore` for a serving cell; this path uses `AnchoredStore` |
| I-38 | Green (licence and update tasks, CrabNebula stand-in) | None |
| I-39 | Green | None |
| I-77 | Green (item 6) | None |
| I-78 | Green | None |
| I-79 | Green locally (Q-I79 decided 2026-11-15, section 9) | Confirm in CI |
| I-80 | Green on macOS. On Linux, CI run 43394088959 passed the root canary scan and failed the seal key scan: destroyed `S(e)` copies stayed in the world host's heap and stack. Lane m3/i80-seal keeps each `SealKey` in one heap allocation and wipes the keyd frames | Confirm the Linux seal key scan in CI |
| I-81 | Green | None |
| I-82 | Green | None |
| I-83 | Green | None |
| Isolation | Green | Confirm in CI (part `isolation-multi-cell`) |
| Hosting provider | Met: OVHcloud is named in ADR-005 | Verify items V1 to V11 stay open for the R-HS-01 claim (L-15) |

Other M3 tests still red: `seam_async` (item 15 was not enough, see section 8), `r_nf_08_no_api_takes_a_caller_nonce` (unlisted, see section 8).

## 8. Open after the second round

- `r_nf_08_no_api_takes_a_caller_nonce` fails on `fstp_control::approval::approval_challenge(digest, issued_at, nonce)`, from the two-operator check. The nonce is part of a passkey challenge hash and seals nothing. Recommendation: an entry in the scan's `NOT_SEALS` list with that reason. That widens an invariant test's list, so it waits on Daniel. It is not on the known-red list, so CI stays red until then.
- `seam_async`: leaving out vault digests and epochs is not enough. The cell's creator-path set-up and its extra vault answers also differ from the engine's. Recommendation: compare the set-up apart and split off the extra vault answers, as the M2-over-HTTP lockstep does.
- Process mode runs every cell and vault in one `fstp-world-host` process, not separate binaries. Separate binaries need `fstp_cell::run` to accept a full configuration.
- The S(e) memory scan covers the App, Vault and CellBackup chains (lane m3/finish-gaps, 2026-11-15). The process-mode test on every platform checks that a destroyed CellBackup seal key exists to look for. The Linux scan itself runs in CI only.
- Devstack browser specs: 13 of 22 pass (lane m3/finish-gaps, 2026-11-15). Fixed: `GET /auth/devices` names the caller's own account, which the account page needs for a removal step-up; the specs pause the enrolled authenticator so only the new key answers a passkey creation; the R-LG-03 "other action" step-up is `ApproveRecovery`; the first admin's login email comes with `/test/reset`; magic links are the world's start option, since no command carries P-70; one literal of `web/src/auth/appshell.ts`. Still open: seven specs wait on `/test/scenario/negotiation` (proposals in NEGOTIATION and RANKED, released canaries, Operations and Judging holders invited to enrol). Two (`i77_grant_of_a_management_role_ends_the_accounts_weak_sessions`, `r_lg_03_committee_grant_fails_without_a_step_up_in_the_last_p71`) need an active programme: a draft admits only a programme manager grant (I-66), so the spec needs the whole creator path with a second tenant admin, and `/test/account` needs the login index exposed to the world.
- The `devstack` CI part compiles the auth pages with Node before `cargo test`. ADR-003 says `cargo test` never needs Node.
- Cell erasure: lane m3/erase-prod built Daniel's decisions of 2026-11-15 (late) (ADR-004, last section). The witness appends a revocation record beside `witness.cell_ca` and refuses the revoked cell. `WitnessRegistry` implements `WitnessCredentials`. Each operator approves an erasure once, over a batch of its job digests. `fstp-pgagent` and `erase_cell_steps` check that each digest is in that batch. `fstp-keyd` holds CA sign keys in sign-key slots, the install step creates the local cluster CA keys there, and `KeydCustody` destroys them in place. Remote edges poll a signed, versioned route table. `RemoteEdges` finishes route removal once every edge reports the version without the cell. Still open: deleting the cell's object storage prefix conflicts with ADR-005 ("never by client DELETE calls") and ADR-012 ("No `DeleteObject` call exists"). So the S3 client has no list or delete, and only tests implement `CellObjects`. The options are in ADR-004. Also open: the edge listener configuration (`fstp_edge::run` still refuses), the interim edge identity and edge set, the `OkmsCustody` sign key destroy (Q11), and the production key list from `cp.custody_entry`.

## 2. Where the tests run

- The M3 tests live in `crates/fstp-celltest/tests`, `crates/fstp-cell/tests` and the crate test directories. They run in the CI `tests (workspace)` part.
- The isolation tests (`t_iso_*`, `t_db_iso_*`, the I-80 memory scans, the I-80 root canary test and `i19_cell_process_serves_one_cell`) run in their own part, `isolation-multi-cell` (design sections 14.4 and 14.8).
- `crates/fstp-celltest/tests/teeth_m3_registry.rs` checks that every exit row has registered teeth tests, that each exists and is not ignored, and that each isolation test runs in exactly one CI part. It registers 160 teeth tests and allows no gap.
- `tools/test-gate` judges every part against `ci/known-red.txt`. On 2026-11-13 it was fixed to read CI's coloured cargo output (8fc7a172). Before that fix it judged no test at all.

## 3. Questions that block closure

Each is recorded in the lane handoffs. Lanes built the stricter reading where one exists.

- **Q-ISO (I-20).** `t_iso_i20` finds seven identifiers shared across tenants. All are vault-change command ids, `fstp:vc:` followed by the vault epoch, stored in clear in each ledger. They carry no person data. Should the test baseline admit them, or should the id be keyed per cell?
- **Q-KEYOP (I-24).** `erasure_runner::i24_cell_erasure_runner_records_a_key_op_for_each_custody_change` expects one key record per state change. ADR-004 records Daniel's decision of 2026-10-29: a record for every custody call. The code follows the ADR.
- **Q-SIM (I-24, I-80).** The custody simulator still refuses to wrap, pinned by `harness_custody_sim_wrap_refuses_until_the_aead_lands`. The AEAD has landed. With a wrapping simulator `i24_custody_ops_reconcile_with_key_records` passes, and cells can run as separate processes so the Linux memory scans get a PID.
- **Q-I79.** Decided by Daniel on 2026-11-15 ("Record it as evidence"), section 9.
- **Q-I77.** Case 243 of the I-77 HTTP test fails on the test's own bookkeeping: two passkey sessions of one account at one tick share one model key. The fix is in the test.
- **Q-D (witness receipt key).** Daniel decided the self-hosted witness opens its receipt key through its own `fstp-keyd` entry. That needs `fstp-custody`, which design rule 7 and the I-80 test `i80_only_listed_crates_reach_fstp_custody` do not allow for `fstp-witness`. The witness run loop was reverted until Daniel decides.
- **Devstack.** `slice_devstack` needs `GET /auth/invite` in `routes::table()`, while the I-78 test `i78_page_routes_are_public_gets_outside_the_section_8_7_table` forbids page routes there. It also needs port 443 on macOS.

Other M3 entries waiting on Daniel: `r_nf_05` (the baseline of a provisioned cluster). Daniel decided `r_nf_08`, `sod_08` and `adr007_erased_textref` on 2026-11-15 (section 9).

## 4. Work left that needs no decision

- I-38 and I-39: licence and update tasks in the cell, a CrabNebula stand-in in the test world, and the steps `seed:<kind>:<text>`, `services-down:<fault>` and restart.
- `r_sw_02_cell_erasure`: the `erase-cell` step, which needs the control plane's erase-cell job (destructive jobs refuse until the two-operator check exists).
- `seam_world` money and ledger suites (I-13, I-14, I-15, I-23 over PostgreSQL): a cell driver for those machines.

## 5. Interim readings built this night

Each is marked "Interim, pending Daniel" in code or in the lane's handoff section. The main ones:

- Token lifetimes: magic link 15 minutes, recovery enrolment 24 hours, recovery case 72 hours, staff assertion 15 minutes, signup proof 15 minutes (`fstp_cell_core::lifetimes`, ADR-008).
- The login email index and operator tickets are held in memory until the keystore tables land.
- The control-plane link sends one connection per exchange and a heartbeat every 60 seconds.
- Backups: the test world plays the uploader and the object store; `base-backup` also takes a keystore snapshot.
- The vault chain writes one kind 1 row per committed fact batch and per identity release or read (Daniel's Q-C answer).

## 6. Not claimed

- R-HS-01 (hosting verify items V1 to V11, L-15).
- A release: `deps-check --release` stays red until a Mythos-tier confirmation of moduletto at `6c1ae92` is recorded (I-74).

## 7. Decided by Daniel on 2026-11-13 (second round)

Daniel answered "follow all recommendations" for these items, and chose `/auth/account` for item 9.

| # | Question | Decision |
| --- | --- | --- |
| 1 | Q-D, witness receipt key and I-80 | `fstp-witness` joins design rule 7 and the list of `i80_only_listed_crates_reach_fstp_custody`. The witness run loop returns |
| 2 | Q-SIM | The custody simulator wraps and unwraps. The pin `harness_custody_sim_wrap_refuses_until_the_aead_lands` is retired, since the AEAD has landed |
| 3 | Q-KEYOP | ADR-004 wins: a key record for every custody call. The `erasure_runner` test's expectation follows the ADR |
| 4 | Q-ISO | The vault-change command id is keyed per cell, so `t_iso_i20` stays strict |
| 6 | Q-I77 | The I-77 HTTP test's cookie bookkeeping is fixed in the test: two sessions of one account at one tick get distinct model keys |
| 7 | Devstack | Pages are served from a separate page table, and `slice_devstack` reads that table. The I-78 rule that keeps page routes out of `routes::table()` stays |
| 8 | Edge and ECH | The edge routes a ClientHello that carries `encrypted_client_hello` on its outer SNI, as ADR-009 records (2026-10-29). `b5_th26_sni_encrypted_client_hello_closes` is replaced by a routing test |
| 9 | Landing on the M3 stack | M3 browser specs land on `/auth/account` |
| 10 | `r_nf_05` | The baseline is a provisioned cluster |
| 15 | Vault digests and epochs | Comparisons against the real vault leave out vault digests and epochs, in `seam_async` and in the M2-over-HTTP comparison |
| 26 | Playwright in CI | CI runs the demo Playwright project as a separate job |

Items 5, 11 to 14, 16 to 18 and the interim readings of section 5 stay open.

## 9. Decided by Daniel on 2026-11-15

Lane m3/decisions-a built these four decisions.

| Question | Decision | What changed |
| --- | --- | --- |
| Q-I79, recovery | "Record it as evidence" | `decide` records `ApproveRecovery` on any path after the email proof, with the same checks. It counts as the second factor only where the path recomputed at completion is `SecondAdmin`, so I-79 holds. The cell-core test is now `i79_approval_needs_another_admin_and_is_evidence_on_any_path`. ADR-008 "Recovery" records it |
| SoD-08 break-glass | "On the approval record" | `ApproveBreakGlass { request, staff, scope, until }` records `BreakGlassApproved { grant, staff, scope, until }`. `gate::admit_break_glass` verifies a composite staff assertion against the pinned key within `STAFF_ASSERTION_US` and admits reads as `Principal::BreakGlass(grant)`. Each admitted read is logged as `OpsRecord::BreakGlassRead`. ADR-008 "Break-glass" records it |
| ADR-007 erasure causes 1 and 4 | "Tenant admin for all" | A tenant admin requests all four causes and is the authoriser the entry names. `ACCOUNT_ERASURE_CAUSES` is gone. ADR-007 "Erasure-log entries" records it |
| R-NF-08 sealed blobs | "Record it in ADR-004" | ADR-004 "Vault sealed values" records `nonce 12 \| ciphertext \| tag 16` for `vault.epoch.affected`, `vault.fact.body`, `vault.negotiation.sealed_accounts` and `vault_audit.chain.body`. The R-NF-08 test reads their nonce at offset 0 |

Open after these decisions:

- **Retention reminder (P-41).** Decided by Daniel on 2026-11-15 (late). Retention starts at the confirmation of the grant's last payment request, with no new act. A timeline event fires at that date plus P-41 years, and a mailbox message reminds the tenant admins. It links to a new page, `/app/admin/erasures`, where a tenant admin lists past erasures, sees grants whose retention ended and requests an erasure with its cause (ADR-007), with step-up. Built by lane m5/retention: `fstp_domain::retention`, the timeline kind `RETENTION_END` (code 11), the mailbox notice `admin.retention_ended`, and the operations `admin.erasures` and `admin.request_erasure` behind the page. Its interim readings are in `crates/fstp-domain/src/retention.rs` and `crates/fstp-api-core/src/erasure.rs`.
- **Staff read route.** No HTTP route serves a staff read yet. `gate::admit_break_glass` and `Admitted::break_glass_log` are the entry points for it, with the operator content views (M4). The cell pins only the operator ticket key (`operator_key`) today; design section 9 lists a staff assertion key beside it, which the route will pass as `pinned_key`.
