# M3 base record

Written in lane W0 of M3 on 2026-10-28. It records the M2 commit that M3 builds on (design section 0.5) and every seam where a W0 stub stands in for a dependency that waits for Daniel. Read it with `docs/handoff/m3-design.md`.

## M2 base commit

| Item | Value |
| --- | --- |
| Commit | `367b7be500bf2e416118fc0794c29168fa21fc62` (`367b7be`, "Draw scheduled role ends in the engine fuzz target") |
| Branch | `m2/w7-fix`, the M2 close-out lane |
| State | Pending the merge of PR #4 ("M2: final review fixes") into `m2-domain-core`. PR #4 was open when W0 ran. |
| M2 crates at the M3 branch head | Identical to `367b7be`. `git diff 367b7be HEAD -- crates/` was empty before W0 started. |

Design section 0.5 names the merge commit that closes M2 as the base. That commit does not exist yet. Until it does, M3 pins `367b7be`. When PR #4 merges, the lead records the merge commit here and repeats the three re-derivations below. Any difference goes to Daniel before a lane depends on it.

Design section 0.5 names `docs/handoff/m3-exit-audit.md` for this record. The W0 lane scope names this file instead, so the record lives here. The exit audit (lane W6) cites it.

## Re-derivations at `367b7be`

1. **High-risk table (I-78).** `fstp_domain::CommandKind::high_risk()` marks seven kinds: `CreateProgramme`, `GrantRole`, `EndRole`, `ReinstateBinding`, `ApprovePayment`, `ReleasePayment` and `PublishCall`. These are the seven the design names. The new `EndScheduledRole` is a system command and is not high-risk. Each of the seven is an entry of `fstp_cell_core::gate::HIGH_RISK_TABLE`. No difference.
2. **Holdings rule (design section 8.2).** The M2 roster's `Binding::held` excludes a binding under a conflict-of-interest suspension (rule I-06). Design section 8.2 counts every suspended binding as holding for login. The design reading is stricter, so it stands. `fstp_auth::holds_management` must not reuse the roster's `held` predicate for that case. This is reported to Daniel as a note, not a conflict.
3. **Binding-end instants (design section 8.2).** A scheduled end is `Binding::scheduled_end` in the roster, recorded as `BindingEndScheduled { binding, at }`. The system command `EndScheduledRole` records the end once the instant is reached, and `fstp_domain::due` lists it from that instant. An immediate end records `BindingEnded` at `ctx.now`. The session-end rule reads the instants from these records. No difference.

## Seams held by W0 stubs

W0 added no third-party crate or npm package. Each seam below kept the designed API without the dependency. The dependency owner then landed moduletto, zeroize, the tokio signal feature and the test-only aws-lc-rs, rustls-webpki and rustls-pki-types edges on 2026-10-28, under the accepted ADRs. The lane named in each row removes its seam. No npm package is added yet.

| Seam | Where | Waits for | Owner |
| --- | --- | --- | --- |
| moduletto (ML-KEM-768, ML-DSA-65) through `fstp_crypto::{mlkem, mldsa, hybrid_kem, composite}` | `fstp-keys::envelope` has the decoders only; `seal_key`, `open_key`, `seal_blob` and `open_blob` are not written. `fstp-audit` has no composite signing call. `fstp_cp_proto::CompositeSig` checks no grammar yet | Dependency landed 2026-10-28 and commit-ready: `fstp-crypto` depends on moduletto 0.1.0 at commit `46754f2fccb0a501be278fb2fab63b670101a33d` (ML-KEM only), recorded in ADR-001 A2, `deps/allowlist.txt`, `deps/adr-roots.txt` and the Tier B marker. deps-check passes with the unconfirmed Tier B warning, and `--release` fails on it (I-74). The ML-DSA-65 half still waits for moduletto PR #13 and a new pin | W1h removes the ML-KEM seam now, then W2f, W2g and W2h. The ML-DSA-65 seam stays until the pin moves |
| zeroize 1.9.1 with features `alloc` and `default` | `fstp_custody::SealKey` holds a plain `[u8; 32]`, and `fstp_keyd::RootMaterial` a plain array. Neither wipes on drop yet. `open_blob` will return `Zeroizing<Vec<u8>>` | Dependency landed 2026-10-28 and commit-ready: a direct dependency of `fstp-crypto`, `fstp-keys`, `fstp-custody` and `fstp-keyd`, with the root line `zeroize ADR-001 alloc,default` and the ADR-001 record line that names all four crates | W1h for the `fstp-crypto` secret types, W2f for `fstp-keys`, `fstp-custody` and `fstp-keyd`. W2f also rewrites the stale "zeroize is not a dependency" comments in `fstp-custody/src/lib.rs` and `fstp-keyd/src/lib.rs` |
| tokio `signal` feature and `signal-hook-registry` | `fstp-rt` has no `signal` module. The stub binaries do not handle SIGTERM | Dependency landed 2026-10-28 and commit-ready: `signal` is enabled on the `fstp-rt` tokio line only, adding `signal-hook-registry 1.4.8` and `errno 0.3.14`. The ADR-002 record and the tokio root features are updated | W2l writes `fstp-rt/src/signal.rs` |
| aws-lc-rs ML-KEM and ML-DSA as test oracles | `fstp-celltest` has no aws-lc-rs code yet. `reference::hybrid::combine` refuses | Dependency landed 2026-10-28 and commit-ready: aws-lc-rs 1.18.2 is a normal dependency of the test-only `fstp-celltest`, with no feature change (ADR-001 A6). Its library oracles under `src/reference` can name it | W1h test agent. It also rewrites the stale "aws-lc-rs is not a dependency yet" comment in `fstp-celltest/src/reference/hybrid.rs` |
| aws-lc-rs, rustls-pki-types and rustls-webpki for the `fstp-pki` round trips | `fstp-pki` has no round-trip test yet. The `cert_build_roundtrip` fuzz target checks only that no input panics | Dependency landed 2026-10-28 and commit-ready: all three are dev-dependencies of `fstp-pki` at the versions and features `Cargo.lock` already held (aws-lc-rs 1.18.2, rustls-pki-types 1.15.1, rustls-webpki 0.103.16), so no package was added. rustls-pki-types supplies `UnixTime` and `CertificateDer`, which rustls-webpki does not re-export. This test-only edge is outside the production rule of design section 2.5, pending the lead's confirmation of that reading. The fuzz project `crates/fstp-pki/fuzz` depends on rustls-webpki and rustls-pki-types with the same features | W1i test agent for the tests, W1i for the fuzz parse check |
| `fstp_ledger::AsyncRecordStore` | `fstp_pgstore::PgRecordStore` implements no store trait yet | Lane W2c (additive, M2 crate change for Daniel's review) | W2c, then W2e |
| `fstp_migrate::catalogue` | W0 added the types of design section 4.5 only, so the column maps compile. `fstp_meta.apply_grant` is not written | Lane W2e | W2e |
| `APPLY_GRANT_SQL` and `RoleName` | `fstp_cp_proto::ROLE_SUFFIX_GRAMMAR` holds the suffix grammar of design section 4.1, and a test ties it to `RoleName`. No test ties it to `APPLY_GRANT_SQL` yet, since that text does not exist | Lane W2e writes `APPLY_GRANT_SQL` with that grammar and adds the test | W2e |
| `KeystoreSnapshots` in `Destination` and `VaultDestination` | Both enums hold the variant, as ADR-009 lists it. No connector builds it | The open point "Keystore snapshot destinations" of ADR-009 and the open point "Keystore snapshot path" of ADR-012. Both ADRs are accepted (2026-10-28), but the two members stay interim, pending Daniel | W3a, W2d |
| Node.js and npm for `web/` and `e2e/` | No npm project exists. The npm gate in `tools/deps-check` runs and passes on an empty tree. `deps/npm-allowlist.txt` does not exist yet | ADR-003 amendment (Q39 A) | W3c |

## Stub conventions

- Every operation of a new crate refuses with a typed `NotImplemented` error. No stub uses `todo!`, `unimplemented!`, `panic!`, `unwrap` or `expect`.
- Where the design gives an infallible signature, the stub returns a `Result` instead. A stub then never answers a policy or planning question with a made-up value. The owning lane restores the designed signature.
- The tripwire constants in `fstp_celltest::mc::tripwires` are zero. A zero tripwire stops every model run, so no model passes on a placeholder.

## Open points for Daniel

- Design section 8.4 lists five strict additions. SPEC now has its own row for approving an account recovery (Q15). `STRICT_ADDITIONS` holds four entries, as ADR-008 says.
- The column classes of design section 4.5 do not cover these columns: `endpoint`, `host`, `server_spki`, `cose_key`, `org_ref`, `key_ref` and `case_ref` in `cp`, and `link`, `signature` and `witness_link` in `witness.anchor`. Their `ColumnSpec::class` is `None` until a class is decided.
- Design section 4.4 lists only `witness.anchor`. ADR-010 adds prepare, abort, in-doubt and restore records, and ADR-005 and ADR-012 place base backup records in `cp`. Neither is in a catalogue until the design names the tables.
- `fstp-witness` needs `fstp-migrate` for its catalogue and migrations. Design section 2.1 omits that edge. W0 added it.
- The metadata register cites ADR-009 (accepted 2026-10-28, Q36 A). SPEC has no register text yet. The wording proposal is with Daniel (Q28). The `Infrastructure` class of ADR-009 is still interim, pending Daniel.
- Design section 2.1 marks `fstp-vault-core` with a fuzz project, while section 15 names no target for it. W0 takes the stricter reading: `crates/fstp-vault-core/fuzz` holds the sequence target `fact_commit_sequence`, and `deps/fuzz-required.txt` lists the crate. Daniel decides which section wins. If it is section 15, the project goes.
- Design section 2.4 rule 6 names only `fstp-cell` and `fstp-release-svc` as crates that reach `fstp-release`. `fstp-celltest` depends on every crate (section 2.1) and tests I-39, so the rule names it as a third, test-only exception. Rules 2 and 7 name it already. No other test-only crate is exempt from rules 2, 6 and 7.
- `ClusterKind` gains `Witness`. Under Q3 C the control-plane databases are provider-managed and the witness database stays self-operated, so the witness can no longer share a `Control` cluster. A `Control` cluster is never a `fstp-pgagent` target.
- W0 edited one M1 crate outside its file list. `crates/fstp-migrate/src/lib.rs` gained `pub mod catalogue`, and W0 created `crates/fstp-migrate/src/catalogue.rs` with the types of design section 4.5 only. Design section 19 gives that file to W2e. The column maps of the new crates need the types to compile. The lead decides whether to accept this as a W0 stub, or to hold the change for a W2e request before staging. Either way it is an M1 crate change for Daniel's review.
