# ADR-004: Hybrid construction and key custody

Status: Accepted in structure by Daniel on 2026-10-10. The hybrid combiner details and the custody providers are fixed before M3 closes.

## Key hierarchy

| Level | Key | Held by |
| --- | --- | --- |
| 1 | Cell root key | Custody backend (below). Never leaves it in plaintext |
| 2 | Cell key-encryption keys, one per purpose: application data, identity vault, backups, exports | Wrapped by the root key |
| 3 | Data keys per object or record set (AES-256-GCM) | Wrapped by a level 2 key through hybrid X25519 plus ML-KEM-768 (ADR-001) |

The identity vault has its own level 2 key and its own custody entry. A compromise of application keys does not expose the vault.

## Custody backends

Root keys sit behind a custody interface with two implementations for the SaaS:

| Backend | Description |
| --- | --- |
| EU-operated KMS or HSM | Key service of an EU-owned provider (ADR-005). Root keys are created inside it and never exported |
| CrabNebula-operated HSM | Hardware security modules in CrabNebula's control, reached through PKCS#11 |

- Each cell records which backend holds its root key. The choice can differ per cell.
- Self-hosted cells use the tenant's own backend: a local HSM, the tenant's KMS, or a passphrase-protected file key for small installs.
- A PKCS#11 client crate, if used, joins ADR-001 Tier A after review.

The backends for M3 are in "Completion part 2" below, which Daniel accepted on 2026-10-28.

## Rules

- **I-80** No root key exists in plaintext outside its custody backend.
- **I-81** Destroying a cell's root key, or a data key, makes the protected data unrecoverable, including from backups. This is how erasure (R-SW-02) and crypto-shredding (R-ID-03) are carried out.
- Root key use is logged by the backend, and the log is reconciled with the cell's audit chain.
- Key rotation re-wraps level 2 keys without re-encrypting data.

## Hybrid combiner

Proposed: an X-Wing style combiner. Both shared secrets, the ML-KEM ciphertext and the X25519 public values are bound through a KDF from aws-lc-rs. Test vectors and a written construction are fixed here before implementation. The construction is reviewed in hardening activity H-19.

The written construction, its bytes and its test vectors are in "Completion part 1" below, which Daniel accepted on 2026-10-28. It replaces the "Proposed" paragraph above.

## Signing keys

| Key | Algorithm | Held in |
| --- | --- | --- |
| Release root key | Composite Ed25519 plus ML-DSA-65 | Offline, under CrabNebula control. Used only to certify and revoke release signing keys |
| Release signing key | Composite Ed25519 plus ML-DSA-65 | Isolated signing service. Ed25519 half in an HSM; ML-DSA half sealed by an HSM or TPM and unsealed into the service at start. Certified by the root for a limited period |
| Audit anchor and export manifest key, per cell | Composite | Level 2 key of the cell, wrapped by the root key |
| Notice companion key, per tenant | Composite | Level 2 key of the cell |
| Licence token, profile bundle and template keys | Ed25519 | Level 2 keys of the issuing cell or the control plane |

Release signing was decided by Daniel on 2026-10-25 (O-42).

- Self-hosted cells and desktop clients pin the release root public key. They accept a release only when its signing key carries a valid, unexpired certificate from that root (I-91).
- Releases are signed automatically. The signing service signs only requests that carry verified build provenance from the release pipeline, and moduletto produces the ML-DSA half (I-75).
- A release can also require approval by two maintainers with a phishing-resistant step-up before the service signs it.
- The root key is used in a short manual step, about once a year, to certify the next signing key, and whenever a signing key must be revoked or rotated. It never signs releases.
- A compromised signing key is revoked through the root and stays bounded by its certificate period.
- If the chosen HSM can run moduletto, the signing service may move into the HSM later without changing what clients verify.

## Completion part 1, 2026-10-28: hybrid combiner, sealed keys and nonces

Status: Accepted 2026-10-28 (Daniel Thompson-Yvetot).

This section fixes the hybrid combiner "before implementation", as the section "Hybrid combiner" requires. Daniel accepted it on 2026-10-28, so it replaces that section's "Proposed" paragraph. It must be accepted before the W1h production agent starts (M3 design, section 18).

### Decision

Daniel chose the HKDF-SHA-256 combiner of M3 design section 3.2 on 2026-10-28 (Q2, option A). It hashes the ML-KEM ciphertext into the KDF info, so it binds every input this ADR and ADR-001 name. It uses only HKDF, HMAC and SHA-256 from aws-lc-rs, beside ML-KEM-768 from moduletto and X25519 from aws-lc-rs (I-75).

Exact X-Wing was not chosen. The review of the M3 proposals found that X-Wing leaves the ML-KEM ciphertext out of its KDF input. This decision does not depend on that finding, because the chosen combiner takes the ciphertext as an explicit input. H-19 reviews the construction and may compare it with the pinned X-Wing draft text.

### Inputs

| Name | Bytes | Source |
| --- | --- | --- |
| `ss_M` | 32 | ML-KEM-768 shared secret (FIPS 203), from moduletto |
| `ss_X` | 32 | X25519 shared secret (RFC 7748), from aws-lc-rs. aws-lc-rs refuses an all-zero result, and so does decapsulation |
| `ct_M` | 1088 | ML-KEM-768 ciphertext |
| `E` | 32 | Ephemeral X25519 public key of the sender |
| `pk_X` | 32 | Recipient's static X25519 public key |
| `pk_M` | 1184 | Recipient's ML-KEM-768 encapsulation key |

A hybrid public key is `pk_X || pk_M` (1216 bytes). A hybrid ciphertext is `E || ct_M` (1120 bytes). Every length is fixed.

### Combiner bytes

```text
salt = "fstp-hkem-v1"                          12 ASCII bytes, no terminator:
                                               66 73 74 70 2d 68 6b 65 6d 2d 76 31
ikm  = ss_M || ss_X                            64 bytes, ML-KEM first
prk  = HKDF-SHA-256-Extract(salt, ikm)         32 bytes
info = SHA-256(ct_M) || E || pk_X || SHA-256(pk_M)      128 bytes
ss   = HKDF-SHA-256-Expand(prk, info, L = 32)  32 bytes
```

- With `L = 32`, Expand is one HMAC-SHA-256 block: `HMAC(prk, info || 0x01)`. The test reference uses that identity (section "Test vector plan").
- `combine(ss_m, ss_x, ct_m, e, pk_x, pk_m)` takes all six values as parameters. No input is read from ambient state.
- The output `ss` is never used as a key directly. It feeds the key derivation of the sealed key format below.

Encapsulation to `(pk_X, pk_M)`:

1. `(ct_M, ss_M) = ML-KEM-768.Encaps(pk_M)`, through `fstp-crypto::mlkem` (moduletto).
2. Draw an ephemeral X25519 key `e` from aws-lc-rs. `E` is its public key, and `ss_X = X25519(e, pk_X)`.
3. `ss = combine(ss_M, ss_X, ct_M, E, pk_X, pk_M)`. Zeroize `e`, `ss_M` and `ss_X`.

Decapsulation with the recipient's secret half:

1. `ss_M = ML-KEM-768.Decaps(dk_M, ct_M)`. FIPS 203 implicit rejection means a forged `ct_M` yields an unrelated `ss_M`, so the failure shows at the AEAD step.
2. `ss_X = X25519(sk_X, E)`. An all-zero result is refused.
3. `ss = combine(...)` with `pk_X` and `pk_M` taken from the stored public half, never from the ciphertext.

No function in `fstp-crypto` decapsulates with one half only (I-75). Both halves always run, even when the first one fails, so timing does not tell which half failed.

### Sealed key format

A sealed key is a level 3 data key sealed to a level 2 group key.

```text
header  = "FSK1" | version u8 = 1 | kem u16 = 1 | aead u16 = 1
          | chain u8 | group 16 | generation u32                    30 bytes
ctx     = "FSC1" | owner 16 | chain u8 | purpose u8 | group 16
          | generation u32 | object 16                              58 bytes
kek     = HKDF-SHA-256-Expand(HKDF-SHA-256-Extract(salt = empty, ikm = ss),
                              info = "fstp-seal-v1" || header, L = 32)
wrapped = AES-256-GCM(kek, nonce, aad = header || ctx, plaintext = data key 32)    48 bytes
sealed  = header | E 32 | ct_M 1088 | nonce 12 | wrapped 48         1210 bytes
```

- Integers are big-endian. `kem = 1` names this combiner. `aead = 1` names AES-256-GCM.
- Chain codes: App 1, Vault 2, CellBackup 3, ClusterBackup 4, ControlPlane 5. Purpose codes come from `fstp_keys::Purpose`. Record at first use: the purpose code table, which is frozen once written.
- `owner` is the `CellId`. For the ClusterBackup chain it is the `ClusterId`, and for the ControlPlane chain the environment id.
- `object` is the data key id. `ctx` is not stored, because the caller supplies it from the row that names the key.
- `open_key` compares the header's chain, group and generation with `ctx` before any decapsulation. A sealed key moved to another object, group, generation, chain or cell fails to open.
- The decoder accepts exactly 1210 bytes, the magic, version 1, and known codes. Any other input is refused. It re-encodes byte for byte. The fuzz target `sealed_key_decode` exists from the first commit.
- Each `kek` seals once. The nonce is still drawn at random, under the rule below, so the rule has no exception.

Sealed blobs (texts, ledger bodies, chain events, checkpoints, outbox rows, keystore secrets and backup chunks) use AES-256-GCM under their data key. Their AAD binds each blob to its owner and its position, so a blob moved to another cell, row or object fails to open. The exact AAD and layout belong to the ADR that owns the table: ADR-007 for ledger and chain rows, and ADR-012 for backup containers (M3 design, section 18).

### Nonce rule

- Every AES-256-GCM seal in the workspace goes through `fstp_crypto::aead::seal`. It wraps `aws_lc_rs::aead::RandomizedNonceKey`, which draws a fresh 96-bit nonce from the system generator and returns it.
- The nonce is stored beside the ciphertext in the sealed bytes.
- No function in the workspace takes a nonce from its caller. None derives a nonce from a sequence number, row id, counter or time.
- Why: an aborted transaction leaves its ciphertext in the WAL and in archived WAL. A position-derived nonce would then repeat under the same key on retry. Under GCM, a repeat reveals the XOR of two plaintexts and allows tag forgery.
- Guard: a source scan refuses `LessSafeKey`, `SealingKey`, `OpeningKey` and every `Nonce` constructor outside `crates/fstp-crypto/src/aead.rs`.
- Fallback: `RandomizedNonceKey` also accepts AES-256-GCM-SIV. That becomes the AEAD only if H-19 asks for misuse resistance on top, and only through a new `aead` code. It needs ADR-001 A8 first.

### Seal-count limit

NIST SP 800-38D bounds random 96-bit nonces at 2^32 seals per key. This ADR stays far below that bound.

| Key | Planned replacement | Hard limit |
| --- | --- | --- |
| Ledger data key (ledger bodies, chain event bodies and checkpoints together) | After 2^20 seals, and at every process start | 2^24 |
| Per-object data key (text, outbox row, document) | Seals one object | 2^24 |
| Backup data key | One per backup attempt | 2^24 chunks. ADR-012 keeps each backup under it |
| Epoch seal key `S(e)` (part 2) | One seal per live group secret per epoch | 2^24 |
| `kek` of a sealed key | Seals once | 1 |

- `fstp-keys` counts every seal call per key in memory, including seals whose transaction later aborts. At the hard limit it refuses to seal.
- A count kept only in memory is lost at a crash. A restart therefore always draws a new ledger data key generation (`key_ix`), so no key resumes with an unknown count. This rule is an addition to M3 design section 3.2.
- At 2^24 seals the chance of any nonce repeat under one key is about 2^-49.
- One data key seals in one process only. The cell's advisory lock already makes `fstp-cell` the single writer of its App chain.

### Test vector plan

The W1h test agent writes the reference `crates/fstp-celltest/src/reference/hybrid.rs` from this section alone, without reading the production code.

1. **Independent combiner.** The reference evaluates Extract and the single Expand block as two HMAC-SHA-256 calls from aws-lc-rs, as RFC 5869 defines them. Production calls the aws-lc-rs `hkdf` module. The reference's KDF evaluation is first checked against the SHA-256 test cases of RFC 5869 Appendix A.
2. **Fixed-input vectors.** `combine` takes plain bytes, so its vectors need no deterministic encapsulation. Inputs for vectors 0 to 63 are expanded from a fixed label with SHA-256 in counter mode, as test input only. Edge vectors add all-zero and all-0xff values for each field, and `ct_M` values that differ only in their last byte.
3. **Frozen constants.** The reference computes the expected outputs once. They are stored as Rust constants in `crates/fstp-crypto/tests/`, so no vector file parser is added. Each run also recomputes them with the reference, so an edited constant fails.
4. **Cross-implementation round trips.** Production encapsulates to keys that the reference generated with the aws-lc-rs ML-KEM oracle, and the reference decapsulates. The reverse runs too. Both sides must derive the same `ss`, on 1 000 random key pairs per run.
5. **Binding property.** Flipping any single bit of any of the six inputs changes `ss`. A teeth twin builds a combiner that omits one input and must fail the property, once for each input.
6. **Both halves (I-75).** A sealed key opened with a wrong X25519 secret or a wrong ML-KEM secret fails.
7. **Context binding.** Changing any field of `ctx` or the header makes `open_key` fail.
8. **X25519.** The RFC 7748 test vectors run through aws-lc-rs static keys.
9. **ML-KEM-768 ACVP.** aws-lc-rs `kem::DecapsulationKey::new` imports raw decapsulation keys, so the ACVP decapsulation cases run against the aws-lc-rs oracle. They run against moduletto if it imports decapsulation keys. KeyGen and encapsulation cases run against moduletto through its deterministic `keygen_derand` and `encaps_derand` entry points (ADR-001 A2, Daniel, 2026-10-28). ACVP files are read with `fstp-json`.
10. **Differential (ADR-001 Verification).** moduletto and aws-lc-rs ML-KEM-768 decapsulate each other's ciphertexts on random keys.
11. **Nonces.** `r_nf_08_aborted_append_never_reuses_a_nonce`, the teeth twin `r_nf_08_teeth_counter_nonce_is_caught`, and the source scan of the nonce rule.
12. **Seal counts.** A test drives a key to the hard limit and expects a refusal. Another restarts the process and expects a new ledger key generation.

Proposed test names: `t_cr_hybrid_combiner_matches_reference_vectors`, `t_cr_hybrid_reference_kdf_matches_rfc5869`, `t_cr_hybrid_cross_implementation_round_trip`, `t_cr_hybrid_combiner_binds_every_input`, `t_cr_hybrid_teeth_combiner_omitting_an_input_is_caught`, `i75_sealed_key_needs_both_halves`, `r_cr_01_sealed_key_moved_context_fails_to_open`, `t_cr_hybrid_x25519_rfc7748_vectors`, `t_cr_hybrid_mlkem_acvp_decapsulation`, `r_nf_08_no_api_takes_a_caller_nonce` (the source scan), `r_nf_08_seal_count_limit_refuses_at_two_to_the_24` and `r_nf_08_restart_draws_new_ledger_key`. The `r_nf_08_*` names match the ADR-007 amendment. T-CR-HYBRID covers TH-50.

Open point for Daniel: the reference evaluates HKDF from HMAC calls in test code only. `.claude/CLAUDE.md` forbids in-house primitives. This draft reads a test-only evaluation of RFC 5869 over aws-lc-rs HMAC as composition, not a new primitive. If Daniel reads it otherwise, items 1 to 3 compare production against vectors computed once with the aws-lc-rs `hkdf` module, and lose some independence.

Freeze rule: published vectors never change. Any change to the combiner bytes needs a new `kem` code, a new salt label and an amendment to this ADR.

Record at first use: the moduletto version and calls used for ML-KEM-768 (ADR-001 records the pin), and whether moduletto checks encapsulation keys as FIPS 203 requires. Also record whether group secrets store the ML-KEM decapsulation key as a seed or in its expanded form.

## Completion part 2, 2026-10-28: chains, erasure and custody backends

Status: Accepted 2026-10-28 (Daniel Thompson-Yvetot).

This section fixes the custody providers "before M3 closes", as the status line of this ADR requires. It must be accepted before W2f starts (M3 design, section 18). The section "Signing keys" above, with its two-tier release signing, is unchanged.

### Hierarchy as built

| Level of this ADR | Object | Held in | Lifetime |
| --- | --- | --- | --- |
| 1 | Root epoch `R(owner, chain, e)` | Custody backend. Created there, never exported | Until the next erasure on that chain, then destroyed |
| 1, wrap step | Epoch seal key `S(owner, chain, e)`, 32 random bytes | Stored only wrapped by `R(e)` through custody `wrap`. Unwrapped into process memory only | Same as `R(e)` |
| 2 | Group key `G(owner, chain, purpose, group, gen)`: X25519 plus ML-KEM-768, or an HMAC or signing key | Public half in `keystore.group_key`. Secret half sealed with AES-256-GCM under `S(e)` | Until its group takes part in an erasure, then replaced by generation `gen + 1` |
| 3 | Data key per object, AES-256-GCM | `keystore.data_key`, sealed to its group key in the part 1 format | Until destroyed |

- `S(e)` is not a root key. It lets one custody call per epoch wrap many level 2 secrets. `R(e)` itself never leaves custody, so I-80 holds for every root epoch.
- `S(e)` is never stored unwrapped, never logged and never serialised. It lives in `Zeroizing` memory, with no `Clone` and no `Debug` output.
- Each group secret is sealed under `S(e)` with an AAD that names owner, chain, purpose, group, generation and epoch.
- Rotation re-seals level 2 secrets under a new epoch. Data is never re-encrypted, as the rules above require. Erasure re-seals surviving data keys of the affected group, which wraps level 3 keys again but leaves data unchanged.

Epoch seal keys and I-80 (decided by Daniel on 2026-10-28):

- Epoch seal keys `S(e)` are not root keys. Only root epochs `R(e)` are root keys, and only they stay in custody.
- `S(e)` lives in process memory, in `Zeroizing` storage that wipes it on drop.
- The memory scan covers `S(e)`. Proposed reading, to be fixed by W1d before code: the simulator gives each epoch a canary `S(e)`. After that epoch is destroyed and zeroised, the scan finds no copy in `fstp-cell` or `fstp-vault` memory. The proposed test name is `i80_destroyed_epoch_seal_key_absent_from_process_memory`.
- I-80 is unchanged. Its claim rests on `R(e)`, which never leaves custody.

### Chains

| Chain | Process | Purposes and groups | Rotated by |
| --- | --- | --- | --- |
| App | `fstp-cell` | `Text`; `Ledger` (one group); `Lookup` and `CredLookup` (HMAC keys of the email and credential id indexes, one group each); `Ticket` (Ed25519); `Anchor` (composite) | Each erasure of App data keys |
| Vault | `fstp-vault` | `Attribute`, `Document` (one group per document), `Fact`, `Match` (identity match key, its own group), `Anchor` | Each erasure of Vault data keys, including every document verification (P-19) |
| CellBackup | `fstp-cell` | Keystore snapshot containers | Yearly re-wrap. Never rotated by erasure |
| ClusterBackup | `fstp-control` | Cluster backup containers | Yearly re-wrap. Never rotated by erasure |
| ControlPlane | `fstp-control`, `fstp-witness` | Licence, staff assertion and operator ticket keys; the witness receipt key | Yearly re-wrap |

- The Vault chain has its own custody entry and its own credential. A compromise of application keys does not expose the vault (R-NF-08).
- `fstp-control` and `fstp-witness` use separate ControlPlane entries and credentials.
- Groups that hold data keys hold at most 256 of them. A `Document` group holds one. That bound keeps the re-seal cost of each affected group at 255 hybrid seals or fewer.
- The `Ledger` group never takes part in an erasure, because the ledger holds no free text (ADR-007). Its data keys are replaced under the part 1 seal-count rule.
- `Lookup`, `CredLookup` and `Match` hold no data keys. Each erasure that removes one of their subjects replaces them (below).

### Epochs

- A root epoch is `Active`, `Retiring` or `Destroyed`. Each chain has exactly one `Active` epoch, plus one `Retiring` epoch only while an erasure runs.
- Provisioning creates epoch 1 of each chain. Epoch numbers only grow.
- `keystore.root` holds, per chain and epoch, the backend, the custody handle, the wrapped `S(e)`, the state and the destroy receipt.
- At start, `fstp-cell` and `fstp-vault` each unwrap their own current `S(e)` through custody. They then open their group secrets locally. No custody call is made per data key or per text open.
- A data key under erasure is refused for open from the moment its request is recorded.

### Erasure construction (Q6)

Daniel chose per-request root-epoch rotation with keyed-digest key replacement on 2026-10-28 (Q6, option A). A copy of a sealed data key in a backup, WAL segment, replica or dead tuple stays recoverable while any live key can open its group key. The wrapping chain itself must therefore die.

- Each erasure request starts a rotation of its chain at once. No timer and no minimum interval apply, so option B's one-minute batching is not used.
- Requests that arrive while a rotation of the same chain runs join the next rotation, which starts as soon as the running one ends. This is the coalescing of M3 design risk R4.
- A document verification puts the document's key into an immediate rotation of the Vault chain (P-19, R-ID-03). The verification fact becomes provisional only after that rotation completes.

One rotation on chain C, from epoch `e` to `e + 1`:

1. Record the requests (`TextErasureRequested` or `DocumentErasureRequested`) and a `keystore.erasure_intent` row. The keys cannot be opened from here on.
2. For each affected group G, create generation `gen + 1`. Open every surviving sibling under G and seal it to the new generation.
3. Create `R(e+1)` in custody and draw a fresh `S(e+1)`. Wrap `S(e+1)` under `R(e+1)`. Re-seal every live group secret of C under `S(e+1)`, locally.
4. Commit the new rows in one transaction. Phase `Committed`.
5. Take a keystore snapshot, sealed under the CellBackup chain. Verify it by opening a sample of live keys from a scratch restore under `R(e+1)`. ADR-012 (Keystore snapshots) names the process that writes and uploads each snapshot. How a Vault chain snapshot is verified is an open point there, and Vault chain rotations wait on it.
6. Destroy `R(e)` in custody and keep the destroy receipt. Zeroize `S(e)` and the old group secrets.
7. Append `KeyEpochDestroyed { chain, epoch, receipt_digest }` and one `TextErased` or `DocumentErased` per key, in one batch.

- After step 6, every copy of an erased key is sealed to an old group generation. That generation's secret was sealed only under epochs up to `e`, and each of them is destroyed. No backup and no live key can open it (I-81, R-KY-02).
- Until step 6, `R(e)` and `R(e+1)` are both alive. A crash at any step loses nothing. The pure planner `fstp_keys::erasure` resumes from the stored phase.
- An erasure is reported complete only at step 7, after the destroy receipt. The erasure-log entry gains `completed_at` and keeps the request time.
- Cost of one rotation: one custody create, one wrap and one destroy; at most 255 hybrid re-seals per affected group; and one AES re-seal per live group of the chain.

**Keyed-digest key replacement.** A keyed digest outlives its plaintext in every backup while its key lives. A guessed email or attribute tuple could then be confirmed against an erased account. Daniel's Q6 answer accepts the cost of replacement.

- When a rotation erases a login email, step 2 also creates a new `Lookup` key. It recomputes the index of every live account from its live sealed email, and the old `Lookup` key dies with `R(e)`.
- When a rotation erases a credential, `CredLookup` is replaced in the same way.
- When a Vault rotation erases an identity, `Match` is replaced in the same way over the live identities' attribute tuples.
- After step 6 no live key can recompute an erased subject's digest. The cost is one HMAC per live account or identity per such rotation.
- The login email lookup (Q22) and the identity match rule (Q17) follow interim readings: interim, pending Daniel.

### Restore rule

- Data tables may come from any backup point.
- Key rows are keyed by stable ids. For each key row, a restore uses the newest available copy: the live store first, then the newest keystore snapshot, then the restored backup's own row.
- A row sealed under a destroyed epoch fails to open. That failure is the intended effect of erasure, not a restore fault.
- No restore tool re-creates a destroyed epoch, and none accepts root material from outside custody.
- Step 5 of every rotation leaves a verified snapshot under the new epoch before the old one dies. A restorable keystore therefore exists for every live epoch.
- ADR-012 implements this rule in the backup container and restore tooling.

### Custody interface

`fstp-custody` defines one trait with six operations: `create_root`, `wrap`, `unwrap`, `destroy`, `sign` and `usage_since`.

- There is no export operation. No code path can ask for root material (I-80).
- A trait without export binds only our own code. A backend that can export key material through its own interface would leave I-80 resting on that backend's access policy. For OKMS-held epochs, the I-80 claim therefore waits on verify item K7. File custody and the simulator do not depend on K7.
- `RootMaterial` is named only in `fstp-keyd` and the test simulator, which a source scan enforces.
- `sign` takes a 32-byte SHA-256 digest and a CA sign key handle, and returns an ECDSA secp256r1 signature.
- `DestroyReceipt` records the backend's own confirmation that the key material is gone, not merely scheduled.
- Each cell records which backend holds each of its chains in `cp.custody_entry`. The choice can differ per cell, as the rules above allow.
- Credentials are per owner and per chain. A backend is used only if no credential can use another cell's keys. For OKMS that waits on verify item K11 below.

### Backends

| Backend | Use in M3 | Status |
| --- | --- | --- |
| `OkmsCustody` | SaaS, the "EU-operated KMS" of this ADR (R-KY-01) | Built. Authentication per Q11 below |
| `KeydCustody` with `fstp-keyd` | Self-hosted small installs, the "passphrase-protected file key" of this ADR | Built, per Q32 below |
| `SimCustody` in `fstp-celltest` | Tests only | Built. Never in a shipped binary |
| PKCS#11 to a CrabNebula-operated HSM | SaaS second option | Not built in M3. A PKCS#11 client crate needs an ADR-001 Tier A review. R-KY-01 is claimed for the EU-operated KMS option only (Q33, `09-milestones.md` NOTE 2) |
| The tenant's own KMS or HSM, self-hosted | Self-hosted | Not built in M3, except that a self-hosted install may use OKMS |

**OVHcloud KMS (OKMS).** OVHcloud was named on 2026-10-28 (ADR-005). The pages read on 2026-10-28, listed in M3 design section 1.6, document the following.

- Key types include `oct` with 256 bits, with encrypt, decrypt, wrapKey and unwrapKey, and EC keys on secp256r1 with sign and verify.
- `protectionLevel` is `SOFTWARE` by default or `HSM`.
- A key must be disabled before deletion, and the pages say that "deleting an encryption key is permanent".
- REST accepts a personal access token, a service account or an access certificate. KMIP requires an access certificate. Billing is per key stored.

Mapping, as proposed:

- Each root epoch is one `oct` 256-bit key at protection level `HSM`, created in the cell's EU region. `wrap` and `unwrap` use wrapKey and unwrapKey.
- Each CA key is one EC secp256r1 key at protection level `HSM`.
- `destroy` disables the key, deletes it, then reads its state back. The receipt holds the key id, digests of the three responses and their times.
- `HSM` is required for every root epoch and CA key (Q11). If the chosen region lacks it, the decision returns to Daniel. No silent fallback to `SOFTWARE` exists.
- The response decoder is fuzzed (`okms_response_decode`).

Authentication, decided by Daniel on 2026-10-28 (Q11: A, otherwise B):

- A: an access certificate over mutual TLS on REST, if OKMS accepts it there.
- B: otherwise, KMIP with the access certificate. Its TTLV codec is in-house in `fstp-custody`, with the fuzz target `kmip_ttlv_decode` from its first commit.
- A personal access token or service account over server-authenticated TLS (option C) is refused.
- The `OkmsCustody` lane waits until A or B is confirmed. Record at first use: the OKMS API or KMIP protocol version.
- R-NF-09 on the OKMS link is claimed only once mutual TLS is confirmed. Until then the interim reading of Q34 applies: interim, pending Daniel.

**File custody (`fstp-keyd`), decided by Daniel on 2026-10-28 (Q32, option A).** The custody boundary is the `fstp-keyd` process.

- Each root epoch is 32 random bytes in its own file `epoch-<chain>-<e>.key`. It is sealed with AES-256-GCM under a per-epoch random key `K(e)`.
- The `K(e)` values live in a separate small key table. It is sealed under a key derived from the passphrase with PBKDF2-HMAC-SHA-256 from aws-lc-rs, at least 600 000 iterations, with a random salt in the table header. PBKDF2 waits on ADR-001 A8 (Open points for Daniel).
- Both live on a separate key volume. That volume is never backed up and never snapshotted.
- `fstp-keyd` refuses to start if the key volume is btrfs, ZFS, overlayfs or a network filesystem.
- The install excludes the key volume from every host backup tool it knows. The operator guide states the condition.
- Destroy overwrites `K(e)` in the key table in place, fsyncs, unlinks the epoch file, fsyncs the directory and reads back. The receipt records each step.
- The key table and frame decoders are fuzzed (`custody_file_decode`, `keyd_request_decode`, `keyd_frame_decode`).

Scope of the I-81 claim for file custody: "the key volume is excluded from host backups and snapshots". SSD block remapping and a backup the install does not know about remain outside it (risk R18). The exit report states this scope. I-81 itself is unchanged, and I-80 is claimed for file custody without that condition.

Operator guide wording, as Q32 C phrases the limit:

> File custody protects root keys from export (I-80). It makes erased data unrecoverable (I-81) only while the key volume is never backed up, snapshotted or copied. If your install cannot guarantee that, use an external KMS or HSM instead of file custody.

Decided by Daniel on 2026-11-01: "i want this to be able to run on anyone's hardware, not just linux. so, if they are running on windows or mac, we just tell them that the ultimate degree of security isn't met, but we should let them continue. in all cases, do not fail on development mode". So `fstp-keyd` no longer refuses a key volume it cannot vouch for. It starts on any host and filesystem, reports full I-81 assurance only on a Linux ext4 or XFS volume, and otherwise reports reduced assurance with the reason. In development mode no host or platform check stops a start (design 21.0).

Access to `fstp-keyd`, as proposed:

- `fstp-keyd` listens on one Unix socket per client OS user. Directory and socket permissions let only that user connect, so std alone suffices and no crate is added.
- Each socket serves a fixed set of chains and keys. `fstp-cell` reaches App and CellBackup. `fstp-vault` reaches Vault only. `fstp-pgagent` reaches the local cluster CA sign keys.
- A root-only console socket serves the host console recovery (Q15) and the restore command. Each use is logged.

Recorded at first use (lane W2f, 2026-10-29):

- **Sign key classes.** The first byte of a sign key handle names its class. `0x01` is a cell CA key, which only the `fstp-cell` socket may use. `0x02` is a local cluster CA key, which only the `fstp-pgagent` socket may use. The vault and console sockets and any other class byte get `NotPermitted`.
- **Epochs without gaps.** A create is epoch 1 for a new chain, or the newest epoch plus one. Anything else is `BadRequest`. So every epoch below the newest really existed, and a destroy of an uncreated epoch, epoch 0 included, gets `UnknownRoot` and no receipt.
- **Damaged usage records.** A usage record that fails its check is not dropped. Each page that spans it carries a 9-byte marker in its place: the tag `0xf0`, then the log index of the record as a u64. Reconciliation raises `CustodyAnomaly` on it.
- **Connection limits.** Each socket serves at most 16 connections at once. A request must arrive and its response go out within 5 seconds of the accept, so one slow client cannot stall another socket. The client side times out after 30 seconds.

Unattended boot (I-80, R-NF-05):

- There is no default passphrase.
- The passphrase comes from a systemd credential (`LoadCredentialEncrypted=`), bound to the host's TPM 2.0 where one exists.
- Without a TPM, `fstp-keyd` waits for the operator to enter it through `systemd-ask-password`. The cell does not start until then.
- Record at first use: the minimum systemd version, after W2f checks these features.

Per-epoch TPM objects (Q32, option B) are evaluated with the M9 self-hosted package.

**Self-hosted install (Q15).** Daniel accepted the local install agent on 2026-10-28. `fstp-install` has `fstp-keyd` create the App, Vault and CellBackup chain entries. It also creates one EC secp256r1 sign key per local cluster CA, so cluster CA keys live in local custody.

**Simulator.** `SimCustody` lives only in `fstp-celltest` and runs as its own process, `fstp-custody-sim`.

- It holds known canary root bytes, so memory scans of `fstp-cell` and `fstp-vault` can show they never hold them (I-80).
- It keeps a usage log for reconciliation tests, and injects a failure after any operation for M-SHRED and crash tests.
- deps-check keeps `fstp-celltest` out of every shipped binary (layering rule 9).

### CA keys in custody

| CA | Created by | Sign key held in |
| --- | --- | --- |
| Cluster CA, one per self-operated PostgreSQL cluster | `fstp-control` at cluster registration, or `fstp-install` when self-hosted | SaaS: control-plane custody. Self-hosted: `fstp-keyd` |
| Cell CA, one per cell | The cell at first start | The cell's App custody entry |
| Control-plane CA, one per environment | Once, at environment set-up | Control-plane custody |

- Every CA key is an EC secp256r1 key created inside custody and never exported. `fstp-pki` builds the certificate bytes, and custody `sign` signs their digest.
- Each CA rolls over yearly, with an overlap in which both keys are trusted.
- Cell erasure (R-SW-02) destroys the cell CA key together with every live root epoch of the cell's App, Vault and CellBackup chains. The erasure confirmation lists every destroy receipt.

### Signing key placement in M3

| Key | Algorithm | Placement | Rotation |
| --- | --- | --- | --- |
| App chain anchor key, per cell | Composite Ed25519 plus ML-DSA-65 | App chain level 2 key, purpose `Anchor`. This is the "Level 2 key of the cell" of the table above | Re-sealed under each new epoch. Replaced yearly. Old public keys stay in the anchor key history the witness holds |
| Vault chain anchor key, per cell | Composite | Vault chain level 2 key, purpose `Anchor` | As above |
| Vault ticket key, per cell | Ed25519 | App chain level 2 key, purpose `Ticket` | Yearly, and on suspicion. The vault pins the current and the next public key |
| Witness receipt key | Composite | The witness's own ControlPlane custody entry, with a separate credential | Yearly. Cells pin a set of witness keys. A new key is announced signed by the old one |
| Licence token key | Ed25519 | Control-plane custody, level 2 under chain ControlPlane | Yearly. A key-transition statement signed by the current key adds the next one |
| Staff assertion key, operator ticket key | Composite | Control-plane custody, level 2 under chain ControlPlane | Yearly. Each cell pins the current and the next public key at provisioning |
| Restore declaration key | Composite | Control-plane custody, level 2 under chain ControlPlane, held by `fstp-control` | Yearly. The witness pins the current and the next public key. Interim, pending Daniel: proposed by ADR-012 (Declared restores at the witness) |

- The export manifest key, the notice companion key, and the profile bundle and template keys are not built in M3. When built, they follow the "Signing keys" table above.
- Release root and release signing keys are not built in M3 (I-91 is an M9 exit). The two-tier release signing above stands unchanged.
- ML-DSA-65 halves come from moduletto (I-75), and every composite verifier requires both halves (I-90).
- moduletto has no ML-DSA-65 yet. Until the pull request of ADR-001 A2 lands, every composite key above refuses to sign with a typed error, and none is created in production. aws-lc-rs ML-DSA is never a production fallback (Daniel, 2026-10-28).

### Reconciliation

The rule "Root key use is logged by the backend, and the log is reconciled with the cell's audit chain" is built as follows.

- Every custody call carries a request id. The call is recorded as a `KeyOp` event in the owning chain (App or Vault).
- Daniel decided on 2026-10-29 that a custody call of the cell is recorded both ways: as a sealed `KeyOp` event in the App chain and as a `RecordKeyOp` ledger record (M3 design section 5.1). Both carry the same request id. Proposed reading: reconciliation compares the backend usage log with the chain events, and each event with its ledger record. The vault has no domain ledger, so a vault custody call has the Vault chain event only (ADR-010 open point 5).
- Normally the `KeyOp` event is written before the call.
- The start-up `unwrap` of `S(e)` is the one exception, because the chain cannot be written before `S(e)` is open. Its request id goes into an operational `keystore` row before the call, and the `KeyOp` event follows once the chain is open. This exception is an addition to M3 design section 3.3.
- A daily task reads `usage_since` from the backend and compares. A backend entry without a matching request id raises `CustodyAnomaly` to tenant admins and the auditor view.
- `fstp-keyd` keeps an append-only usage log of request ids, operations, chains, epochs, times and client users. The log holds no key bytes, so it may sit outside the key volume.
- OKMS documents no usage log on the pages read (M3 design G19). OKMS reconciliation waits on verify item K6. If OKMS offers no such log, Daniel decides how this rule is met for OKMS.
- Test: `i24_custody_ops_reconcile_with_key_records`, against the simulator log.

### Residual risk

Root on a cell or vault host can read unwrapped `S(e)` and group secrets in process memory. Sandboxing does not stop root. This is not a root key leaving custody, so I-80 is not weakened. It is a path to content around SoD-08 (M3 design risk R16). Daniel accepted this residual risk on 2026-10-28 (Q35), under separate host staff, no standing root, two-person access and access events visible to the tenant. Confidential computing is evaluated in L-15.

### Tests

- I-80: `i80_custody_has_no_export_and_root_material_cannot_escape`, `i80_root_material_named_only_in_keyd`, `i80_root_canary_absent_from_cell_and_vault_memory`, `i80_root_canary_absent_from_logs_dumps_and_backups`, `i80_file_custody_root_confined_to_keyd`, `i80_teeth_leaking_custody_is_caught`. Proposed with the decision on epoch seal keys above: `i80_destroyed_epoch_seal_key_absent_from_process_memory`. The memory scan runs on Linux CI (Q27: interim, pending Daniel).
- I-81: `i81_m_shred`, `i81_erased_text_unrecoverable_from_every_backup`, `r_id_03_document_unrecoverable_after_verification`, `r_sw_02_cell_erasure_kills_every_backup`, `i81_completion_recorded_only_after_destroy_receipt`, `i81_erasure_resumes_after_crash_at_every_step`, `i81_erased_email_digest_cannot_be_recomputed_from_backups`, `i81_erased_identity_match_key_cannot_be_recomputed_from_backups`.
- I-81, file custody: `i81_file_custody_destroy_leaves_no_openable_epoch_on_the_key_volume`, `i81_keyd_refuses_copy_on_write_key_volume`.
- I-81 teeth: `i81_teeth_group_not_rotated_is_caught`, `i81_teeth_destroy_before_commit_loses_data_is_caught`.

### Verify list

This is the single OKMS verify list. ADR-005 and ADR-012 refer to its items by id and keep no copy. K1 to K9 keep the ids they had in the ADR-005 amendment draft, so earlier references stay valid.

These items are unverified. Daniel asks OVHcloud about them (Q11 answer), and L-15 covers the provider facts. Until each closes, the claim that depends on it is not made.

| ID | Item | Claim that waits on it |
| --- | --- | --- |
| K1 | Does REST accept an access certificate as mutual TLS? If not, which KMIP operations does OKMS support for create, wrap, unwrap, sign, disable and delete? | Q11 choice between A and B; R-NF-09 on the OKMS link |
| K2 | Which EU regions offer the `HSM` level today? | `HSM` for every root epoch and CA key |
| K3 | Does the FIPS 140-3 claim on the product page cover those regions and the `HSM` level? | `HSM` for every root epoch and CA key |
| K4 | Does deleted key material survive in provider backups, and for how long? | I-81 for OKMS-held epochs |
| K5 | What rate limits and key quotas apply? What does one create and delete cycle cost under per-key billing? | Per-request rotation (Q6 A) at expected erasure rates |
| K6 | Is every key operation logged, not only lifecycle events, in a form we can read for reconciliation? | Reconciliation for OKMS |
| K7 | Can a key be created so that its material can never be exported? The M4 design notes, as a lead only, that OKMS BYOK offers to "import and export key material". Can export be disabled per key, and can a cell's credential be denied it? | I-80 for OKMS-held epochs. If export cannot be disabled per key, I-80 there rests on access policy alone |
| K8 | Which certification covers the `HSM` protection level, described as "shared specialised hardware"? | `HSM` for every root epoch and CA key |
| K9 | What is the general availability date, contract and certification of Cloud HSM with PKCS#11 and of Dedicated HSM? | R-KY-01 second backend, not needed in M3 |
| K10 | Does deletion remove the material at once, or is it scheduled? Which response proves it is gone? | `DestroyReceipt` content |
| K11 | Can an access certificate be limited to one cell's keys or one OKMS domain? | Per-cell, per-chain credentials; I-19 |
| K12 | How is an access certificate issued? Can the component generate its own key pair, so the private key never leaves the host? | Credential handling for the cell and vault |
| K13 | Do wrapKey or encrypt accept additional authenticated data? | The `wrap` AAD. Without it, binding rests on one key per owner, chain and epoch |
| K14 | Does sign accept a precomputed SHA-256 digest? Is the signature DER or raw `r || s`? | CA signing through custody |
| K15 | Can keys be confined to EU regions, excluding Erith (UK) and any other non-EU region? | R-HS-01, with L-15 |

W2f also checks these items on the host side.

- Whether the filesystem type check can use `statfs`. std exposes no `statfs`, and the libc crate is allowed only in a build role (ADR-001 Record). The alternative reads `/proc/self/mountinfo`, which is an in-house parser and needs a fuzz target from its first commit.
- Whether a journal mode of the chosen filesystem copies data blocks into the journal. If one does, `fstp-keyd` also refuses that mode.
- The systemd version that provides the credential features above.

### Open points for Daniel

- Self-hosted physical cluster backups need a ClusterBackup chain entry, which M3 design section 9.5 does not list. Proposed: `fstp-install` creates one per local cluster, usable only through the root-only console socket.
- The self-hosted witness needs custody for its receipt key, which section 9.5 also omits. Proposed: a `fstp-keyd` ControlPlane entry with its own socket for the `fstp-witness` OS user.
- ADR-001 lists the aws-lc-rs functions in use. The ADR-001 amendment of 2026-10-28 adds PBKDF2-HMAC-SHA-256 for the file custody key table and AES-256-GCM-SIV as a conditional fallback (ADR-001 A8). Daniel accepted A8 with that amendment on 2026-10-28, so the file custody KDF is no longer blocked on it.
