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
- Chain codes: App 1, Vault 2, CellBackup 3, ClusterBackup 4, ControlPlane 5. Purpose codes come from `fstp_keys::Purpose`. The purpose code table below records them (accepted by Daniel on 2026-11-07), and it is frozen.
- `owner` is the `CellId`. For the ClusterBackup chain it is the `ClusterId`, and for the ControlPlane chain the environment id.
- `object` is the data key id. `ctx` is not stored, because the caller supplies it from the row that names the key.
- `open_key` compares the header's chain, group and generation with `ctx` before any decapsulation. A sealed key moved to another object, group, generation, chain or cell fails to open.
- The decoder accepts exactly 1210 bytes, the magic, version 1, and known codes. Any other input is refused. It re-encodes byte for byte. The fuzz target `sealed_key_decode` exists from the first commit.
- Each `kek` seals once. The nonce is still drawn at random, under the rule below, so the rule has no exception.
- **A sealed key is not sender-authenticated.** Accepted (Daniel, 2026-11-18, issue 6 L15). `E` is an ephemeral key, so anyone who holds the group public key can make a sealed key that opens. The envelope binds a sealed key to its owner, chain, purpose, group, generation and object. It does not prove who sealed it. Authenticity of a sealed key comes from the integrity of the row that holds it and from database role separation, not from the envelope. A writer of keystore rows could substitute a sealed key, and could then also write the blobs under it. The ledger chain and its anchoring (ADR-007) detect a changed history. No signature is added to the format.

Sealed blobs (texts, ledger bodies, chain events, checkpoints, outbox rows, keystore secrets and backup chunks) use AES-256-GCM under their data key. Their AAD binds each blob to its owner and its position, so a blob moved to another cell, row or object fails to open. The exact AAD and layout belong to the ADR that owns the table: ADR-007 for ledger and chain rows, and ADR-012 for backup containers (M3 design, section 18).

**Vault sealed values.** Decided (Daniel, 2026-11-15: "Record it in ADR-004"). The vault owns its tables, so this ADR records their layout.

```
sealed = nonce 12 | ciphertext | tag 16
aad    = column name || "|" || row key
```

- `fstp_vault::AeadSealer` seals every such value with AES-256-GCM under the Vault chain data key, through `fstp_crypto::aead::seal` (nonce rule below).
- The nonce sits at offset 0. The ciphertext has the plaintext's length, and the 16-byte tag follows it.
- The column name in the AAD is the table and column, such as `vault.epoch.affected`. The row key is the row's epoch, fact, proposal or entry key.
- Columns with this layout: `vault.epoch.affected`, `vault.fact.body`, `vault.negotiation.sealed_accounts` and `vault_audit.chain.body`. The chain body's row key is its entry sequence number as a big-endian `u64`.
- A reader that checks the nonce rule, such as the R-NF-08 test, reads the nonce from offset 0 of these values.

**Application sealed values.** Recorded by lane L1 on 2026-11-20, from the code of lanes L1, L2 and L3, for the nonce check of R-NF-08 (`r_nf_08_aborted_append_never_reuses_a_nonce`). Every value below is an AES-256-GCM seal through `fstp_crypto::aead::seal`, with a random nonce under the rule below. None uses a deterministic key wrap, so every column has a nonce a reader can check.

| Layout | Nonce at | Columns |
| --- | --- | --- |
| `nonce 12 \| ciphertext \| tag 16`, in a table whose `key_ix` column names the ledger key generation | 0 | `ledger.entry.body`, `ops.checkpoint.body`, `api.pending_actions.request`, `workspace.drafts.sealed` |
| `nonce 12 \| ciphertext \| tag 16`, under the epoch seal key `S(e)` | 0 | `keystore.chain.state` (AAD `"fstp-chain-state-v1"`, cell, chain, epoch), `keystore.group_key.sealed_secret`, `keystore.signer.sealed_secret` |
| `nonce 12 \| ciphertext \| tag 16`, under the row's own outbox data key | 0 | `ops.outbox.body` |
| A wrapped seal key of `fstp-keyd` or the custody simulator: `nonce 12 \| S(e) 32 \| tag 16`, exactly 60 bytes, under the root `R(e)` | 0 | `keystore.root.wrapped_seal_key` |
| A sealed blob of `fstp_keys::envelope`: `"FSB1" \| version u8 = 1 \| aead u16 = 1 \| nonce 12 \| ciphertext \| tag 16` | 7 | `blob.text.envelope`, `keystore.text.envelope`, `doc.blob.envelope`, and any other column holding that form |
| A sealed key (section "Sealed key format"): 1210 bytes from `"FSK1"` | 1150 | `keystore.data_key.sealed` |
| An App chain event (ADR-010 amendment of 2026-11-20): `be32(key_ix) \| nonce 12 \| ciphertext \| tag 16` under the ledger key generation `key_ix` | 4 | `audit.chain.body` of a kind 2 row |

- A wrapped seal key of another backend, such as OKMS, has the layout of that backend. It is recorded here before that backend wraps a production root. Until then a reader that meets another length reports the value as unread, so the check fails closed.
- `keystore.erasure_intent.plan` and `ops.licence_state.sealed_token` have no writer in the cell yet. Their layout is recorded here with their first writer. Until then a reader that meets a value reports it as unread.
- `keystore.erasure_intent.plan` of the vault database `v_<cell>` (lane L11, 2026-11-21): `nonce 12 | ciphertext | tag 16`, nonce at 0, under the epoch seal key `S(e)` of the Vault chain, AAD `"fstp-vault-chain-state-v1"`, cell, chain and epoch. `keystore.identity_tuple.envelope` of the vault database holds a sealed blob of `fstp_keys::envelope`, nonce at 7. The same column of the application database still has no writer.
- `doc.blob.envelope` (lane L5, 2026-11-21, the blob store of the API core): a sealed blob of `fstp_keys::envelope`, nonce at 7, under a fresh data key of a group of its own, so erasing the group erases the blob. The data key is kept in `keystore.data_key` like a text's, and its id is `doc.blob.dek`. The blob's context is the text context of the cell, the group and the data key id at generation 0, so a later re-seal of the data key at another generation still opens it. The plaintext is `"fstpblb1" \| owner kind u8 = 1 \| programme 16 \| bytes`, and `doc.blob.digest` is the SHA-256 of the bytes.
- `workspace.drafts.sealed` holds the seal without the generation prefix of `fstp_pgstore::seal_workspace`. The prefix lives in the row's `key_ix` column, and the store puts it back on read.

### Purpose code table

Status: Accepted by Daniel Thompson-Yvetot on 2026-11-07 (m3-finish Q-E). The table is frozen.

The `purpose u8` of `ctx` takes one code per `fstp_keys::Purpose` variant, in declaration order. Code 0 names no purpose. A code is never reused or renumbered, and a new purpose takes the next free code.

| Code | `Purpose` | What it seals or keys |
| --- | --- | --- |
| 1 | `Ledger` | A ledger entry |
| 2 | `Text` | A text of the text store |
| 3 | `AuditEvent` | An audit event body |
| 4 | `Checkpoint` | A checkpoint of the projections |
| 5 | `Backup` | A backup chunk |
| 6 | `Lookup` | The HMAC key of the login email index (App chain) |
| 7 | `CredLookup` | The HMAC key of the credential id index (App chain) |
| 8 | `Ticket` | The vault ticket key (App chain, Ed25519) |
| 9 | `Anchor` | A chain's composite anchor key |
| 10 | `Attribute` | An identity attribute (Vault chain) |
| 11 | `Document` | An identity document (Vault chain) |
| 12 | `Fact` | A vault fact (Vault chain) |
| 13 | `Match` | The identity match key (Vault chain) |
| 14 | `NoticeCompanion` | The composite notice companion signing key (App chain). Added by M9 lane C2 on 2026-11-13 as the next free code, interim, pending Daniel |

`fstp_keys::Purpose::code` implements this table, and `fstp_celltest::reference::keys::purpose_code` copies it. The code binds through the AAD of the wrapped data key, since `ctx` is not stored.

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
| App | `fstp-cell` | `Text`; `Ledger` (one group); `Lookup` and `CredLookup` (HMAC keys of the email and credential id indexes, one group each); `Ticket` (Ed25519); `Anchor` (composite); `NoticeCompanion` (composite, M9 lane C2) | Each erasure of App data keys |
| Vault | `fstp-vault` | `Attribute`, `Document` (one group per document), `Fact`, `Match` (identity match key, its own group), `Anchor` | Each erasure of Vault data keys, including every document verification (P-19) |
| CellBackup | `fstp-cell` | Keystore snapshot containers | Yearly re-wrap. Never rotated by erasure |
| ClusterBackup | `fstp-control` | Cluster backup containers | Yearly re-wrap. Never rotated by erasure |
| ControlPlane | `fstp-control`, `fstp-witness` | Licence, staff assertion and operator ticket keys; the witness receipt key | Yearly re-wrap |

- The Vault chain has its own custody entry and its own credential. A compromise of application keys does not expose the vault (R-NF-08).
- `fstp-control` and `fstp-witness` use separate ControlPlane entries and credentials.
- The self-hosted witness receipt key has its own `fstp-keyd` entry with its own credential (Daniel, 2026-11-13, m3-finish Q-D, ADR-010 open point 6). See "Self-hosted witness receipt key" below.
- Groups that hold data keys hold at most 256 of them. A `Document` group holds one. That bound keeps the re-seal cost of each affected group at 255 hybrid seals or fewer.
- The `Ledger` group never takes part in an erasure, because the ledger holds no free text (ADR-007). Its data keys are replaced under the part 1 seal-count rule.
- `Lookup`, `CredLookup` and `Match` hold no data keys. Each erasure that removes one of their subjects replaces them (below).
- The delivery body digest key of `ops.delivery.body_digest` is derived from the App chain `Lookup` key through HKDF-SHA256 with the fixed label `fstp delivery body digest v1`, so a new `Lookup` key gives a new digest key (Daniel, 2026-11-07).
- The display name fingerprint key (SA-11 amendment, lane m4/unique-names) is derived from the App chain `Lookup` key through HKDF-SHA256 with the fixed label `fstp display name fingerprint v1`. Each fingerprint is HMAC-SHA256 of the normalised name under it. A display name is a subject of `Lookup`, like a login email. An erasure that removes one replaces `Lookup`, and step 2 recomputes the fingerprint of every live display name from its sealed text. Decided by Daniel on 2026-11-21.

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

Recorded at first use by lane m3/erase-cell, 2026-11-13. Interim, pending Daniel:

- **Destroying a sign key.** The `Custody` trait keeps its six operations (I-80). Destroying a CA sign key is a separate trait, `fstp_control::erase::SignKeyCustody`, with one operation. It returns a `DestroyReceipt` as `destroy` does. The test custody implements it. `OkmsCustody` and `KeydCustody` do not yet, so cell erasure runs in the test world only.
- **What is destroyed.** `fstp-control erase-cell` takes the cell's live roots and CA sign keys as input. It refuses a root of another cell, and a root of the ClusterBackup or ControlPlane chain. In production the list comes from `cp.custody_entry` and the backend's own listing, which is not built.
- **Erasure confirmation.** A composite signature under the context `fstp-cell-erasure-v1`. The signed body holds the cell, the erasure time, the job digest, both approvers, and one entry per destroyed key: chain code (0 for a CA key), handle and receipt. The key is a control-plane composite key, level 2 under chain ControlPlane, handed in by the caller. Its custody placement and rotation follow the staff assertion key.
- **Order.** The design's step 1 and step 4 run: every key is destroyed, then the confirmation is issued. Steps 2 and 3, dropping the databases and removing the routes, need the destructive `fstp-pgagent` jobs and the edge route removal, which are not built. Superseded by the record of lane m3/erase-cell-2 in ADR-011 and below.

Recorded at first use by lane m3/erase-cell-2, 2026-11-13. Interim, pending Daniel:

- **Sign key destroy in file custody.** The keyd protocol gains request kind `0x07`: the request id, a handle length octet and the handle. Socket access follows the sign rules by class byte, so the `fstp-cell` socket destroys cell CA keys only and the `fstp-pgagent` socket cluster CA keys only. The usage log records it as operation 7, `destroy-sign-key`, with no root. `KeydCustody::destroy_sign_key` sends it, and `fstp-control` implements `SignKeyCustody` for `KeydCustody` through it. The six operations of `Custody` are unchanged (I-80).
- **Sign key receipt.** `"FKS1"`, version 1, the handle with a length octet, then the step count and the step codes of a root destroy. The client accepts a receipt only when it lists every step once and in order and names the destroyed handle.
- **No sign key in `fstp-keyd` yet.** No request creates a sign key, neither the install step that creates the local cluster CA keys nor the cell's first start. So `fstp-keyd` holds none, and a permitted sign key destroy answers `NoSignKey`, as `sign` does. Storing sign keys needs a slot form in the key table beside the root slots, so that a destroy overwrites the key in place. That form is open for Daniel.
- **OKMS.** `OkmsCustody` still has no sign key destroy, since its network calls wait on Q11.
- **Order of cell erasure.** `fstp_control::erase::erase_cell_steps` runs design section 3.7 in order. It first checks the erasure job, the key list, and four approved drops with their evidence: the database, then its roles, on the application cluster, then the same on the vault cluster. Nothing is destroyed if a check fails. Step 1 destroys every key. Step 2 has each agent drop the database and its roles and rewrite `pg_hba.conf`. Step 3 removes every route of the cell at the edge. Step 4 signs the confirmation, whose body is unchanged.
- **Erasure log.** Each custody call is logged before it is made, and each finished step after it, in the approval log under the erasure job's digest. A failure after step 1 stops the job with no confirmation, and the log shows the last finished step. Resuming such a job needs its state in `cp.job`, which is not built.
- **Not yet in step 2 and step 3.** Step 2 revokes the cell's witness credentials after the database drops, through `fstp_control::erase::WitnessCredentials` (lane m3/finish-gaps, 2026-11-15). It deletes no object of the cell's object storage prefix (Daniel, 2026-11-15 night, below). Only tests implement the trait. The witness has no operation that deletes a cell's credentials, and `witness.cell_ca` refuses DELETE under a trigger, with the anchor rows referencing it. So the witness side needs a design: a revocation record beside `cell_ca`, or a delete that the append-only rule admits. Step 3 reaches an edge in the same process through `fstp_edge::LiveRoutes`. The route feed from `fstp-control` to a remote `fstp-edge` is not designed.
- **Approvals per erasure.** Each drop is its own destructive job with its own digest, so an erasure needs five approvals from each of two operators. A batch approval over several digests is open for Daniel.

### Signing key placement in M3

| Key | Algorithm | Placement | Rotation |
| --- | --- | --- | --- |
| App chain anchor key, per cell | Composite Ed25519 plus ML-DSA-65 | App chain level 2 key, purpose `Anchor`. This is the "Level 2 key of the cell" of the table above | Re-sealed under each new epoch. Replaced yearly. Old public keys stay in the anchor key history the witness holds |
| Vault chain anchor key, per cell | Composite | Vault chain level 2 key, purpose `Anchor` | As above |
| Vault ticket key, per cell | Ed25519 | App chain level 2 key, purpose `Ticket` | Yearly, and on suspicion. The vault pins the current and the next public key |
| Witness receipt key, SaaS | Composite | The witness's own ControlPlane custody entry, with a separate credential | Yearly. Cells pin a set of witness keys. A new key is announced signed by the old one |
| Witness receipt key, self-hosted | Composite | A separate `fstp-keyd` entry of the local witness, chain ControlPlane, with its own credential (Q-D, below) | As the SaaS key |
| Licence token key | Ed25519 | Control-plane custody, level 2 under chain ControlPlane | Yearly. A key-transition statement signed by the current key adds the next one |
| Staff assertion key, operator ticket key | Composite | Control-plane custody, level 2 under chain ControlPlane | Yearly. Each cell pins the current and the next public key at provisioning |
| Restore declaration key | Composite | Control-plane custody, level 2 under chain ControlPlane, held by `fstp-control` | Yearly. The witness pins the current and the next public key. Interim, pending Daniel: proposed by ADR-012 (Declared restores at the witness). Self-hosted, interim, pending Daniel (ADR-012 record of lane m10/declared-restore): no such key exists. The local witness signs each declaration with its own receipt key under the context `fstp-restore-v1`, and only root reaches the console command. Daniel decided on 2026-11-25 to keep that signer for self-hosted hosts. SaaS, interim, pending Daniel (ADR-012 record of lane m10/saas-declare): the key is sealed in `restore-declaration.key` under a seal key that `fstp-keyd` wraps under a ControlPlane root, as the route feed key is. Its public keys reach the witness as `restore-declaration-keys` |

- The export manifest key, the notice companion key, and the profile bundle and template keys are not built in M3. When built, they follow the "Signing keys" table above.
- Record, M9 lane C2, 2026-11-13 (interim, pending Daniel): the notice companion key is a composite App chain level 2 key with purpose `NoticeCompanion` (code 14), separate from the `Anchor` key (M9 design D6). It signs only through `CompositeSigningKey::sign_with_context` under the context `fstp-notice-companion-v1`, in `fstp_contract::notice_companion`. Its verifier is a row of the I-90 sweep. Placement in the cell keystore and its yearly rotation follow the `Anchor` key and arrive with the notice store.
- Record, M9 finish, 2026-11-13 (interim, pending Daniel): the App chain keystore (`fstp_cell::tasks::erasure`) creates the `NoticeCompanion` key at first use and holds it as a sealed level 2 signing key. Its private key `mldsaSeed || tradSK` is sealed with AES-256-GCM under the epoch seal key `S(e)`, which custody wraps under `R(e)`, with the AAD `fstp-level2-signer-v1`, cell, chain, purpose code, generation and epoch. Each new epoch reseals it with the group secrets, and the snapshot check opens it. `rotate_signer` makes the next generation and keeps the replaced public key. A generation is due for rotation after 365 days. No scheduler triggers the rotation yet. Creating or rotating the key makes no custody call. Since 2026-11-15 (late) it still appends a `RecordKeyOp` (`create_signer` or `rotate_signer`), as recorded below. The `Anchor` key is still handed in by the caller.
- Record, lane m3/cell-routes, 2026-11-15 (interim, pending Daniel): the cell signs vault tickets itself. The `Ticket` key reaches the cell as the `Anchor` key does: the caller hands it in (`fstp_cell::process::CellKeys::ticket`), and the route backend holds it. The keystore does not yet create, seal or rotate it as a level 2 key of purpose `Ticket`, so its custody placement and yearly rotation above are not built. With no key the ticket routes answer 501 before the engine runs, so no issue record commits without its ticket. The vault pins the key's public key at provisioning, as before. Proposed next step: the keystore creates the key at first use as it creates the `NoticeCompanion` key, sealed under `S(e)`, Ed25519 instead of composite.
- Release root and release signing keys are not built in M3 (I-91 is an M9 exit). The two-tier release signing above stands unchanged.
- ML-DSA-65 halves come from moduletto (I-75), and every composite verifier requires both halves (I-90).
- moduletto has no ML-DSA-65 yet. Until the pull request of ADR-001 A2 lands, every composite key above refuses to sign with a typed error, and none is created in production. aws-lc-rs ML-DSA is never a production fallback (Daniel, 2026-10-28).

### Self-hosted witness receipt key

Decided by Daniel on 2026-11-13 (m3-finish Q-D, ADR-010 open point 6): the receipt key of a self-hosted local witness has a separate `fstp-keyd` entry with its own credential.

- The entry belongs to the witness alone. Its chain is ControlPlane. The credential is readable only by the `fstp-witness` OS user, and no other component's credential can use the entry.
- `fstp-install` creates the entry and the key at first start, before it starts the witness (design section 9.5, step 6). B-06 defers the installer, so the M3 test world plays this step.
- The key is a level 2 key. Its secret half is the 64-byte composite private key of `CompositeSigningKey::to_bytes`, sealed under the epoch seal key `S(e)` of the entry. Those bytes are sealed for this one key only (ADR-010, "Component key reuse").
- Interim, pending Daniel: the seal binds purpose `Anchor` (code 9), the composite signing key purpose, with chain ControlPlane. The owner and the chain keep it apart from any anchor key, so no new purpose code is added.
- Interim, pending Daniel: the key file `receipt.key` in the witness credentials directory. It holds the custody root reference, the wrapped `S(e)` and the sealed secret. Its layout is in `fstp_witness::config`, with a fuzz target from its first commit.
- The SaaS witness keeps its own ControlPlane custody entry, as the table above says. Until the OKMS client takes a ControlPlane entry, the SaaS witness process reads its key through the same `fstp-keyd` path.

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
- Record, lane m3/seams-custody, 2026-11-13 (interim, pending Daniel):
  - `RequestId` moved to the root of `fstp-custody`. The `Custody` trait keeps its six operations (I-80). A caller makes a call under its id with `fstp_custody::with_request`, which holds the id while the call is made and polled. A backend with a usage log reads it with `current_request`, or uses a fresh id. The `fstp-keyd` client and the simulator log it.
  - The 41-byte usage record of `fstp-keyd` is now the shared layout `fstp_custody::usage`, with a decoder and the fuzz target `usage_record_decode`. The simulator writes the same layout.
  - The `RecordKeyOp` body is `fstp_keys::keyop`, with the fuzz target `key_op_decode`. The cell keystore records each call with a fresh id and passes the same id to custody.
  - The start-up `unwrap` keeps its request id in the keystore before the call. `ErasureRunner::from_open` writes the deferred record with it.
  - `fstp_custody::usage::reconcile` matches by request id and operation, one record per usage entry. It skips `usage_since` reads, which use no root key.
  - The test reads the `RecordKeyOp` ledger records. No cell code writes the sealed `KeyOp` event of the same call yet, and no task runs the reconciliation daily.

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

- The purpose code table above is Proposed (m3-finish Q-E). Daniel accepts it, or names other codes, before the F-CRYPTO lane merges.
- Self-hosted physical cluster backups need a ClusterBackup chain entry, which M3 design section 9.5 does not list. Proposed: `fstp-install` creates one per local cluster, usable only through the root-only console socket.
- The self-hosted witness needs custody for its receipt key, which section 9.5 also omits. Proposed: a `fstp-keyd` ControlPlane entry with its own socket for the `fstp-witness` OS user. Decided by Daniel on 2026-11-13 (m3-finish Q-D): a separate `fstp-keyd` entry with its own credential. Recorded under "Self-hosted witness receipt key".
- ADR-001 lists the aws-lc-rs functions in use. The ADR-001 amendment of 2026-10-28 adds PBKDF2-HMAC-SHA-256 for the file custody key table and AES-256-GCM-SIV as a conditional fallback (ADR-001 A8). Daniel accepted A8 with that amendment on 2026-10-28, so the file custody KDF is no longer blocked on it.

## Decided by Daniel, 2026-11-15 (late)

- **Witness credentials on cell erasure.** The witness appends a revocation record beside `witness.cell_ca` and refuses the revoked cell from then on. `cell_ca` stays append-only, and the anchor rows keep their references. The cell's secret key material is destroyed through custody.
- **Approvals per erasure.** One batch approval per operator per erasure. Each of the two operators approves once, with a passkey, over a signed list of all the erasure's job digests. The two-operator rule is unchanged.
- **Sign keys in `fstp-keyd`.** The key table gains a sign-key slot form beside the root slots. Install creates the local cluster CA sign keys there, and a destroy overwrites the key in place.
- **Route removal on a remote edge.** Each `fstp-edge` polls a signed route table from `fstp-control`. The erasure finishes route removal once every edge reports the table version without the cell's routes.
- **Level 2 signing keys.** Creating or rotating a level 2 signing key appends a key record, although no custody call is made. Built by lane m5/retention: the `KeyOp` body names the call `create_signer` or `rotate_signer`, with the chain, the current epoch and a fresh request id. `fstp_keys::keyop::KeyCall::is_custody_call` is false for both, so reconciliation skips them.

## Built by lane m3/erase-prod, 2026-11-15

Each entry builds one decision of the section above. Interim readings are marked "interim, pending Daniel".

- **Witness revocation.** Witness migration 4 adds `witness.cell_revocation`: the cell, referencing `witness.cell_ca`, and the revocation time. It is append-only under the same triggers as the other witness tables. Triggers also refuse an anchor key, an anchor row or a withdrawal of a revoked cell. `witness.cell_ca` and every record of the cell stay.
  - The witness refuses every request of a revoked cell, on open connections too. It asks its store once per request until it knows the cell is revoked, so a revocation another login wrote counts from the next request. It then unpins the cell's CA, and a registry reload or a restart pins it no more. A registration of a revoked cell is refused.
  - The local witness of a self-hosted install appends a registry record of tag 3: the cell and the revocation time. The registry loader refuses a second revocation, one of an unknown cell, and an anchor key after it. The loader keeps its fuzz target `file_store_records_decode`.
  - `fstp_control::erase::WitnessRegistry` implements `WitnessCredentials`. It logs in to the witness database as `witness_migrator`, as provisioning does to register a cell, and appends the row (`fstp_witness::store::revoke_cell`). Interim, pending Daniel: `witness_service` gains SELECT on the new table only, so the service still cannot write the registry. The erasure step is now `WitnessCellRevoked`.
  - The cell's secret key material at the witness is its CA key and its App and Vault anchor keys. Step 1 destroys them in custody, so the revocation needs no secret of its own.
  - The test world revokes the erased cell at its witness after step 1, as it plays provisioning.
- **Approvals per erasure.** Each operator approves an erasure once, with a passkey, over the batch of its five job digests. The batch digest, the challenge, the approved frame version 3 and the agent's check are recorded in ADR-011 (record of lane m3/erase-prod). `erase_cell_steps` refuses before step 1 unless every job of the erasure carries the same two batch approvals over exactly those jobs. The two-operator rule is unchanged. The test world approves its one-job erasure the same way.
- **Sign keys in `fstp-keyd`.** A sign-key slot has the length and seal of a root slot. Its first byte is `0x80` or the class byte, then the 8 name bytes of the handle, where a root slot holds the chain and epoch. A keyd sign key handle is the class byte and those 8 name bytes. The slot holds a random key `K`. `K` seals the key's PKCS#8 document in its own file `sign-<class>-<name>.key` (header `"FKK1"`, version 1, class, name), as `K(e)` seals an epoch file. The structural file decoder has the fuzz target `sign_key_file_decode`, and the slot form is read by the fuzzed table body decoder.
  - Request kind `0x08` creates a sign key, or finds the live one, and answers its public key as a DER SubjectPublicKeyInfo (response kind `0x87`). The usage log records it as operation 8, `create-sign-key`. A destroyed key is never created again.
  - Interim, pending Daniel: only the console socket creates keys, and only cluster CA keys, since the install runs as root. No socket creates a cell CA key yet.
  - `sign` opens the key from its file for one signature. A destroy overwrites `K` in its slot in place and fsyncs, unlinks the file, fsyncs the directory and reads back, and answers the `"FKS1"` receipt with every step. A retried destroy answers the same receipt.
  - `fstp_control::install::create_cluster_ca_keys` is the install step. It names each local cluster CA key from its cluster id (`cluster_ca_key`). The install run itself stays unbuilt (B-06). `KeydCustody` implements `SignKeyCustody` through `destroy_sign_key`, so cell erasure destroys a keyd-held CA key in place.
- **Route table polling.** `fstp_control::routes::RoutePublisher` holds every cell's route and a version that rises with each change. It signs each version with the control-plane composite key under the context `fstp-route-table-v1`. Interim, pending Daniel, the bytes: `"FRT1"`, the version as `u64`, a route count, and per cell its id, application host and both tunnel endpoints, in ascending host order, then the signature. The decoder `fstp_edge::decode_signed_route_table` has the fuzz target `route_table_decode`. Lane L15 replaced these bytes by version 2 (`"FRT2"`, context `fstp-route-table-v2`), which carries a pin after each endpoint (ADR-009 "Pilot route feed").
  - Each edge polls over mutual TLS, one exchange per connection, with a 12-byte poll `"FRP1"` and the version it serves. `fstp_edge::RouteFeed` checks both signature halves (I-90), builds the table through the route table's own rules, and swaps it in only for a newer version (`LiveRoutes::apply`), so a replayed table never brings back a removed route.
  - `fstp_control::routes::RemoteEdges` implements `EdgeRoutes`. It publishes the version without the cell, then waits until every configured edge reports that version or a newer one. A wait that runs out fails the erasure with no confirmation.
  - Interim, pending Daniel: an edge is named by its client certificate's one subject CN, `edge_<32 hex digits>`, and the set of edges is configured. `fstp_edge::run` still refuses to start, since the edge listener configuration and credentials are not designed. The in-process `LiveRoutes` path stays for the test world.
- **Left: the cell's object storage prefix.** Decided below (night): option B. Not built, because it conflicts with two records. ADR-005 says "Old backups are deleted only by bucket lifecycle rules, never by client DELETE calls". ADR-012 says "No `DeleteObject` call exists" and "No listing call exists in M3". Design section 3.7 step 2 and `fstp_control::erase::CellObjects` delete the prefix `<cell>/`. The buckets also carry object lock (ADR-005, V14). On such a bucket a plain delete only adds a delete marker during retention. The keystore snapshots under `<cell>/keystore/` are sealed to the CellBackup chain, whose roots step 1 destroys, so I-81 holds without the delete. Open for Daniel. (A) Allow `ListObjectsV2` and `DeleteObject` on the `<cell>/` prefix for cell erasure only, with a fourth XML shape and its fuzz coverage. (B) Drop the prefix delete from step 2 and rely on key destruction and lifecycle rules. (C) Another reading. The S3 client of `fstp-backup` stays a W0 stub.
- **Left in the test world.** The world still runs no `fstp-pgagent`, no remote edge and no object store server for its cells, so its `erase-cell` step runs steps 1 and 4 and the witness revocation. `erase_cell_steps` over real agents and remote edges runs in the tests of `fstp-control`.

## Decided by Daniel, 2026-11-15 (night)

- **Object storage on cell erasure.** Option B. Step 2 does not delete the cell's object-storage prefix. Destroying the CellBackup roots in step 1 makes every backup unreadable (I-81), and bucket lifecycle rules remove the objects later. ADR-005 and ADR-012 stand: no client `DeleteObject` and no listing call. `CellObjects` leaves step 2. Built by lane m4/matrix-final: `erase_cell_steps` takes no object store, and the `ObjectsDeleted` step is gone.
- **Interim readings of lane m3/erase-prod accepted.** An edge is named by its client certificate's subject CN `edge_<32 hex digits>`, and the set of edges is configured. Only the `fstp-keyd` console socket creates sign keys, and only cluster CA keys. `erase_cell`, which runs steps 1 and 4 only, still accepts an approval of its single job.
- **Registries.** The I-90 sweep gains the break-glass staff assertion (`fstp_auth::breakglass::verify_staff_assertion`), and the M3 teeth registry gains the two I-17 unmask teeth tests of `fstp-api-testkit/src/harness_unmask.rs`.

## Decided by Daniel, 2026-11-20: keystore tables and the cell key file

Decided by Daniel on 2026-11-20 (production MCP design, `docs/handoff/production-mcp-design.md` section 2.1, decision D5). A restart of a production cell must keep every key, so the keystore leaves process memory.

| Topic | Decision |
| --- | --- |
| Keystore | The rows of the keystore image (`fstp_cell::tasks::erasure::snapshot`) move to `keystore.root`, `keystore.group_key`, `keystore.data_key` and `blob.text`. Signer rows, the chain state and the login email index get their own tables in migration `0011_keystore.sql`. They are written through `c_<cell>_keys` only |
| Load | `fstp_cell::process::start` loads the keystore from the tables when the ledger is not empty, and runs genesis only on an empty ledger |
| Cell key file | `cell-keys.sealed` holds the `Anchor` key, the ledger data key generations, the CredLookup key and the ticket key. It is sealed under a seal key wrapped by `fstp-keyd`, with the layout of the witness receipt key file. Its decoder `cell_key_file_decode` is fuzzed |

Tests, from section 3.5 of the design: `i80_keystore_rows_hold_no_root_material`, `i81_destroyed_epoch_stays_unreadable_after_restart`, `r_cr_01_keystore_rows_sealed_at_rest`, `adr004_keystore_round_trips_through_tables`, `i23_process_restart_reads_every_text`, `i79_login_email_lookup_survives_restart` and `i82_keystore_written_by_keys_role_only`.

## Built by lane L3 `prod/keystore-pg`, 2026-11-20

Each entry builds a row of the decision above. Readings marked "interim, pending Daniel" are this lane's own.

- **Tables.** Migration `0011_keystore.sql` adds `keystore.chain`, `keystore.text`, `keystore.signer`, `keystore.login_digest`, `keystore.login_text` and `keystore.erasure_request`, and the column `keystore.root.receipt_digest`. Each column has a class in `fstp_pgstore::CATALOGUE`. The role plan of `fstp-control` grants every `keystore` table to the keys role only (I-82).
- **Texts.** Interim, pending Daniel: the texts go to `keystore.text`, not `blob.text`. `blob.text` is the table of `fstp_pgstore::TextStore`, whose envelope holds a salt before the text (ADR-007). The app role inserts there, and the keys role holds SELECT and DELETE only. A text row and its data key row must commit in one transaction of one role, so both live in the keys role's schema.
- **Rows.** A root row is live, pending (created for a batch not yet committed, with no wrapped key) or destroyed, with the receipt digest. A group row holds the hybrid public key, the purpose and the secret sealed under `S(e)`. A signer row holds the current generation sealed under `S(e)`, and a replaced generation with its public key only.
- **Chain state.** Interim, pending Daniel: the planner's chain state is stored in the form `"FKC1"` of `fstp_keys::erasure::codec`, with the fuzz target `chain_state_decode`. It is sealed with AES-256-GCM under `S(e)` of its epoch, AAD `"fstp-chain-state-v1"`, cell, chain and epoch. The epoch stands in clear beside it, so the start knows which root to unwrap. It opens with the group secrets, and dies with its root (I-81).
- **Write-through.** `fstp_cell::tasks::erasure::tables`: the keystore marks each changed row, and a flush writes every marked row in one transaction through `fstp_pgstore::KeystoreTables` over `c_<cell>_keys`. The runner flushes before and after each erasure step and after each request it serves. So no reply claims a change that is not durable, and no step or custody call follows a step whose rows are not durable. A failed flush refuses the request, keeps the marks, and the next flush writes them. The start-up unwrap's request id is written before the call (ADR-004 "Reconciliation").
- **Load.** `fstp_cell::process::start_with` takes the `c_<cell>_keys` login in place of an in-memory keystore. It loads the rows. With no rows and an empty ledger it runs genesis, writes the keystore whole, and loads it back. No rows beside a ledger that is not empty is refused. The test world's restart passes no keystore any more.
- **Tests.** `fstp-pgstore/tests/keystore_tables.rs`, `fstp-control/tests/i82_keystore_role_plan.rs`, `fstp-cell/tests/keystore_tables.rs` (restart at every step and a failed write at every step of a batch) and `fstp-celltest/tests/keystore_restart_pg.rs` (a world restart over PostgreSQL).
- **Not built: the cell key file.** Section 3.6 of the design gives `keyfile.rs` and `cell_key_file_decode` to lane L4. Three points need a decision first. (1) Which custody root seals it: the App chain roots are destroyed at every erasure, so the file needs a root that no erasure destroys, as the witness has its own entry. (2) A ledger key generation may not be reused across starts (`fstp_pgstore::LedgerKey`), so each start draws a generation and rewrites the file. (3) `fstp-cell` holds no `zeroize` dependency, and ADR-001 A1 names the crates that may. Wiping the plain body needs either that record or a wiping type from `fstp-crypto`.
- **Open, for Daniel.**
  - A crash inside genesis, after its key records and before the keystore rows commit, leaves a ledger with no keystore. The start then refuses on every attempt, and an operator must reset the cell database.
  - A failed write after `create_root` can leave a root that no row names. The restart creates another. Reconciliation reports the orphan, and nothing destroys it yet.
  - Each flush that changes the chain state seals it once more under `S(e)` with a random nonce. No seal count bounds that per epoch yet (ADR-004 part 1 "Seal-count limit").
  - The migration set allows no gap. The file is `0011_keystore.sql` as the design fixes it, but its version is 9 on this lane alone. Merged after L1 it becomes 10, and L2's `0010_mcp.sql` then follows as 11.

## Built by lane L4 `prod/cell-run`, 2026-11-20: the cell key file

Daniel decided on 2026-11-20 the two points that lane L3 left open for the cell key file. Each is recorded here as "Decided by Daniel on 2026-11-20". Readings marked "interim, pending Daniel" are lane L4's own.

| Topic | Decision |
| --- | --- |
| Sealing root | The sealed cell key file is sealed by a dedicated custody cell root. It is created at genesis, and no erasure ever destroys it. Decided by Daniel on 2026-11-20 |
| Root entry | Decided by Daniel on 2026-11-21. The root lives in its own `fstp-keyd` entry, named by the configuration member `key_file_keyd_socket`, as the witness receipt key has its own entry. The start refuses a configuration whose two keyd sockets are the same path. The keystore and its erasures never reach that entry |
| Root label | Interim, pending Daniel. The root is labelled cell, chain CellBackup, epoch 1. The `fstp-keyd` cell role reaches that chain, and ADR-004 part 2 says erasure never rotates it. So a root shared by mistake with the cell's own entry is still never destroyed by an erasure. A yearly re-wrap of CellBackup must re-wrap the key file too |
| Ledger key generations | A generation is never reused across starts. Each start, `first-admin` included, draws a new generation with the next index and a fresh data key id, keeps every older one for opening, and rewrites the key file before the first seal. Decided by Daniel on 2026-11-20 (L3's open question 3) |
| Rewrite | The file is written to a temporary file in the same directory, synced, and renamed over the old one. A crash leaves the old file or the new one, never a mix. The new body is sealed again under the same `S(e)` with a fresh random nonce |
| Wiping | `zeroize` wipes the plain body of the key file in `fstp-cell` (ADR-001 record of 2026-11-20). Decided by Daniel on 2026-11-20 |

```text
file    = magic "fstp-cell-keys-v1" (17) || cell (16) || be64(epoch)
          || be16(len) || custody handle || be16(len) || wrapped S(e)
          || nonce (12) || be32(len) || sealed
wrap    = custody wrap of S(e) under the dedicated root,
          AAD = magic || cell || "cellbackup" || be64(epoch)
sealed  = AES-256-GCM under S(e) of body,
          AAD = magic || cell || "cellbackup" || be64(epoch)
body    = anchor composite secret (64) || CredLookup key (32)
          || ticket Ed25519 seed (32) || be16(n)
          || n x (be32(key_ix) || data key id (16) || ledger key (32))
```

- Interim, pending Daniel: the layout. It follows the witness receipt key file (`fstp_witness::config`). The handle and the wrapped key are 1 to 4096 bytes each. The body holds 1 to 4096 generations, in increasing `key_ix`, with distinct indexes and data key ids. The last one is the current generation.
- The decoder accepts exactly this form and re-encodes it byte for byte. Its fuzz target `cell_key_file_decode` exists from the first commit.
- The file never holds an open key (I-80, `i80_cell_key_file_holds_no_open_key`). Errors name a rule and never quote file bytes (R-NF-02).
- Interim, pending Daniel: the ticket key now always exists, so the vault ticket routes no longer answer 501 on a production cell.

## Written by lane L8 `prod/vault-run`, 2026-11-21: the vault keystore

Written by lane L8 before its code (gap G12 of `docs/handoff/production-mcp-design.md`). Every row is interim, pending Daniel. The vault keystore gives `fstp_vault::run` its sealing key, its query digest key and the Vault chain's anchor key. It persists across restarts, so the vault no longer depends on keys handed in by a test world.

| Topic | Reading |
| --- | --- |
| Where | The rows live in the vault database `v_<cell>`, in the `keystore` tables that vault migration 3 created in M3: `keystore.root`, `keystore.group_key` and `keystore.data_key`. No new migration. They are read and written through `v_<cell>_keys` only, which the `fstp-control` role plan grants every `keystore` table to (I-82) |
| Custody | The root lives in the vault's own `fstp-keyd` entry, reached through a socket of the `vault` client role. That role reaches the Vault chain only (`fstp_keyd::access`). The cell's entries never hold it (R-NG-01, I-83) |
| Root | One root, labelled cell, chain Vault, epoch 1. A fresh seal key `S(1)` is wrapped under it with the AAD `"fstp-vault-seal-key-v1" \|\| cell \|\| chain code \|\| be64(epoch)`. The row holds the backend code, the custody handle and the wrapped `S(1)` only (I-80) |
| Groups | Three group rows, generation 1, each secret sealed under `S(1)` with AES-256-GCM as `nonce \|\| ciphertext`. The AAD is `"fstp-vault-group-v1" \|\| cell \|\| purpose code \|\| group \|\| be32(generation) \|\| be64(epoch)`, as the test harness `fstp_celltest::vault_keys` seals its groups. `Anchor` holds the composite public key and the composite secret of the Vault chain's anchor key. `Fact` and `Match` each hold a hybrid KEM public key and its secret |
| Data key | One `Fact` data key, sealed to the `Fact` group key in the FSK1 form (`fstp_keys::envelope::seal_key`). Its id is the `dek` of every sealed vault value (`fstp_vault::service::AeadSealer`) |
| Query digest key | `HKDF-SHA-256(Match secret, "fstp-vault-query-digest-v1")`. It keys the digests of `vault.query_log`. The identity match key of design section 6.4 will take its own label from the same group |
| Genesis | `fstp-vault init-keys <dir>` refuses a keystore that holds any root row. It runs the I-83 start check over the vault login first. It creates the root through custody, then writes every row in one transaction. It writes `anchor.pub`, the Vault chain anchor public key in lowercase hex, which the witness registers for the Vault chain |
| Load | Each start reads the rows, unwraps `S(1)` through custody and opens the groups and the data key. A keystore without a root row, or with rows that do not open, is refused. The start never runs genesis |
| Errors | An error names a rule and never quotes row bytes (R-NF-02) |
| Not built | Rotation and erasure on the Vault chain (design section 3.5): the vault does not yet rotate `S(e)` or the `Match` group when an identity is erased. The test world still plays that keystore in `fstp_celltest::vault_keys`. A crash after `create_root` and before the rows commit leaves a root that no row names, and the next `init-keys` creates another |

Tests: `i80_vault_keystore_rows_hold_no_open_key`, `adr004_vault_keystore_rows_round_trip`, `adr004_vault_keystore_survives_a_restart` (over PostgreSQL), `r_nf_02_vault_keystore_errors_never_quote_bytes`, and the end-to-end test `g12_vault_binary_answers_the_cell_binary`.

## Written by lane L11 `prod/vault-erase`, 2026-11-21: erasure on the Vault chain

Written by lane L11 before its code. It builds the row "Not built" of lane L8 above: design section 3.5, steps 1 to 7, on the Vault chain, with the keyed digest rule G24 for the `Match` key. Every row is interim, pending Daniel, unless it says otherwise.

| Topic | Reading |
| --- | --- |
| Planner | `fstp_keys::erasure` unchanged. The vault's runner is `fstp_vault::erasure`, the shell of `plan_erasure`, `next` and `apply`, as `fstp_cell::tasks::erasure` is on the App chain |
| Chain state | The planner's state in the `"FKC1"` form, sealed with AES-256-GCM under `S(e)` of the current epoch, as `nonce 12 \|\| ciphertext \|\| tag 16`. AAD `"fstp-vault-chain-state-v1" \|\| cell \|\| chain code \|\| be64(epoch)`. It is stored in `keystore.erasure_intent.plan`, one row for the Vault chain with a random `id`. `phase` holds the planner phase: 0 idle, 1 planned, 2 resealed, 3 committed, 4 snapshot verified, 5 destroyed |
| Current epoch | The highest epoch whose `keystore.root` row is live. Between the commit and the destroy two rows are live. The chain state is always sealed under the current epoch's seal key, so the start knows which root to unwrap |
| Root states | `keystore.root.state` 1 live, 2 destroyed, 3 pending, as the App chain keeps them (`fstp_pgstore::keystore`). A pending root is written at once after `create_root`, with an empty wrapped key, so a restart before the commit reuses it. A destroyed root keeps `destroyed_at` and the custody receipt in `receipt` |
| A keystore from genesis | A keystore that lane L8's `init-keys` wrote has no intent row. Its chain state is built from its rows at load: epoch 1, the `Anchor` and `Fact` groups, the `Fact` data key, and the `Match` digest group with no subject. It is written with the first change |
| Identity tuples | New migration 8 `identity_tuple` of the vault set adds `keystore.identity_tuple (identity_id, group_id, envelope)`. Each identity's canonical attribute tuple is sealed in the `"FSB1"` form under its own data key. That key's id is the identity id. It sits in an `Attribute` group of at most 256 keys, sealed to the group key in the `"FSK1"` form. The blob context is cell, Vault, `Attribute`, group, generation 0 and the identity id, so a re-seal of the data key to a later generation still opens it. The tuple and its key live in the keys role's schema, so they commit in one transaction, as lane L3 placed `keystore.text` |
| Match key | The identity match key is `HMAC-SHA-256(M, tuple)` with `M = HKDF-SHA-256(Match secret, "fstp-keyed-digest-v1" \|\| Match code)`, the derivation of the App chain's `Lookup` key and of the test world. Every live tuple's data key is a subject of the `Match` digest group. The query digest key stays lane L8's: `HKDF-SHA-256(Match secret, "fstp-vault-query-digest-v1")`. A new `Match` generation therefore gives a new query digest key too |
| Registering an identity | `fstp_vault::erasure::Runner::register_identity`. A known match key gives its identity, and stores its tuple if none is stored. A new one is journaled as `IdentityAssigned` through the vault login first, then its tuple, data key and chain state commit through the keys login. A crash between the two leaves an identity without a tuple, which the next registration of the same tuple repairs |
| Erasing an identity | Step 1 requests the identity's tuple data key in the planner, and writes the intent row. The tuple is refused for open from then on. The batch affects the identity's `Attribute` group and the `Match` group (G24). An identity with no stored tuple is refused, since no batch can make its match key unrecoverable |
| Steps 2 and 3 | New key pairs for the affected groups. Each surviving tuple key is opened under the old generation and sealed to the new one. `R(e+1)` is created in the vault's custody entry and written as pending, `S(e+1)` is drawn and wrapped, and every live group secret is sealed under `S(e+1)` |
| Step 4 | One transaction of the keys login: the new root live, every group row re-sealed or replaced, the old generations of affected groups and the erased keys and tuples deleted, and the chain state at `Committed`. Then the live identities move to their match keys under the new `Match` key through `Vault::rekey_identities`, and each erased identity gets 32 random bytes, in one vault journal. The rekey repeats after a restart until the snapshot step is durable. An unchanged key is now a no-op in `rekey_identities` |
| Step 5 | The snapshot is the committed keystore rows, read back from the database over the keys login, as the vault cluster's base backup and WAL archive hold them (ADR-012, record of lane L10). The check unwraps `S(e+1)` from those rows through custody and opens every live group secret, every data key and every tuple. No separate container is written, since ADR-012 leaves the Vault chain's snapshot key open (option A or B) |
| Step 6 | `R(e)` is destroyed in custody. The root row is marked destroyed with the receipt. `S(e)` and the old group secrets are dropped, which wipes them |
| Step 7 | One vault journal: `KeyEpochDestroyed { epoch, receipt digest }` and one `IdentityErased` per erased identity. The journal is one kind 1 row of the Vault chain, whose body binds a digest of each record, as a fact batch binds its rows. A crash after the journal and before the chain state can record it twice. It is never lost |
| Entry point | `fstp-vault erase-identity <account id>`. The command resolves the account's identity, runs the batch to its end and prints the destroyed epoch. It takes a PostgreSQL advisory lock on its keys connection. The serving vault holds the same lock for its lifetime, so the command refuses while the vault runs. Each start completes a stored batch before it serves |
| Not built | `RecordKeyOp` events (kind 2) before each custody call of the Vault chain, and their reconciliation. A route that registers identities with their tuples: `register_identity` is a library call, and the recorder route of ADR-008 is still a seam. Erasure of documents and of facts sealed under the `Fact` data key. A route from the cell for an identity erasure. Rotation of the `Fact` and `Anchor` keys |

Tests: `i81_vault_erased_identity_key_unreadable_from_backup_rows_and_live_store`, `g24_vault_no_live_key_recomputes_an_erased_match_digest`, `i81_vault_erasure_resumes_after_crash_at_every_step`, `r_ky_02_vault_live_identities_readable_after_rotation_and_restart` (over PostgreSQL, in `crates/fstp-vault/tests/erasure_pg.rs`), with `i81_vault_erasure_refuses_an_identity_without_a_tuple`. In `crates/fstp-vault`: `r_ky_02_vault_erase_identity_takes_one_account_id` and, over PostgreSQL, `r_ky_02_vault_keystore_lock_refuses_a_second_process`. The end-to-end run of `erase-identity` through the binary, with a witness, is not built.

## Written by lane L13 `prod/identity-facts`, 2026-11-21: identity fact keys and registration

Written by lane L13 before its code, on Daniel's decision of 2026-11-21 to build it before any real applicant data. It closes two rows that lane L11 left "Not built": facts sealed under the shared `Fact` data key, and a route that registers identities. Every row is interim, pending Daniel, unless it says otherwise. Daniel accepted on 2026-11-21 that identity facts reach the vault through the cell.

| Topic | Reading |
| --- | --- |
| Key hierarchy | Each registered identity `X` has one level 3 data key, its tuple key `T(X)` of lane L11. It sits in an `Attribute` group, sealed to the group key in the `"FSK1"` form, with data key id `X`. The identity's fact key is derived from it: `F(X) = HKDF-SHA-256(ikm T(X), empty salt, info "fstp-vault-identity-fact-v1" \|\| cell \|\| X)`, 32 bytes |
| Why derived | One data key per identity record set: its tuple and its facts. The L11 batch that erases `X` already destroys `T(X)`, so it destroys `F(X)` with no change to the planner. `F(X)` is never stored, never logged and lives in process memory only, in a wiping key type |
| Primitives | HKDF-SHA-256 and AES-256-GCM from aws-lc-rs through `fstp-crypto` (ADR-001). No custody call is added and no primitive is written in-house. The root, wrap and destroy steps stay those of the Vault chain (I-80) |
| Fact seal | An identity fact body is sealed with AES-256-GCM under `F(X)`, with a random 12-byte nonce, as `nonce \|\| ciphertext \|\| tag`. AAD `"vault.identity_fact.body\|" \|\| be64(epoch) \|\| X`. The row's `vault.fact.dek` holds `X`. Every other value keeps the shared `Fact` data key, and its row names that key's id |
| Identity fact kinds | `BankDetails` (14) and `HardshipEvidence` (17). They hold holder names, IBANs and free text. Once erased they fail closed: a grant with no bank details is never releasable (I-33), and a hardship with no evidence is never verified (R-PR-04) |
| Kinds left shared | Kinds 1 to 13 and the verifications and disputes (15, 16, 18). Kinds 1 to 13 feed the I-03 and I-54 conflict checks and the eligibility queries. Dropping a verification or a relationship at an erasure could turn a conflict into "no conflict". Kinds 15, 16 and 18 hold ids, methods and checks only. Open for Daniel: whether some of them move to `F(X)`, and how a dropped conflict fact keeps failing closed |
| Registration table | Vault migration 9 `identity_account` adds `vault.identity_account (account_id, identity_id, registered_at)`. It binds an account to its identity. `identity_id` is NULL once that identity is erased. The vault login writes it with SELECT, INSERT and UPDATE, as every `vault` table |
| Registration route | `POST /v1/identity` on the internal listener, mutual TLS with the `cell-app` certificate only, as the other internal routes. The body is the `fstp-vault-proto` request `{"account":"<id>","tuple":"<hex>","type":"register_identity"}`, with a tuple of 1 to 4096 bytes. The reply is `{"type":"acked"}` and names no identity. The decoder keeps the fuzz target `vault_request_decode` |
| Registration steps | Refused while an erasure batch runs. The match key under the current `Match` key resolves the identity, or a new one is journaled (`IdentityAssigned`). The tuple and `T(X)` are stored through the keys login if they are not. Then the binding is journaled (`IdentityRegistered`) and `F(X)` joins the sealer. A crash between steps leaves an identity with no binding, which the retry completes |
| Idempotence | The same account and tuple again change no row. Another account with the same tuple binds to the same identity. An account bound to `X` with a tuple that resolves to another identity is refused as malformed, so no account changes person by registration |
| Intake | `POST /w` refuses a write of kind 14 or 17 for an account with no live binding, with 403 (`OriginRefusal::Unregistered`), before the ticket is used. A fact of a bound account is sealed under its identity's `F(X)` whatever path took it. `Vault::take_fact` stays the library seam of the test world and refuses nothing more |
| Verification | `Vault::verification_fact` refuses a verification whose resolved identity differs from the account's registered identity |
| Erasure | Steps 1 to 7 of lane L11 are unchanged. `T(X)` is in the batch, so every copy of it is sealed to an `Attribute` generation whose secret dies with `R(e)`. Step 7's `IdentityErased` sets `identity_id` NULL on `X`'s bindings, so a later fact of those accounts is refused until they register again, as a new identity (G24) |
| Load | The vault opens every live tuple key at start and derives each `F(X)`. A fact row that names an identity with no live key is erased. It is replayed as an erased write (`fstp_vault_core::write_erased`): it keeps its epoch, touches no account and adds no fact. A binding to an identity with no live key is dropped at load |
| Existing facts | Re-sealing old facts is impossible: an old bank or hardship fact names an account with no tuple, so no `F(X)` exists to seal it to. So `fstp-vault serve` refuses to start while any fact of kind 14 or 17 is sealed under the shared `Fact` data key. This is the safer choice: no such fact can outlive an erasure. No real applicant data is held yet. A pilot vault that holds synthetic ones is recreated with `init-keys` on a fresh database |
| Snapshots and backups | `F(X)` is never stored. A keystore snapshot, a base backup or a WAL segment holds `T(X)` sealed to its `Attribute` generation and the fact bodies sealed under `F(X)`. After step 6 no live root opens that generation, so no restore opens the facts (I-81, ADR-012 restore rule). A restore that brings back an old fact row or binding of an erased identity finds no key and treats it as erased. ADR-012 option A or B for the Vault chain snapshot key does not change this |
| Entry point | `fstp-vault erase-identity <account id>` resolves the account through `vault.identity_account` first, then through `vault.account` |
| Cell side | `fstp_cell::vault::HttpVaultClient::register_identity` posts the request. No cell command calls it yet: the vault intake of ADR-026 is still refused as `OracleDown`, and the attribute tuple of each method is the open Q17 reading. Open for Daniel: which cell flow sends it, and when |
| Not built | A seal count for `F(X)` (ADR-004 part 1 "Seal-count limit"). Erasure of the facts under the shared `Fact` key. An erasure route from the cell |

Tests, written before the code: `i81_erased_identity_facts_unreadable_from_live_store_snapshot_and_backup`, `r_ky_02_live_identity_facts_open_after_erasure_and_restart`, `adr004_identity_registration_is_idempotent` and `i81_start_refuses_shared_key_identity_facts` (over PostgreSQL, in `crates/fstp-vault/tests/identity_facts_pg.rs`). `i81_unregistered_identity_facts_refused_at_intake`, `i81_identity_facts_sealed_for_the_bound_identity`, `adr004_identity_binding_is_idempotent_and_never_moves_an_account` and `i81_erased_identity_unbinds_its_accounts` (`crates/fstp-vault/tests/identity_facts.rs`) and the property `i81_prop_erased_write_keeps_epochs_and_drops_its_fact` (`crates/fstp-vault-core/tests/i81_erased_write.rs`) run without a database. The route itself runs over mutual TLS with a witness in `adr004_vault_registers_an_identity_on_the_internal_route` (`crates/fstp-vault/tests/vault_chain.rs`). Built by lane L13 on 2026-11-21 as written above.

## Decided by Daniel, 2026-11-21: lane L13's open points

- **Identity fact kinds.** Only kinds 14 and 17 are sealed under `F(X)` and refused for an unregistered account. Kinds 1 to 13, 15, 16 and 18 stay under the shared `Fact` key. Decided by Daniel on 2026-11-21.
- **Old facts.** `fstp-vault serve` refuses to start while an identity fact is sealed under the shared `Fact` key, and such a pilot vault is recreated. Decided by Daniel on 2026-11-21.
- **Left open, recorded.** `Vault::take_fact` stays the library seam of the test world. A seal count for `F(X)`, erasure of the facts under the shared `Fact` key and an erasure route from the cell stay not built.
- **Registration at verification.** The cell registers the identity at identity verification: when the vault accepts an applicant's identity verification, the cell calls `register_identity` with the account and the attribute tuple. Retries are idempotent, and a failed registration never leaves a verification half done without a retry path. Lane L13b's reading is below.
- **Registrar reconnect.** When the registrar's keys connection drops, the vault takes the keystore lock again on a new connection. If another process holds it, the vault stops serving and says so. Lane L13b's reading is below.

## Written by lane L13b `prod/identity-registration`, 2026-11-21: registration at verification and the registrar's lock

Written by lane L13b before its code. Every row is interim, pending Daniel, unless it says otherwise.

### The attribute tuple per method (Q17)

| Method | Tuple |
| --- | --- |
| Every method | `"fstp-identity-tuple-v2"` (the label was `"fstp-identity-tuple-v1"` until lane L21, see row "Normalisation"), then each field as `be16(len) \|\| UTF-8 bytes`, in this order: family names, given names, date of birth as `YYYY-MM-DD`, and the ISO 3166-1 alpha-3 code of the state that issued the identity evidence. The method is not part of the tuple, so one person verified by two methods has one identity |
| `manual` (R-ID-02) | The four fields as printed on the checked document, entered by the recorder. No document number and no image enter the tuple, as R-ID-02 forbids storing them |
| EUDI (M4, not built) | The same four fields from the person identification data. Which attribute of the presentation fills each field is open |
| Normalisation | Decided by Daniel on 2026-11-21: NFKC + case fold. Each name is `fstp_unorm::name_key`: the compatibility caseless key `toNFKC_Casefold(NFD(s))`, then leading and trailing white space removed and inner runs one space (ADR-029). Case, canonical equivalence, compatibility variants (ligatures, full-width letters) and default ignorables (soft hyphen, zero width joiner) no longer separate two spellings of one name. Diacritics still count: `Muller` and `Müller` stay two names. A name that folds to nothing is refused. The label is `fstp-identity-tuple-v2` since lane L21. A vault that stores a tuple under the label `fstp-identity-tuple-v1` refuses to start, as for shared-key identity facts, since its match keys would give the same person a second identity. Such a pilot vault is recreated. The `TODO(legal)` on the data minimisation basis of the four fields stays |

### Where the tuple travels: a conflict, stopped for Daniel

Daniel's decision has the cell call `register_identity` with the attribute tuple. Two higher sources say the application never receives identity attributes:

- `SPEC/03-architecture/overview.md`, "Operations other than queries" (decided 2026-10-28): "The application writes only facts that carry no identity attributes", and the browser sends attributes to the vault origin directly, "So the application never receives them (I-17, NOTE 6)".
- ADR-008, "Where the outcome travels": the recorder enters the verification outcome on the vault origin under a `VerificationRecorded` write ticket, and "No identity attribute enters the application".

No path accepts a verification in production today either. The cell issues the `VerificationRecorded` ticket (`POST /api/v1/verifications`), but the vault origin decodes no kind 6 write, and the cell's vault intake (ADR-026) is refused as `OracleDown`. Lane L13b therefore builds no transport of the tuple. The options for Daniel:

- (A) The cell carries the tuple as a `VaultBound` value, never read, stored or logged, from a recorder route of the cell to `POST /v1/identity`. The overview and ADR-008 change to say so.
- (B) The recorder enters the tuple with the outcome on the vault origin under the ticket the cell already issues. The vault registers the identity as it accepts the verification, and the cell never holds the tuple. Nothing in the SPEC changes. Proposed by lane L13b.

### What lane L13b builds for either option

| Topic | Reading |
| --- | --- |
| Verification with registration | `fstp_vault::erasure::Runner::record_verification(verifier, account, record, tuple)`. It refuses a recorder who verifies their own account or an account of their own identity (ADR-008 rules 1 and 2) before anything is written. It then registers the account (`register_account`), and only then writes the `VerificationRecorded` fact, whose identity is the registered one. A verification is never recorded for an unregistered account |
| Retry | Each step is idempotent. A failure after the registration leaves a registered account with no verification, and the same call again writes the verification. A call for an account whose newest facts already show it verified as that identity writes nothing. So a retry always completes, and never writes twice |
| Bank details after verification | A verified account is registered, so its bank details and hardship evidence are taken and sealed under `F(X)` |

### The registrar's keystore lock

| Topic | Reading |
| --- | --- |
| Watch | The serving vault probes the registrar's keys connection every 5 seconds with `SELECT 1`, under the registrar's lock. The PostgreSQL advisory lock lives exactly as long as that session |
| Reconnect | On a failed probe, or a registration whose keys connection failed, the vault opens a new keys connection and calls `pg_try_advisory_lock` on it. If it gets the lock, it reads the keystore rows again. Rows equal to the ones it holds keep it serving on the new connection. A database that cannot be reached is tried again at the next probe, and registrations answer 503 meanwhile |
| Fail closed | If another process holds the lock, or the rows changed while the lock was free, the vault stops serving. Every request on both listeners answers 503, the log line `{"event":"serving_stopped","rule":"I-81"}` is written, and `fstp-vault` drains and exits with status 1. Its in-memory keys may then be stale against an erasure that ran meanwhile, which only a restart resolves |
| Window | Between the drop and the next probe, another process may take the lock. An erasure that runs in that window ends the serving vault at its next probe. A fact the vault sealed meanwhile for the erased identity is sealed under a key that the erasure destroyed, so it stays unreadable (I-81) |

Tests, written before the code: `r_id_02_verification_registers_before_it_records_and_retries` and `r_id_02_recorder_never_registers_their_own_identity` (over PostgreSQL, `crates/fstp-vault/tests/identity_facts_pg.rs`); `i81_vault_retakes_the_keystore_lock_after_its_connection_drops` and `i81_vault_stops_serving_when_another_process_takes_the_lock` (`crates/fstp-vault/tests/vault_chain.rs`); `r_nf_02_serving_stopped_is_one_json_line` (`crates/fstp-obs`).

## Decided by Daniel, 2026-11-21: lane L13b's open points

- **Where the tuple travels.** Option B. The recorder enters the identity attributes with the outcome on the vault origin, under the `VerificationRecorded` ticket the cell issues (`POST /api/v1/verifications`). The vault registers the identity as it accepts the verification, through `Runner::record_verification`. The cell never sees the attributes (I-17). Decided by Daniel on 2026-11-21. Option A is withdrawn, and the overview and ADR-008 stand.
- **Name normalisation of the tuple.** Unicode NFC plus case folding, with no new crate. The four fields stay, and the `TODO(legal)` on data minimisation stays. Decided by Daniel on 2026-11-21. Lane L13b's finding on the tables it needs is below.
- **Watch interval.** The registrar's keys connection is probed every 5 seconds. Decided by Daniel on 2026-11-21.

## Written by lane L13b, 2026-11-21: the recorder route on the vault origin

Written before the code. Every row is interim, pending Daniel, unless it says otherwise.

| Topic | Reading |
| --- | --- |
| Cell ticket | `POST /api/v1/verifications` takes `{command_id, proposal}` and runs the new command `IssueVerificationTicket { proposal }`. The cell issues a `write:verification_recorded` ticket naming the proposal, held by the recorder, only when: the recorder is a tenant admin (ADR-008 "Recorder in M3"); the proposal is in NEGOTIATION or later (the strict release window of ADR-008); the recorder holds no Judging binding in any state (the I-17 guard of ADR-008); the recorder holds no binding on the proposal (rule 1); the vault answers that the recorder is verified, and that the recorder shares no identity with any account bound to the proposal (rule 2, and ADR-008's interim refusal of an unverified recorder). The ticket record is `TicketIssued` with kind 6, as for every write ticket |
| Origin body | `POST /w` with a kind 6 ticket takes the body `{"account":"<id>","checks":[...],"document_type":"...","identity":{"birth_date":"YYYY-MM-DD","family_names":"...","given_names":"...","issuing_state":"AAA"},"method":"manual"}` in canonical JSON. The labels are those of R-ID-02 in `fstp_vault_core::fact`. Each name is 1 to 200 characters with no control character. The date is a calendar date from 1900-01-01. The state is three capital letters. The body limit of the kind rises from 1 KiB to 4 KiB, since a name may take four bytes per character. The decoder `fstp_vault::codec::decode_verification_write` has the fuzz target `verification_write_decode` from its first commit |
| Origin checks | The ticket checks of every `/w` write come first: signature, cell, route, window, lifetime and single use. The ticket must be of kind `verification_recorded` and name a proposal. The vault's own negotiation fact of that proposal must list the body's account, as a release needs (ADR-009, design section 6.5 "Second guard"). The account must not be the ticket's holder (rule 1). `Runner::record_verification` then refuses a recorder of the subject's identity (rule 2), registers the account, and records the fact with the vault's time and the ticket's holder as verifier |
| Ticket use | The ticket is marked used only after the verification is recorded. A failure before leaves it unused, so the recorder retries with the same link, and the retry completes without writing twice. A ticket used once is refused after |
| Reply | 204, as every write with no reference. The reply names no identity |
| Sans-IO path | `Vault::origin` has no keystore, so it answers a kind 6 write 503. The serving vault routes it to its registrar |
| Page | The write page of the vault origin shows a form for `write:verification_recorded`: the account id of the person checked, method, document type, checks, and the four identity fields. It posts to `/w` as the other forms do. The cell never sees the entries. The ticket names the proposal but not the person, so the recorder enters the account id. Open for Daniel: whether the ticket should name the person |
| Tuple | `"fstp-identity-tuple-v1"`, then each field as `be16(len) \|\| UTF-8`, in this order: family names, given names, date of birth, issuing state. Names are trimmed and inner runs of white space become one space. NFC and case folding are decided, but not built: see the next table. Superseded by lane L21: label `fstp-identity-tuple-v2`, names through `fstp_unorm::name_key` (row "Normalisation" above) |
| Static page | The shipped vault does not serve the static write page yet (ADR-009, third route group). Only the test world serves `web/dist/vault`. So a recorder on a pilot vault cannot open the form until the vault serves its pages. Open for Daniel |
| Not on real binaries | No end-to-end test runs on the real binaries. The cell issues the ticket only to a verified recorder, and no account is verified in production before the operator path of ADR-008, which waits on the ML-DSA-65 pull request. The g12 harness cannot seed a verification. The flow is tested through the cell's command decision with the vault's ground truth, and through the vault over PostgreSQL |

### NFC and case folding: what an in-house normaliser needs

No workspace code applies NFC or case folding. `fstp_api_core::display_name::normalised` trims, collapses and calls `to_lowercase`, and says so. `fstp_import::text` applies no normalisation form either. So the decided normalisation is not built, and lane L13b stopped before writing one. What it needs, from the Unicode Character Database of one pinned Unicode version, as approximate sizes for Unicode 15.1:

| Part | Data |
| --- | --- |
| Canonical decomposition | About 2,060 code points with a canonical mapping of one or two code points (`UnicodeData.txt` field 5 without a `<tag>`). Hangul syllables are computed and need no table |
| Canonical combining class | About 920 code points with a non-zero class, in about 380 ranges |
| Composition | About 940 primary composite pairs, and about 1,120 code points with `Full_Composition_Exclusion` (`DerivedNormalizationProps.txt`) |
| Quick check | `NFC_QC` No and Maybe, about 1,250 code points, optional, for speed only |
| Case folding | About 1,450 simple (`C`) and about 105 full (`F`) mappings of `CaseFolding.txt`. Full folding can lengthen a string, as `ß` to `ss` |
| Conformance | `NormalizationTest.txt`, about 19,000 cases and 2.5 MB, as a test fixture only |

In compact Rust tables that is roughly 30 to 40 KB of static data, generated from the UCD files by an in-house Rust generator, since no Python may be used. The UCD files are under the Unicode licence, and adding them or tables derived from them needs Daniel's review. The canonical caseless form would be `NFC(casefold(NFD(x)))`, which needs decomposition, composition and folding together. Open for Daniel: approve that work as its own lane. Until then the tuple uses the trimmed, collapsed form above. When the normaliser lands, the tuple's label changes, the stored tuples are recomputed and the match keys rekeyed, and pilot vaults are recreated.

Tests, written before the code: `adr008_verification_ticket_rules`, `adr008_verification_ticket_issued_in_negotiation` and `adr008_second_admin_issued_once_verified` (`crates/fstp-celltest/tests/adr008_verification_ticket.rs`); `adr008_vault_verification_body_spelling` and `adr008_vault_verification_field_bounds` (`web/test/vault_verification.test.ts`); `adr008_recorder_verification_registers_the_identity`, `adr008_recorder_route_refuses_without_writing` and `adr008_recorder_retry_completes_and_replay_is_refused` (over PostgreSQL, `crates/fstp-vault/tests/identity_facts_pg.rs`); `adr008_verification_write_body_decodes_and_refuses` (`crates/fstp-vault/tests/codecs.rs`).

## Decided by Daniel, 2026-11-21: the first admins and the person in the ticket

- The technical admin verifies the first admins on the host, with the operator as verifier of record (ADR-008, same date). Decided by Daniel on 2026-11-21.
- The verification ticket names the person, and the recorder types only that person's identity details. Decided by Daniel on 2026-11-21.
- The shipped vault serves the static write and release pages. Decided by Daniel on 2026-11-21.
- The full NFC plus case folding normaliser is its own lane. The tuple keeps a seam for it. Decided by Daniel on 2026-11-21.

### Lane L13b's readings

Every row is interim, pending Daniel, unless it says otherwise.

| Topic | Reading |
| --- | --- |
| Host command | `fstp-vault verify-first-admin <account> <identity file>`. It runs with the vault stopped, as `erase-identity` does: it takes the keystore lock, so it refuses while the vault serves, and it needs the configuration, the credentials directory and the vault's `fstp-keyd` entry, which only root and the vault's OS user can read. It asks nothing and prints nothing. Exit status 0 means the verification is recorded, or was recorded before for the same person. Status 2 means a refused argument or file. Status 1 means any other failure |
| Identity file | One JSON object with the members `checks`, `document_type`, `identity` and `method` of the recorder's body (below). Any JSON spelling is taken, since a person writes it by hand. At most 4 KiB. No document number |
| Verifier of record | The operator, as the reserved account id `340282366920938463463374607431768211455` (`u128::MAX`), which no cell assigns. Lead reading, 2026-11-21 |
| Limit | The command records operator verifications for at most two accounts per vault, the first admins. A repeat for an account it verified before is idempotent and does not count again. A third account is refused with status 1. The vault does not know the tenant admin roles, so it counts instead. Verified admins record everyone else on the web. Two first admins per vault, one for each of the two operators: lead reading, 2026-11-21 |
| Cell side | The verification ends at the vault as a provisional epoch. The cell takes it at its next vault exchange after the vault starts again, as for every vault write (NOTE 4) |
| Ticket | `IssueVerificationTicket { account, proposal }` names the person and, for an applicant, the proposal. The record is `VerificationTicketIssued { id, holder, subject, proposal }`. The cell issues it to a verified tenant admin with no Judging binding, who is not the person and shares no identity with the person, and, for a proposal, holds no binding on it and shares no identity with its accounts. With a proposal, the proposal is in NEGOTIATION or later and the person holds a binding on it. Without one, the person holds no Receiving binding at all, so an applicant is verified only in NEGOTIATION (R-NG-01). The claims carry the person as the scope `person:<id>` |
| Vault checks | The person comes from the ticket's scope, never from the body. The body is `{checks, document_type, identity, method}`. With a proposal, the vault's negotiation fact must list the person. The person must not be the holder |
| Staff app | The member page of the tenant admin (`/app/admin/members`) shows "Record verification" next to each member, and, in a section of its own, next to each person of a proposal in NEGOTIATION or later, whose ticket names that proposal. That list comes from the cell route `GET /api/v1/verification-people`, `{people: [{account, proposal, role}]}`: ids and roles only (I-17), for a tenant admin with no Judging binding, never their own account. No existing staff proposal page shows a tenant admin the team's accounts, so the list lives on the member page. The button asks the cell for the ticket and opens the vault form in the same tab |
| Static pages | The vault configuration takes an optional `assets_dir`. It holds `vault/` (the compiled vault modules and `shell.html`) and `auth/` (`dom.js`, `encoding.js`, `i18n.js`, `tokens.css` and `auth.css`). The vault serves `GET /w`, `GET /r`, `/assets/vault/<name>` and `/assets/auth/<name>` under the loader policy of ADR-009. Without the member it serves no page, as before |
| Normaliser seam | `fstp_vault::codec::tuple_name` is the one function the NFC plus case folding lane replaces. The tuple label changes with it |

## Written by lane L16 `prod/backup-custody`, 2026-11-21: off-host sealed copy of a `fstp-keyd` volume

Written by lane L16 before its code. Decided by Daniel on 2026-11-21: on the single-host pilot (ADR-026, D1), the `fstp-keyd` state gets an off-host sealed copy, made by an operator command, with an import onto a fresh host and a runbook. A destroyed root epoch must not come back from an old copy. A second custodian holds its own custody of the ClusterBackup chain (ADR-012 record of lane L16). Every reading below is interim, pending Daniel, unless it says otherwise.

**Reading of I-80.** For file custody the backend is the `fstp-keyd` process with its key volume. On the volume each root exists only sealed under its `K(e)`, and each `K(e)` only sealed under the passphrase key. The copy holds exactly those sealed forms, inside one more seal under a key derived from the same passphrase. It never holds a root, a `K(e)` or a table key in the clear. Only `fstp-keyd` makes or opens it, and opening writes the sealed forms onto a new key volume. `RootMaterial` stays named in `fstp-keyd` only. So the copy is a sealed artefact of the same custody backend, as the key volume is, and I-80 holds for it with no condition. "Custody interface" is unchanged: the `Custody` trait and the socket protocol gain nothing, and no client can ask for a copy.

**Reading of I-81.** Q32 scoped the I-81 claim of file custody to a key volume that is never backed up, snapshotted or copied. A copy is a copy, so these rules carry the claim:

1. A copy never holds a destroyed epoch. It re-encodes the opened key table, with each live `K(e)` and each destroyed entry as a tombstone of zeros, and it carries the epoch and sign-key files of live keys only. A slot that a failed write left blocked is never copied.
2. An imported volume is held. While the hold marker exists, `fstp-keyd` serves only unwrap and usage requests on the CellBackup and ClusterBackup chains, to a socket whose role reaches them. Every other request is refused with `NotPermitted` and logged. So `fstp-backup restore` runs, and no cell or vault can open a key.
3. Release ends the hold. The operator names the current epoch of each erasable chain the volume holds (App, Vault): the highest epoch whose `keystore.root` row is live in the restored keystore (ADR-004 record of lane L11). Release destroys every live epoch of that chain below it, with the steps and receipt of a destroy. An epoch above it is kept, since a rotation creates its new root before it commits. If the named epoch is not live in the volume, the copy is older than the last erasure. Release then destroys the older epochs, keeps the hold and refuses.
4. Each copy is recorded on its source volume in `exports.log`. At each start `fstp-keyd` reports reduced I-81 assurance, reason `ExportHoldsErasedEpoch`, while a copy that is not retired holds an epoch or sign key that has since been destroyed. `fstp-keyd retire-export` records the operator's statement that every copy of that id is destroyed.

Residual risk: a copy made before an erasure still holds the erased epoch. Whoever holds that copy and its passphrase can open the epoch outside our tools. An offline copy cannot prevent this by cryptography alone: only a component that is destroyed online can. Rules 2 and 3 keep our own tools from serving such an epoch, and rule 4 reports it until the copy is retired. The same holds for a cell erasure (R-SW-02) and the cell's CA sign key. Q-L16-1 below records how Daniel decided this.

| Topic | Reading |
| --- | --- |
| Copy file | `header = "FKX1" \| version u8 = 1 \| kdf u8 = 1 \| iterations u32 \| salt 16 \| export id 16 \| created u64` (50 bytes). `file = header \| nonce 12 \| ciphertext \| tag 16`, AES-256-GCM with AAD = header under `PBKDF2-HMAC-SHA-256(passphrase, salt, iterations)`, at least 600 000 iterations as the key table. `body = count u16 \| count times (name_len u8 \| name \| len u32 \| bytes)`. The first file is `keytable`. Every other is the epoch file of a live root, the sign-key file of a live sign key, or the usage log `usage.log` (Q-L16-2), named as on the volume. No other file, no repeated name and nothing after the last file is accepted. The whole copy is at most 160 MiB. Integers are big-endian. The decoders are fuzzed (`keyd_export_decode`) |
| Export | `fstp-keyd export <volume> <file>` opens the key table strictly, opens each live epoch and sign-key file under its key to check it, and writes the copy with a fresh salt and a random export id. It then appends the register record. It writes the copy with mode 0600 and refuses an existing file |
| Import | `fstp-keyd import <file> <volume>` refuses a volume that holds a key table, and a wrong passphrase (`WrongPassphrase`). It checks that the files are exactly those the opened table implies, and that each live file opens under its key. It then writes each file with mode 0600, fsyncs each and the directory, and writes the hold marker last |
| Hold marker | The empty file `import.hold` on the key volume |
| Release | `fstp-keyd release <volume> <chain>=<epoch> ...`, with chain `app` or `vault`. Every erasable chain with a live epoch in the volume must be named. A chain named but absent counts as a copy older than the last erasure |
| Register | `exports.log` on the source volume, append-only. `record = tag u8 \| export id 16`, then for tag 1 (taken) `created u64 \| count u16 \| count times slot head (9 bytes, as in the key table: chain u8 \| epoch u64, or the sign-key class with its 8 name bytes)`. Tag 2 (retired) has nothing more. It holds no key bytes. The decoder is fuzzed (`keyd_export_decode`) |
| Assurance | New `ReducedReason::ExportHoldsErasedEpoch`, code 23 in `fstp-obs`: "an off-host copy holds a destroyed key". A volume reason found by the filesystem check is reported first |
| Lock | `keyd.lock` on the key volume, held with an exclusive `flock` (std `File::try_lock`) by the server for its lifetime, and by export, import, release and retire-export. So none of them runs while the entry serves. A start waits up to 5 seconds for the lock |
| Passphrase | The commands read it as the server does: the systemd credential, or else `systemd-ask-password`. The copy is sealed under the passphrase of the volume, so an import needs the passphrase of the volume it came from |
| Usage log | Carried in the copy since Q-L16-2, sealed with the rest, as the file `usage.log`. Import writes it, so a restored entry answers the usage records made before the copy, and release's destroys follow them. Reconciliation after a restore therefore covers the time before the loss. It holds no key bytes. A copy is at most 160 MiB, room for a usage log at twice its size bound |
| Second custodian | Another `fstp-keyd` entry, on another machine, that creates its own ClusterBackup root. No request or command moves a root between entries. The ceremony is in ADR-012 (record of lane L16) |

Tests, in `crates/fstp-keyd/tests/offhost_copy.rs` and the unit tests of `fstp_keyd::export`: `i80_i81_host_loss_restore_from_offhost_copy`, `i80_offhost_copy_never_holds_a_root_or_epoch_key_in_the_clear`, `i81_destroyed_epoch_never_in_a_later_copy`, `i81_older_copy_restored_after_erasure_is_re_erased_before_serving`, `i81_held_import_serves_backup_chains_only`, `i81_copy_register_reports_reduced_assurance_after_erasure`, `i81_release_destroys_only_epochs_below_the_current_one`, `i81_destroyed_epoch_bytes_never_in_a_later_copy_body`, `adr004_copy_formats_round_trip_in_one_spelling`, `adr004_keyd_binary_takes_five_command_forms`, `i80_import_refuses_a_wrong_passphrase`, `i80_import_refuses_a_tampered_copy_or_a_used_volume`, `adr004_keyd_volume_lock_excludes_a_second_holder` and `adr004_offhost_copy_carries_the_usage_log_for_reconciliation`.

Questions raised by lane L16, all decided by Daniel on 2026-11-21:

- **Q-L16-1. Decided by Daniel on 2026-11-21:** the residual risk is accepted for the pilot. The runbook retires, which means destroys, every older copy after each erasure. A guard key that the second custodian holds online and destroys at each erasure is a release item. It must be built before a release, and the pilot runs without it. Built since 2026-11-23 as option A, below.
- **Q-L16-2. Decided by Daniel on 2026-11-21:** yes. A copy carries the usage log, sealed with the rest, and reconciliation after a restore covers the time before the loss. Built: the "Usage log" row above.
- **Q-L16-3. Decided by Daniel on 2026-11-21:** yes. The cell key file and the witness receipt key file follow the same rule. Built: "Copies of sealed key files" below.
- **Copy id. Decided by Daniel on 2026-11-21:** the runbook reads the id of a copy from its header with `od`. No command prints it (R-NF-02).
- The escrow formats of ADR-012 (record of lane L16) stay interim.

### The guard key of Q-L16-1 (F-018): option A, as built by lane `m10/guard-key`

Decided by Daniel on 2026-11-23: the M10 exit counts as the release that Q-L16-1 names, and the guard is built as option A. The second custodian becomes required. It serves the pilot host over mutual TLS and holds the guard, a hybrid KEM key pair. `backup-keys` seals each key copy once more to the guard's public half. The rotation step of an erasure asks the custodian to destroy the guard and make the next one, and records it. An import asks the custodian to open the outer seal. Daniel chose this knowing it needs a second machine that stays on, one pairing at setup and one configuration member naming the custodian.

Options B (the guard in OKMS) and C (the pilot reading) were not taken. This record replaces the options of the earlier draft. Every row below is the lane's reading of option A, interim, pending Daniel, unless it says otherwise. Findings F-018, TH-30, TH-59 and TH-84.

**What the guard does.** A copy made before an erasure, its passphrase and a database backup of the same age must not open data erased later. Only a component destroyed online can stop that. So each copy is sealed once more to a guard that lives only on the second custodian, and every destroy on the pilot entry replaces that guard before its receipt goes out. A copy made before the destroy then opens nowhere. A copy made after it never held the destroyed key (rule 1 of the record of lane L16).

| Topic | Reading | Basis |
| --- | --- | --- |
| Where the guard lives | On the key volume of the second custodian's `fstp-keyd` (ADR-012 record of lane L16). Each generation is a hybrid key pair from `fstp_crypto::hybrid_kem` (X25519 from aws-lc-rs plus ML-KEM-768 from moduletto, I-75). Its secret half is sealed with AES-256-GCM under a random key `K` of its own in the file `guard-<entry>-<generation>.key`. `K` lives in a slot of the key table, in the sign-key slot form with the class byte `0x10` | I-75; ADR-004 "Decided by Daniel, 2026-11-15 (late)" |
| Guard file | `header = "FGK1" \| version u8 = 1 \| class u8 = 0x10 \| name 8`, then `nonce 12 \| AES-256-GCM(K, aad = header, secret 2432) \| tag 16`. The name is `entry u8 \| 0 0 0 \| generation u32`. The structural decoder is fuzzed (`guard_link_decode`) | CLAUDE.md fuzz rule |
| One guard per pilot entry | The custodian keeps one guard sequence for each `fstp-keyd` entry of the pilot: `cell` 1, `cell-keys` 2, `vault` 3, `witness` 4, `control` 5. A Vault rotation runs at every document verification (P-19). With one shared guard, each verification would kill the copy of the `cell` entry too, and so every backup of the application cluster until the next copy | Availability of the copies |
| No socket reaches a guard | `SignKeyClass` knows no class `0x10`, so no Unix socket role can sign with, create or destroy a guard slot. Only the guard link reaches it | R-NF-08 |
| The custodian's volume is never copied | `fstp-keyd export` refuses a volume that holds a guard slot. A copy of the guard would outlive its destroy | I-81 |
| Generation 1 | The custodian creates it at the first `public` request of an entry, which `fstp-admin` sends when it checks the link after pairing | ADR-028 record of lane `m10/guard-key` |
| When a guard is replaced | At every destroy that the pilot entry serves: a root epoch, a sign key, or a destroy of `release` after an import. The pilot `fstp-keyd` first records the destroy's request id as the owed event in `guard.state`. It then runs the five destroy steps of its own key. After the read back passes it sends `rotate` with that event. The custodian creates generation `g + 1`, then destroys every older live generation of that entry with the five steps of a sign-key destroy, then answers | I-81 |
| When the receipt goes out | Only after the custodian answered `rotate`. Until then the pilot answers the destroy with the refusal `GuardPending` (code 10) and keeps the owed event. A retried destroy finds its own key gone, reads back again and retries the same event | I-81; ADR-004 part 2 "Erasure construction" |
| What the erasure does meanwhile | Step 6 of the App and Vault runners fails, keeps its phase, and is retried after one tick. Step 7, the completion, needs the receipt. So no erasure is reported complete while the old guard lives. A cell erasure (R-SW-02) waits the same way | I-81 |
| Order at the custodian | `rotate` first writes the event as pending in `guard-<entry>.event`, creates `g + 1`, destroys the older ones, and marks the event done. A retry of a done event answers the recorded result. A retry of a pending one finishes it. A crash at any point leaves at least one live generation, so a later copy still has a guard | ADR-004 part 2 "A crash at any step loses nothing" |
| Outer seal of a copy | `header = "FGC1" \| version u8 = 1 \| kem u16 = 1 \| entry u8 \| generation u32 \| copy id 16 \| created u64` (36 bytes). `file = header \| hybrid ciphertext 1120 \| nonce 12 \| AES-256-GCM(kek, aad = header, inner copy) \| tag 16`. `kek = HKDF-SHA-256(salt = "fstp-guard-copy-v1", ikm = ss, info = header, L = 32)`, with `ss` from `hybrid_kem::encapsulate` to the guard's public half. The inner copy is the passphrase-sealed `"FKX1"` copy, unchanged. The copy id of both headers is the same | R-CR-01; I-75 |
| Opening | The importing entry sends `open` with the generation, the header and the hybrid ciphertext. The custodian decapsulates with both halves and answers `kek`. It never sees the inner copy. A destroyed generation answers `Destroyed`, so the import stops with nothing written | I-80; I-81 |
| I-80 | The guarded copy holds the same sealed forms as before, inside one more seal. `kek` opens only the outer layer. No root, `K(e)` or table key crosses the link | I-80 |
| Register | `exports.log` gains tag 3, a guarded copy: `tag 3 \| id 16 \| created u64 \| generation u32 \| count u16 \| heads`. A guarded copy counts towards `ExportHoldsErasedEpoch` only while its generation is not below the current generation in `guard.state` | Rule 4 of the record of lane L16 |
| Pilot guard state | `guard.state` on the pilot key volume: `"FGS1" \| version u8 = 1 \| generation u32 \| rotated u64 \| owed u8 \| event 16` (34 bytes), written to a temporary file, synced and renamed. It holds no key bytes. Its decoder is fuzzed (`guard_link_decode`) | R-NF-02 |
| Development mode | Without a configured custodian the pilot entry destroys as before. In production it then starts at reduced assurance, the new reason `GuardMissing` (code 25, "no second custodian guards the off-host copies"), and the binary's `export` refuses. In development mode `export` writes an unguarded copy, which the register reports until it is retired, as the I-81 note of 2026-11-01 allows | I-81 NOTE |

**The guard link.** Settled here, interim, pending Daniel.

| Topic | Reading | Basis |
| --- | --- | --- |
| Transport | TCP with TLS 1.3 through `fstp-tls` (rustls with the aws-lc-rs provider, X25519MLKEM768 first). One exchange per connection, as `fstp_control::exchange`: the client writes one frame and closes its sending side, the server answers one frame and closes | R-NF-09; ADR-009 route feed |
| Runtime | The guard listener and the client run on tokio through `fstp_rt::tokio::TokioRuntime`, the one runtime of every M3 binary (ADR-002 note of 2026-10-28). The socket loop of `fstp-keyd` stays on std threads, as before | ADR-002 |
| Port | The custodian listens on port 7460 unless `FSTP_KEYD_GUARD_LISTEN` names another address | ADR-028 |
| Request | `"FGL1" \| version u8 = 1 \| kind u8 \| entry u8 \| request id 16`, then by kind: 1 `public`, nothing; 2 `rotate`, the event 16; 3 `open`, `generation u32 \| copy header 36 \| hybrid ciphertext 1120`. Each kind has one fixed length: 23, 39 or 1183 bytes | CLAUDE.md fuzz rule |
| Response | `"FGL1" \| version u8 = 1 \| kind u8 \| request id 16`, then by kind: `0x81` public, `generation u32 \| public key 1216`; `0x82` rotated, `destroyed u32 \| generation u32 \| public key 1216 \| receipt len u16 \| receipt`; `0x83` opened, `kek 32`; `0xff` refused, one `fstp_custody::Refusal` code. The receipt is the `"FKS1"` receipt of the last destroyed generation, or empty when none was live | ADR-004 record of lane m3/erase-cell-2 |
| Versions | Version 1 only. Any other version byte, kind or length is refused as `BadRequest`, so a new version needs a new byte and an amendment here | Freeze rule of part 1 |
| Limits | A request of more than 1183 bytes is not read further. A reply is at most 1312 bytes. The server allows 10 seconds for the handshake and the request, and serves at most 16 connections at once. The client allows 5 seconds to connect and 10 seconds for the whole exchange | R-NF-08 |
| Decoders | `decode_guard_request`, `decode_guard_response`, the guarded copy header, the guard file and `guard.state` are fuzzed in `crates/fstp-keyd/fuzz` (`guard_link_decode`), from their first commit | CLAUDE.md fuzz rule |

**Certificates.** No new trust root. The pilot's cell CA (`fstp-cell-ca`, ADR-028 "Certificates") issues both sides.

- Each pilot entry has a client certificate with the subject CN `keyd-guard-<entry>`, seven days long, renewed by `fstp-admin renew` with the other client certificates.
- The custodian has a server certificate with the CN `keyd-custodian` and its host name or address as the one subject alternative name. It lives two years. `status` names a new pairing 30 days before its end.
- The custodian trusts only the cell CA of its paired pilot, which the pairing file carries. The TLS handshake refuses every other peer.
- After the handshake the custodian reads the peer's subject CN with `fstp_pgwire::x509::subject_common_names` (fuzzed). It serves a request only when the certificate names exactly one CN `keyd-guard-<entry>` of a known entry, and the request names that entry. Anything else answers `NotPermitted` and is logged.
- The pilot checks the server's name against the configured host, and its CN against `keyd-custodian`.
- Why the cell CA. Its key already sits on the pilot as a root-only file and issues the other component links of the host. A second CA on the same host would add a root and protect nothing more.

**What is recorded, and where.**

- The custodian appends one record per request to `guard.log` on its volume: `tag 0xf2 \| time u64 \| op u8 \| entry u8 \| outcome u8 \| generation u32 \| next u32 \| id 16 \| check 4`, 40 bytes, check the first 4 bytes of SHA-256 of the rest. Op 1 public, 2 rotate, 3 open. No key bytes. Its decoder is fuzzed.
- The id of a `rotate` record is the request id of the pilot destroy that caused it. The cell's and the vault's `RecordKeyOp` of that destroy carry the same id (ADR-004 "Reconciliation"). So the custodian's log reconciles with the audit chain, and the receipt digest that `KeyEpochDestroyed` records is of a receipt sent only after the rotation.
- The pilot keeps the generation, the time of the last rotation and the owed event in `guard.state`.

**While the custodian is unreachable.** The I-81 note of 2026-11-01 scopes reduced assurance to the host and the filesystem of the key volume. It does not cover an old copy that still opens. So the erasure waits, as the lane brief asks when the invariant does not settle it. The key is gone on the pilot at once, and only the completion waits. Document verifications wait with their Vault rotations (P-19). `status` and the System page show the custodian red. Question Q-F018-1 below asks Daniel to confirm.

**Recovery after the loss of the pilot host.** The operator installs a new host and runs `fstp-admin setup`. They then pair it with the same custodian (ADR-028 record of lane `m10/guard-key`). The new pairing file names the new cell CA, and the custodian keeps its guards. `fstp-admin restore` imports the newest copy of each entry: the custodian opens the outer seal, and the rules of the record of lane L16 apply as before. A copy older than the last erasure of its entry no longer opens.

**Recovery after the loss of the custodian.** Every guarded copy is then unopenable, so the pilot must make new ones at once. The operator pairs a new custodian, `fstp-admin setup` checks the link, and `fstp-admin backup-keys` writes copies under its generation 1. An owed rotation completes against the new custodian, which has no older generation to destroy. The operator states, by pairing again, that the old custodian's volume is destroyed. Its guards sit sealed under a passphrase stored on that machine, so a stolen custodian disk with an old copy, its passphrase and an old backup still opens erased data. That residual risk is Q-F018-2.

**Tests.** `m10_f018_th30_an_old_key_copy_and_an_old_backup_do_not_open_later_erased_data`, `m10_f018_i81_an_erasure_is_not_complete_while_the_old_guard_lives`, `m10_f018_a_key_copy_does_not_open_without_the_custodian` and `m10_f018_r_nf_09_a_peer_without_the_right_certificate_cannot_open_or_destroy` in `crates/fstp-keyd/tests/guard.rs`, with the unit tests of `fstp_keyd::guard`.

**Questions for Daniel.** All five were answered on 2026-11-24, below.

- **Q-F018-1.** While the custodian is unreachable, the erasure waits, because the I-81 note does not cover this case. Confirm, or name a reduced-assurance completion with a visible state instead.
- **Q-F018-2.** A lost custodian is replaced by pairing again. Its old volume holds guards sealed under a passphrase on the same machine. Should the custodian's passphrase come from the operator at each start, as `systemd-ask-password` allows, so a stolen custodian disk alone opens nothing?
- **Q-F018-3.** Copies made before this change are plain `"FKX1"` copies. In production `import` refuses them, since no guard can be destroyed for them. The runbook retires them after the first guarded copy. Confirm.
- **Q-F018-4.** After each erasure the old copies of that entry stop opening at once. A host loss before the next `backup-keys` then loses the keystore snapshots of that entry. An old copy already failed to open the App or Vault data after an erasure, since it lacks the new epoch. The cluster backups still restore through the custodian's escrow (ADR-012 record of lane L16). `status` and the System page name the new copy as the next thing to do. Should `fstp-keyd` write a fresh guarded copy to the custodian after each rotation, so no gap remains?
- **Q-F018-5.** The import of a guarded copy after the loss of the host is still a command by hand, with the guard variables and credentials beside the passphrase (`docs/guide/production-reference.md`). Should `fstp-admin` gain a `restore-keys <dir>` that stages them, as `backup-keys` does?


#### Decided by Daniel on 2026-11-24: the answers to Q-F018-1 to Q-F018-5

| Question | Decision |
| --- | --- |
| Q-F018-1 | Decided by Daniel on 2026-11-24: while the custodian is unreachable, the erasure waits. The key is gone on the pilot at once, and the completion waits for the guard rotation, as built |
| Q-F018-2 | Decided by Daniel on 2026-11-24: the custodian's passphrase stays on the custodian machine, as built, so it starts unattended. Residual risk, accepted: a stolen custodian disk holds both the guards and the passphrase that seals them. Whoever also holds an old pilot copy, its passphrase and a database backup of the same age can then open data erased since. Four separate things must be stolen. Pairing a new custodian after a loss is the operator's statement that the old disk is destroyed. Amended on 2026-11-24 by the decision on the passphrases below: a directory of `backup-keys` holds a copy and its passphrase together. Three separate things must then be stolen: the old custodian disk, a copy directory of the same age and a database backup |
| Q-F018-3 | Decided by Daniel on 2026-11-24: in production `fstp-keyd import` refuses a plain pre-guard `"FKX1"` copy, as built, since no guard can be destroyed for it. Development mode still admits one. The runbook retires plain copies once the first guarded copy exists |
| Q-F018-4 | Decided by Daniel on 2026-11-24: after each guard rotation the pilot entry sends a fresh guarded copy to the custodian by itself. The operator has no step. Built as "The custodian's copy" below |
| Q-F018-5 | Decided by Daniel on 2026-11-24: `fstp-admin restore-keys <dir>` stages the guarded import after a host loss in one command. Built as recorded in ADR-028 (record of lane `m10/guard-key`, part 2) |

#### Decided by Daniel on 2026-11-24: the passphrases beside the key copies

Asked "Should backup-keys write the custody passphrases beside the key copies? It saves typing at restore-keys, but a stolen copy directory would then open by itself", Daniel answered "yes". `fstp-admin backup-keys` now writes each guarded entry's passphrase as `<entry>.passphrase` beside the guarded copies, and `restore-keys` reads them without asking. ADR-028 records the details (record of lane `m10/guard-key`, part 3).

Residual risk, accepted. The directory still does not open by itself, because the outer seal of each copy needs the custodian. The custodian opens it only for a peer with that entry's guard client certificate from the paired cell CA, and only while the copy's guard generation lives. So a thief of the directory also needs either a root-only key of the pilot (a guard client key or the cell CA key) with a path to the custodian, or the custodian's disk. The directory together with the custodian's disk opens the live roots, since the disk holds the guards, their passphrase and the newest held copy of each entry. No erasure reopens that way (I-81). The case of Q-F018-2 needs three separate things stolen, not four. Only guarded copies get their passphrases, so a plain `"FKX1"` copy of development mode never sits beside one (I-80).

#### The custodian's copy (Q-F018-4)

Written by lane `m10/guard-key` before its code. Interim, pending Daniel, unless a row says otherwise.

| Topic | Reading | Basis |
| --- | --- | --- |
| What the custodian stores | For each pilot entry at most one copy, the file `held-<entry>.fgc` on its key volume. It is a guarded copy (`"FGC1"`) of that entry, sealed to the entry's newest live guard generation. A new copy replaces the old one: written to a temporary file, synced and renamed | Q-F018-4 |
| The custodian cannot open it | The outer seal opens with the guard, which the custodian holds. The inner `"FKX1"` copy is sealed under a key derived from the pilot entry's passphrase. The custodian never receives it. It stays on the pilot and, since Daniel's decision of 2026-11-24, in each directory of `backup-keys`. So the custodian alone opens no root (I-80). Its disk together with such a directory does, as the decision above states | I-80 |
| Which generations it keeps | One: the copy sealed to the newest live generation. A `put` for any other generation is refused with `Destroyed` when that generation is gone and `BadRequest` otherwise, so the custodian never stores a copy that a destroyed guard sealed | I-81 |
| When it deletes the old one | In the same `rotate` that destroys the old generations, after their destroy has read back, the custodian unlinks every held copy of the entry sealed to an older generation and syncs the directory. If the unlink fails, the file stays sealed to a destroyed guard. No key opens it, so it cannot reopen F-018. The next `rotate` or `put` tries the unlink again | I-81, TH-30 |
| No erased key in it | The pilot makes the copy after the rotation, so after its own destroy has read back. Rule 1 of the record of lane L16 then keeps every destroyed key out of it | I-81 |
| When the pilot sends it | Right after each rotation answers, inside the same destroy request: the pilot builds the copy under the lock it already holds, seals it to the new public half the rotation returned, and sends `put`. It needs the passphrase, which the pilot entry now keeps in wiped memory for its lifetime, as it already keeps the table key | Q-F018-4 |
| Completion does not wait for it | The receipt goes out once the rotation answered, whether the copy reached the custodian or not. I-81 needs only the old guard destroyed. The fresh copy serves availability. Tying it to completion would let a full disk or a slow link hold back erasures that are already safe | I-81; Q-F018-1 |
| When the write fails | `guard.state` marks the copy owed. The pilot retries at its next start, at every destroy, and every ten minutes while it serves. `fstp-keyd guard-check` exits 6 while a copy is owed, and `status` and the System page show it amber, with the host admin to act | Usability rule of 2026-11-21 |
| Not in the register | Held copies are not recorded in `exports.log`. The custodian deletes each at the next rotation, and each dies with its guard. Recording one per erasure would grow the register without end | Rule 4 of the record of lane L16 |
| Size | A copy is at most the bound of a guarded copy: 160 MiB of inner copy plus the outer seal. The custodian reads a request body only after the TLS peer names a pilot entry. A peer of the right CA with another CN can send 1183 bytes at most. `put` and `fetch` allow 300 seconds, every other exchange 10 seconds | R-NF-08 |
| Wire | Request kind 4 `put`: `generation u32 \| len u32 \| copy`; kind 5 `fetch`: nothing. Response `0x84` stored: `generation u32`; `0x85` copy: `generation u32 \| len u32 \| copy`. A `fetch` with nothing held answers `UnknownRoot`. The guard log records op 4 put and op 5 fetch. Fuzzed in `guard_link_decode` | CLAUDE.md fuzz rule |
| Pilot guard state | `guard.state` gains `copy u8 \| copied u64` after the event: 1 while a copy is owed, and the time of the last copy the custodian stored. The branch never shipped the shorter form, so the version stays 1 | R-NF-02 |

Tests: `m10_f018_i81_after_a_rotation_the_custodian_holds_a_copy_that_opens_with_the_new_guard`, `m10_f018_th30_the_custodian_holds_no_copy_that_opens_erased_data`, `m10_f018_i81_a_failed_copy_write_does_not_hold_back_completion_and_is_retried`, `m10_f018_i81_the_custodian_refuses_a_copy_for_another_generation` and `m10_f018_i81_production_refuses_a_plain_pre_guard_copy` in `crates/fstp-keyd/tests/guard.rs`.

### Copies of sealed key files (Q-L16-3)

Built by lane L16 after Daniel's answer of 2026-11-21. The readings are interim, pending Daniel, unless a row says otherwise.

| Topic | Reading |
| --- | --- |
| Rule | Decided by Daniel on 2026-11-21: each copy of `cell-keys.sealed` or of the witness receipt key file `receipt.key` is recorded in a copy register. The owning process reports reduced I-81 assurance while a copy that is not retired holds a key it has since replaced |
| Commands | `fstp-cell copy-key-file <out>` and `fstp-witness copy-key-file <out>` open the file through the owner's own `fstp-keyd` entry, write its sealed bytes to the new file `<out>` with mode 0600, record the copy, and write its id to the new file `<out>.id`. `retire-key-file-copy <id>` records that every copy of an id is destroyed. The commands write typed events only |
| Register | `cell-keys.copies` and `receipt.copies`, beside the key file. `record = tag u8 \| copy id 16`, then for tag 1 (taken) `created u64 \| count u16 \| count times digest 32`. Tag 2 (retired) has nothing more. The decoder is fuzzed (`copy_register_decode`, in `fstp_custody::copies`) |
| Digest | `SHA-256("fstp-copy-register-v1" \| label_len u8 \| label \| key)`. The cell labels its keys `anchor`, `cred_lookup`, `ticket` and `ledger`, the witness its key `receipt`. Each key is high-entropy, so a digest names it without revealing it. The register holds no key bytes (I-80) |
| Replaced | A key whose digest the copy holds and the live file does not. A new ledger generation adds a key and replaces none. A register that does not decode counts as holding a replaced key |
| Report | At each start, after the key file opens, the owner logs `key_file_assurance` with the file name and `ReducedReason::CopyHoldsReplacedKey` (code 24): "an off-host copy of a key file holds a replaced key". Nothing is logged when no copy holds a replaced key, since the owner does not vouch for the credentials directory |

Tests: `i81_copy_register_flags_a_copy_holding_a_replaced_key`, `i81_unreadable_copy_register_counts_as_reduced`, `i80_copy_register_holds_no_key_bytes` and `adr004_copy_register_round_trips_in_one_spelling` in `crates/fstp-custody/tests/copy_register.rs`; `i81_cell_key_file_copy_reports_reduced_after_a_key_is_replaced`, `i80_cell_key_file_copy_register_holds_no_key` and `adr004_cell_binary_takes_the_key_file_copy_commands` in `fstp_cell::key_copy`; `i81_witness_key_file_copy_reports_reduced_after_the_key_is_replaced` in `fstp_witness::key_copy`.

## Written by lane L17 `prod/vault-snapshots`, 2026-11-21: the VaultBackup chain and the snapshot keys

Written by lane L17 before its code. Decided by Daniel on 2026-11-21: ADR-012 "Keystore snapshots" option A, a vault-held snapshot key under the vault's own custody entry. This record is the amendment that option needs. The snapshot writers, step 5 and the restore rule are in ADR-012 (record of lane L17). Every row is interim, pending Daniel, unless it says otherwise.

**A chain, not a purpose.** Option A named two forms: a `Backup` purpose on the Vault chain that never takes part in erasure, or a separate `VaultBackup` chain. This lane takes the chain, for three reasons.

1. A `Backup` group on the Vault chain is a level 2 group. Its secret is sealed under `S(e)` of the Vault chain, resealed at step 3 of each rotation, and its old seal dies with `R(e)` at step 6. A restore needs that secret to open the newest snapshot. A restored database that predates the last rotation holds the secret sealed only under a destroyed epoch. The snapshot then does not open in exactly the case that ADR-012's restore rule takes it for.
2. A held import of an off-host copy (record of lane L16, rule 2) serves only the backup chains, so the restore commands run while no erasable epoch can open. A purpose on the Vault chain could not be served there without serving the Vault chain itself.
3. A chain of its own is never reached by the planner `fstp_keys::erasure`, as CellBackup and ClusterBackup are not. So "never takes part in erasure" holds by construction, not by a rule in the runner.

| Topic | Reading |
| --- | --- |
| Chain code | `VaultBackup`, code 6, file custody name `vaultbackup`. The chain codes of part 1 become App 1, Vault 2, CellBackup 3, ClusterBackup 4, ControlPlane 5, VaultBackup 6. No code is renumbered. `fstp_keys::Chain::from_code` and the reference copy `fstp_celltest::reference::keys::chain_code` take it |
| Chains table | A new row: VaultBackup, process `fstp-vault`, purpose `Backup` (code 5), the vault's keystore snapshot containers. Yearly re-wrap. Never rotated by erasure. The owner is the cell id, as for CellBackup |
| Custody | The vault's own `fstp-keyd` entry. The `vault` client role reaches Vault and VaultBackup. The `cell` role never reaches VaultBackup, and the `vault` role never reaches App or CellBackup (R-NF-08, I-83). The console role is unchanged |
| Vault snapshot key | `vault-snapshot.key` in the vault's credentials directory. It has the layout of `cluster-backup.key` (ADR-012 record of lane L10) under the 22-byte magic `"fstp-vault-snapshot-v1"`. The owner field holds the cell. Its root is `{cell, VaultBackup, epoch 1}` in the vault's entry. The file holds the group public key, the custody handle, `S` wrapped under the root and the group secret sealed under `S`. It never holds an open key (I-80) |
| App snapshot key | `cell-snapshot.key` in the cell's credentials directory, the same layout under the magic `"fstp-cell-snapshots-v1"`. Its root is `{cell, CellBackup, epoch 1}` in the cell's own entry, which the `cell` role reaches. It is not the dedicated root of the cell key file (record of lane L4), which lives in another entry. The CellBackup chain of part 2 now has a key, as that row always said |
| Genesis | Automatic, with no operator step (usability rule of 2026-11-21). `fstp-vault init-keys` writes `vault-snapshot.key` beside the keystore. A vault or a cell whose configuration names an object store and whose credentials directory has no snapshot key file creates it at its next start, then serves. A crash between the custody create and the file write leaves a root that no file names. The next start creates another, as genesis does (record of lane L8) |
| Separation | A key file decodes only under its own magic, so neither process reads the other's file. Each container's data key is sealed to its chain's group (`FSK1` context with chain 3 or 6), so a vault snapshot never opens under the App snapshot key, and the reverse (R-NF-08) |
| Held import | While a volume is held, `fstp-keyd` serves unwrap and usage requests on VaultBackup too, to a socket whose role reaches it. VaultBackup takes no part in erasure, so this opens no erasable epoch (I-81). Release still names App and Vault only |
| Cell erasure | `fstp-control` destroys every live root of the App, Vault, CellBackup and VaultBackup chains of the cell that it is given (R-SW-02). So every snapshot of an erased cell stays sealed under a destroyed root. A VaultBackup root is optional (`OPTIONAL_CELL_CHAINS`), since a pilot with no bucket has none. The list of the cell's roots must name it when it exists |
| Copies | The off-host copy of the vault's entry carries the live VaultBackup root like any live root (record of lane L16). The snapshot key files hold no key that an erasure replaces, so they need no copy register (Q-L16-3). A copy of a credentials directory carries them |
| Rotation | The yearly re-wrap of CellBackup and VaultBackup is not built, as for ClusterBackup |

Tests, written before the code: `r_nf_08_vault_socket_reaches_vault_backup_and_never_app_chains` in `crates/fstp-keyd/tests/serve.rs`; `adr004_vault_backup_chain_code_is_six` in `fstp-keys`; `r_nf_08_snapshot_keys_never_open_each_other` and `adr004_snapshot_key_files_decode_only_under_their_magic` in `crates/fstp-backup/tests/keystore_snapshots.rs`; `r_sw_02_cell_erasure_destroys_vault_backup_roots` in `fstp-control`. Also `i81_held_volume_serves_vault_backup_unwrap_only` in `fstp_keyd::export`. Built by lane L17 on 2026-11-21 as written above.

**Amended by lane m10/backup-followups, 2026-11-24.** Interim, pending Daniel (ADR-012 record of lane m10/backup-followups). The rows "Vault snapshot key" and "App snapshot key" above describe version 1. Each snapshot key file now has a version 2 form under the magics `"fstp-vault-snapshot-v2"` and `"fstp-cell-snapshots-v2"`. It carries the process's composite writer public key and a binding signature, and its sealed part holds the writer's private key after the group secret. The wrap of `S` gives custody `"fstp-backup-key-custody-aad-v2" || SHA-256(header)`, so the AAD stays within the 1,024 bytes of `fstp-keyd`. The root, the chain, the group and the separation are unchanged. A process that starts with a version 1 file upgrades it through its own entry under the same root. No new custody call and no new socket permission is needed: the upgrade unwraps and wraps on the snapshot root, as genesis and step 5 already do.

## Built by lane L21 `prod/unicode-normaliser`, 2026-11-22: the normaliser in the tuple

Decided by Daniel on 2026-11-21: NFKC + case fold (ADR-029). Every other reading is the lead's, pending Daniel.

| Topic | Reading |
| --- | --- |
| Seam | `fstp_vault::codec::tuple_name` is `fstp_unorm::name_key`. `fstp_vault::codec::TUPLE_LABEL` is `fstp-identity-tuple-v2` |
| Field check | A name field must also give a non-empty `name_key`, so a name of only default ignorables is refused at decode |
| Earlier labels | `fstp_vault::codec::OLD_TUPLE_LABELS` holds `fstp-identity-tuple-v1`. `Runner::check_tuple_labels` opens every live tuple and refuses a keystore that stores one under an earlier label. `fstp-vault serve` runs it at each start (`resume_keystore`), and `fstp-vault verify-first-admin` runs it before it registers. The refusal reads "an identity tuple of an earlier label: recreate this pilot vault". An erased tuple is not checked, since it no longer opens |
| Pilot vaults | A pilot vault that verified anyone before lane L21 is recreated: a fresh vault database, then `init-keys` (the operator guide says so) |

Tests: `i81_adr004_name_variants_register_as_one_identity` and `i81_start_refuses_identity_tuples_of_an_earlier_label` (over PostgreSQL, `crates/fstp-vault/tests/identity_facts_pg.rs`); `adr004_name_variants_give_one_tuple` (`crates/fstp-vault/tests/codecs.rs`).

## Written by lane L26 `prod/display-names`, 2026-11-22: display names on the production cell

Written before the code. Decided by Daniel on 2026-11-21: the fingerprint key and the recompute at step 2 (section "Chains", row on the display name fingerprint key). Every other row is interim, pending Daniel, unless it says otherwise.

Until this lane, `TextStore::set_display_name` failed closed on the production cell, so no pilot could set a display name (SA-11).

| Topic | Reading |
| --- | --- |
| Owner | The App chain's keystore owner, `fstp_cell::tasks::erasure`, keeps the display names beside the login email index. `CellTexts` (`fstp_cell::api::content`) reaches them through `ErasureHandle`. The `Lookup` key and the fingerprint key never leave the erasure task |
| Text | Each display name is sealed as a text of its own, under a data key of its own, in a group of its own (purpose `Text`), as `CellTexts::put` stores a text. The text holds the name as the person typed it after the API core's trim |
| Subject of `Lookup` | The text's data key is a subject of the `Lookup` keyed digest group, as a login email text is. The erasure task creates the `Lookup` group at the first display name when no login email created it first |
| Fingerprint | `fstp_api_core::display_name::fingerprint` under the key HKDF-SHA256(`Lookup` key, empty salt, `fstp display name fingerprint v1`). The task derives the key into a zeroed heap box, as it derives the `Lookup` key, and drops it after each use |
| Normalisation | `fstp_api_core::display_name::normalised` becomes `fstp_unorm::name_key`: compatibility caseless folding (`NFKC_CF`), default ignorables removed, white space trimmed and collapsed. It replaces the "Simpler comparison" of the SA-11 amendment. The reasons are in "Why `name_key`" below |
| Index table | Migration `0012_display_name.sql`: `keystore.display_name (account, text_id, fingerprint)`, one row per account that has a name. The fingerprint column is `UNIQUE`, so PostgreSQL refuses one fingerprint for two accounts as a second guard. Only the keys role holds a right on it (I-82) |
| Atomic check | The erasure task serves one request at a time. The check, the seal and the index write are one request, and its reply follows the durable write of every row it changed |
| Same name again | The account's own name again, byte for byte, changes nothing. Its own name in another case or spacing is `Set`, and replaces the text |
| Replace and clear | The old fingerprint leaves the index at once, so the name is free at once. The old text's data key gets an erasure request in the chain state directly, at the sequence of the ledger head, and its batch starts at once. The batch gives the `Lookup` group a new generation (G24) |
| Step 2 | A batch that gives `Lookup` a new generation recomputes the fingerprint of every live display name from its sealed text under the new key, beside the login email digests. Step 4 commits both. A name whose text the batch erases leaves the index |
| A batch in flight | A set that arrives while a batch is before its commit first runs that batch to its commit, then is served. So a person who changes the name twice in a row is not refused. A step that fails answers `Unavailable`, and the person tries again |
| Erasure log | Built by lane L33 (ADR-007 section "Built by lane L33"): the erasure runner appends `KeystoreErasureRequested` for the replaced or cleared name, naming the account, and `ErasuresCompleted` once its key died |
| Account erasure | The production cell has no account erasure path yet. `Keystore::display_text` names the text, as `Keystore::login_text` does, for that path. When a batch erases that text, the name leaves the index at the commit |
| Reads | `TextStore::display_names` releases names only to the team read, the member read and the account's own read, as the test kit's store does (`clears`). No other read shows a name, so no Judging read model and no applicant read carries one (I-17, P-11, R-AN-01). No message carries one (I-27) |
| Snapshot image | The keystore image of ADR-012 holds the display name texts among its text rows, but not the index rows, as it holds no signing key rows yet. The index rows are in the keystore tables, which the cell's backups hold |

### Why `name_key`

- The SA-11 amendment first asked for NFC and case folding. Daniel chose the simpler comparison on 2026-11-15 because no workspace code did either. `fstp-unorm` does both now (ADR-029).
- Daniel decided on 2026-11-21 that compatibility forms match in the identity tuple. The same key for display names gives the platform one rule for names.
- `name_key` removes default ignorables, such as U+200D ZERO WIDTH JOINER. Under the simpler comparison, "Anna Berg" and the same name with a zero width joiner inside are two names that look alike on the team page. Under `name_key` they are one.
- A name whose key is empty, such as one made only of default ignorables, is refused under SA-11, as the tuple refuses one (row "Field check" of lane L21).
- Stability: no fingerprint was stored before this lane. The production cell refused every set, and the test kit's store lives in memory only. So no stored fingerprint needs a migration, and the key label stays `v1`. A later change of the key form, such as a new Unicode version, needs a new label and a recompute of every fingerprint from its sealed name.

Tests, written with the code: `sa11_unique_adr029_variants_of_one_name_are_one_name` and `sa11_unique_name_of_ignorables_only_is_empty` (`fstp_api_core::display_name`); `sa11_unique_adr004_display_key_is_derived_from_lookup`, `sa11_unique_production_display_name_is_sealed_unique_and_read_back`, `sa11_unique_i81_replacing_a_name_erases_it_and_replaces_lookup`, `sa11_unique_clearing_a_name_frees_and_erases_it`, `sa11_unique_display_names_survive_a_restart` and `sa11_set_during_a_batch_is_served_after_its_commit` (`crates/fstp-cell/tests/keystore_tables.rs`); `sa11_unique_display_name_index_holds_one_account_per_fingerprint` (over PostgreSQL, `crates/fstp-pgstore/tests/keystore_tables.rs`); `sa11_production_cell_sets_unique_display_names` (the production cell over PostgreSQL, `crates/fstp-celltest/tests/sa11_display_names_pg.rs`).

### Lead reading, 2026-11-22

- The normaliser: `fstp_unorm::name_key` for display names is accepted, consistent with Daniel's NFKC choice for identity names (ADR-029). It replaces the "Simpler comparison" of 2026-11-15.
- The erasure log: no erasure-log row for a replaced or cleared display name for now. A later lane adds one (row "Erasure log").
- The old image `FKI1` need not hold the index rows (row "Snapshot image"). Lane L27's image `FAK1`, from which a restore takes the tables whole, carries them from version 2, since only the index names the account of each name (ADR-012 record of lane L26).
