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
- The display name fingerprint key (SA-11 amendment, lane m4/unique-names) is derived from the App chain `Lookup` key through HKDF-SHA256 with the fixed label `fstp display name fingerprint v1`. Each fingerprint is HMAC-SHA256 of the normalised name under it. A display name is a subject of `Lookup`, like a login email. An erasure that removes one replaces `Lookup`, and step 2 recomputes the fingerprint of every live display name from its sealed text. Interim, pending Daniel.

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
| Restore declaration key | Composite | Control-plane custody, level 2 under chain ControlPlane, held by `fstp-control` | Yearly. The witness pins the current and the next public key. Interim, pending Daniel: proposed by ADR-012 (Declared restores at the witness) |

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
- **Route table polling.** `fstp_control::routes::RoutePublisher` holds every cell's route and a version that rises with each change. It signs each version with the control-plane composite key under the context `fstp-route-table-v1`. Interim, pending Daniel, the bytes: `"FRT1"`, the version as `u64`, a route count, and per cell its id, application host and both tunnel endpoints, in ascending host order, then the signature. The decoder `fstp_edge::decode_signed_route_table` has the fuzz target `route_table_decode`.
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
| Root entry | Interim, pending Daniel. The root lives in its own `fstp-keyd` entry, named by the configuration member `key_file_keyd_socket`, as the witness receipt key has its own entry. The start refuses a configuration whose two keyd sockets are the same path. The keystore and its erasures never reach that entry |
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
