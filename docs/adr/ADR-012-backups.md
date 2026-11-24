# ADR-012: Backups

Status: Accepted 2026-10-28 (Daniel Thompson-Yvetot).

Labels such as Q4, Q25, G22 and W2k exist only in `docs/handoff/m3-design.md`. They are not spec identifiers. ADR-008 to ADR-012 were drafted on 2026-10-28 and accepted the same day. Items marked "interim, pending Daniel" are proposals that no answer of 2026-10-28 settles.

## Context

- **I-81** Destroying a root or data key makes the protected data unrecoverable, including from backups.
- R-CR-01 asks that data at rest leaving the running system, such as backups, be protected by hybrid post-quantum key encapsulation (ADR-001).
- R-ID-03 asks that no backup or replica can reproduce an identity document after verification. R-SW-02 asks that no backup or replica can restore an erased cell.
- ADR-004 and its M3 completion use root-epoch rotation per erasure batch. Copies of erased keys in backups stay sealed to group generations whose epochs are destroyed (`m3-design.md` section 3.5).
- Daniel decided Q4 A with R1 on 2026-10-28. There is no streaming replica. `pg_basebackup` runs over loopback, and a standby restores from the sealed WAL archive.
- Daniel decided on 2026-10-28 that the second backup provider is chosen later, with the L-15 due diligence (Q25).
- ADR-005, as amended on 2026-10-28, sets the primary copy at OVHcloud Object Storage and the recovery point objective of about one minute.

## Decision

### What is backed up

| Source | Method | Sealed to | When |
| --- | --- | --- | --- |
| Each self-operated cluster: `application`, `vault`, `witness` | `pg_basebackup` over loopback as `fstp_repl`, and the WAL archive through `archive_command` | The ClusterBackup group key of that cluster | WAL continuously, with `archive_timeout` of 60 seconds. Base backup frequency is decided with retention (Q25) |
| Each cell's keystore, in `c_<cell>` and in `v_<cell>` | A keystore snapshot, written by `fstp-cell` and `fstp-vault` respectively | The CellBackup group key of the cell for `c_<cell>`. For `v_<cell>`, an open point (Keystore snapshots) | After every erasure batch, and daily |
| The managed `control` cluster | The provider's managed backups | Not sealed by us | The provider's schedule (ADR-005 verify item V10) |

- The witness also writes each prepare, abort, in-doubt record and receipt to an object-lock bucket at a second provider (ADR-010). That copy is not a backup in this ADR's sense, and it waits on Q25 as well.
- As first drafted, a vault keystore snapshot is sealed to the CellBackup group key, so the vault holds that group's public key only. Its rows stay sealed under the vault chain's epoch seal key. Opening the container therefore does not open any vault key. That leaves the vault unable to verify its own snapshot, which ADR-004 erasure step 5 needs. "Keystore snapshots" below proposes how this is closed.

### Container format

Every backup object is one container. ADR-004 leaves the exact layout and AAD of backup containers to this ADR. The bytes below are interim, pending Daniel.

```text
header = "FBC1" | version u8 = 1 | aead u16 = 1 | kind u8 | chain u8 | owner 16
         | container 16 | part u32 | chunk_size u32 | sealed_key 1210        1259 bytes
chunk  = final u8 | len u32 | nonce 12 | ciphertext len | tag 16
aad(i) = header | i u64 | final u8
body   = chunk(0) | chunk(1) | ... | chunk(n), and chunk(n) alone has final = 1
```

- Integers are big-endian. `aead = 1` names AES-256-GCM, as in ADR-004.
- `kind`: 1 base backup file, 2 WAL segment, 3 keystore snapshot, and 4 custodian escrow since the record of lane L16.
- `chain`: the ADR-004 code for ClusterBackup (4) or CellBackup (3). `owner` is the `ClusterId` for ClusterBackup and the `CellId` for CellBackup, as in ADR-004.
- `container` is a random id. It is also the id of the data key, so it is the `object` of the sealed key's context.
- `part` numbers the parts of a split container from 0. A container that is not split has `part = 0`.
- `chunk_size` is 1 MiB (1 048 576). Version 1 accepts no other value.
- `sealed_key` is the data key in the 1210-byte `FSK1` form of ADR-004, sealed to the chain's group key. The purpose code for backups comes from the ADR-004 purpose table: Record at first use.
- Each chunk is sealed with AES-256-GCM through `fstp_crypto::aead::seal`, which draws a random 96-bit nonce. The nonce is stored in the chunk.
- The AAD binds each chunk to its container, its position and its final flag. A chunk moved, reordered or relabelled fails to open.
- Test vectors: recorded below in "Record: container test vectors" (lane m3/erase-steps, 2026-11-13). The writer and opener landed in lane F-ERASE before them.

Rules:

- **Data key:** fresh for every backup attempt, every WAL segment and every snapshot, so a retried upload never reuses a key. Its hybrid sealing, X25519 plus ML-KEM-768 (ADR-004), meets R-CR-01.
- **Writer:** `fstp-backup` holds only the group's public key, so the writer cannot decrypt what it wrote.
- **Seal limit:** a container whose chunk count would reach the 2^24 hard limit of ADR-004 is split. Each part gets its own data key.
- **Decoder:** one spelling only. `final` is 0 or 1. A non-final chunk has `len` equal to `chunk_size`, and the final chunk has `len` at most `chunk_size`. Exactly one chunk is final, and it is the last. Bytes after it are refused. A missing final chunk is reported as truncation.
- **Opening:** needs the group secret, which opens only through the chain's current epoch seal key, unwrapped through custody. `fstp-control` holds the ClusterBackup chain and `fstp-cell` the CellBackup chain (ADR-004). The key that seals vault snapshots is an open point (Keystore snapshots).

### Record: container test vectors

Recorded by lane m3/erase-steps on 2026-11-13. Interim, pending Daniel, like the container bytes they record.

- `seal_container` draws the container id, the data key, the KEM randomness and each chunk nonce itself. No API takes them from a caller (ADR-004 nonce rule). So each vector is a container the writer sealed once and the test decodes. Production randomness is unchanged.
- The vector key pair is fixed. Its X25519 scalar is `SHA-256("fstp-adr012-vector-v1 x25519")`. Its ML-KEM-768 seeds are `d = SHA-256("fstp-adr012-vector-v1 mlkem d")` and `z = SHA-256("fstp-adr012-vector-v1 mlkem z")`, expanded through FIPS 203 `ML-KEM.KeyGen_internal`.
- SHA-256 of the public key `pk_X || pk_M`: `0304c1ef4c006f2310fa89666d06d7161bace83f4f75af95856548c6e4212e78`.
- The container bytes are Rust constants in `crates/fstp-celltest/tests/adr012_container_vectors.rs`, as ADR-004 item 3 keeps its vectors. That crate may name the single-half ML-KEM entry points for test vectors (I-75 scan).

| Vector | Kind, chain | Owner, group, generation, part | Plaintext | Container id | Data key | SHA-256 of the container |
| --- | --- | --- | --- | --- | --- | --- |
| V1 | 3 keystore snapshot, CellBackup (3) | `11` x16, `22` x16, 1, 0 | empty (one empty final chunk) | `56ba72ac6b2081c17aceb7b1a32698c8` | `11d1ae184bce65726ef2766bc93f968b7098f631fb6dc01ef844d7f8990c4f98` | `4750b2152de2f8bcee455ed0f43775b91026524bb7b71dd6c580da55379a0900` |
| V2 | 2 WAL segment, ClusterBackup (4) | `33` x16, `44` x16, 7, 2 | the 39 ASCII bytes `synthetic WAL segment, ADR-012 vector 2` | `b3d161759f60bc6cb1769cf510998905` | `a77531001dcf43265464ea9fd68cbdedbbc946a442be8a05d9f8b963f533150a` | `fe4f9a4dc50d6be5ca06a125a8b4faca0e4a3cd8c26c0b46fdeae29d9fd6ed29` |

The test checks each digest and each header field at its offset. It opens each container through `open_container`, and again by hand: the data key through `fstp_keys::envelope::open_key` under the context (owner, chain, purpose `Backup`, group, generation, container id), and each chunk under `header | index u64 | final u8`. A changed header byte and another key pair are refused. The test also reads this record, so the values here and in the test cannot drift apart. No multi-chunk vector is recorded, since a 1 MiB constant is too large. `r_cr_01_container_round_trips_under_the_hybrid_kem` covers two chunks.

### Object names

- Object keys hold only the cluster id or cell id, random backup and snapshot ids, part numbers and WAL segment names. They hold no tenant name and no host name.
- Interim, pending Daniel: `<cluster>/base/<backup id>/<part>`, `<cluster>/wal/<segment name>` and `<cell>/keystore/<snapshot id>`.
- WAL segment names are parsed by `wal_name_parse`, fuzzed from the first commit.

### S3 subset

`fstp-backup` contains an in-house SigV4 client over `fstp-http` and `fstp-tls`. It adds no third-party crate.

| Operation | Use |
| --- | --- |
| `PutObject` | WAL segments and small containers |
| `GetObject`, `HeadObject` | Restore, standby replay and upload checks |
| `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` | Base backups and large containers |

- No `DeleteObject` call exists. Old backups are deleted only by bucket lifecycle rules (ADR-005 amendment).
- No listing call exists in M3. See "Finding the newest backup" below.
- Response bodies go through an in-house XML subset parser for exactly three shapes: the multipart create result, the multipart complete result, and the error document.
- The parser refuses a DTD, an entity declaration and a processing instruction. Whether it must accept the five predefined XML entity references depends on how OVHcloud escapes quotes in ETag values (ADR-005 verify item V16). It accepts nothing beyond those five.
- Response bodies have a fixed size bound. Its value: Record at first use.
- `s3_xml_decode` is fuzzed from the first commit.
- Each request signs the payload SHA-256 in `x-amz-content-sha256`, if the service verifies it (V16). On restore, the AEAD tag of every chunk authenticates the content in any case.
- Buckets are created with object lock in an EU region that supports it (V14). Credentials are scoped per cell where the service allows it (V15).
- This link is authenticated by request signatures over server-authenticated TLS. R-NF-09 is not claimed for it until Q34 is answered.

### Keystore snapshots

- A snapshot holds the `keystore.root`, `keystore.group_key`, `keystore.data_key` and `keystore.erasure_intent` rows of one database.
- It holds no root material, which never leaves custody (I-80). It holds wrapped epoch seal keys and sealed group secrets, which open only while their epoch lives.
- Erasure step 5 takes a snapshot and verifies it. A scratch restore opens a sample of live keys under the new root epoch. The old root epoch is destroyed only after that check passes (step 6).
- A daily snapshot is taken as well.

**Writer and upload.** Interim, pending Daniel. The first draft named no process for this, and `fstp-backup` works per cluster with no per-cell role.

- `fstp-cell` writes the snapshot of the keystore in `c_<cell>`. `fstp-vault` writes the snapshot of the keystore in `v_<cell>`. Each reads its own rows through its own `keys` role (ADR-011) and seals the container itself.
- Each process uploads its own snapshot to `<cell>/keystore/<snapshot id>`, using the S3 subset of this ADR as a library. The credential is per cell and covers only that prefix, where the service allows it (V15).
- Neither `Destination` nor `VaultDestination` (ADR-009) has an object storage member. This needs `Destination::KeystoreSnapshots` and `VaultDestination::KeystoreSnapshots`. ADR-009 lists both as proposed by this ADR. No code opens such a connection before Daniel accepts them.
- The operations are `PutObject`, the multipart calls, `GetObject` and `HeadObject` on that prefix only. `GetObject` serves the verification below.

**Verification before the old epoch dies (ADR-004 step 5).**

- App chain: `fstp-cell` fetches the uploaded snapshot back, opens the container under the CellBackup chain, and opens a sample of live keys from that scratch copy under `R(e+1)`. `fstp-cell` holds both chains, so this needs no other process.
- Vault chain: under the first draft, the vault cannot open a container sealed to CellBackup, and `fstp-cell` cannot open vault keys. No process can run the check. Two options:
  - (A) A vault-held snapshot key. The vault seals its snapshots to a backup group under its own custody entry, such as a `Backup` purpose on the Vault chain that never takes part in erasure, or a separate `VaultBackup` chain. The vault then verifies its own snapshot as `fstp-cell` does. This keeps vault keys apart from application keys (R-NF-08). It needs an ADR-004 amendment for the purpose or chain code.
  - (B) A joint check. `fstp-cell` fetches and opens the container and passes the inner rows to the vault over the internal mTLS API. The vault opens a sample under `S(e+1)`. The cell learns no vault key, but this adds a vault operation outside `overview.md`'s list.
  - Proposed: option A. Interim, pending Daniel: until one is accepted, no Vault chain rotation passes step 5, so no Vault chain epoch is destroyed. Document verifications then cannot become provisional (ADR-004 part 2), which adds to the M3 limits that ADR-008 records.

### Restore rule

- Data tables may come from any backup point.
- Key rows follow the restore rule of ADR-004. Key rows are keyed by stable ids. For each key row, a restore uses the newest available copy: the live store first, then the newest keystore snapshot, then the restored backup's own row.
- The restored backup's own row matters when the restore point lies after the newest snapshot. Keys created in that interval exist only there.
- An old keystore copy cannot open keys whose group later rotated. That is how I-81 holds against old backups.
- No restore brings back a destroyed root epoch, because custody holds no other copy. For OKMS this rests on ADR-004 verify item K4.
- Before serving, a restored cell and its vault each verify their chain against the witness and resolve any in-doubt prepare (ADR-010).
- A production restore replays WAL to the newest archived position. Entries committed after that position were receipted by the witness but are missing from the restored chain. The verifier reports them, never silently (ADR-010). Each report needs a tenant admin acknowledgement (design risk R9).
- A restore to an earlier point loses more receipted entries, which are reported the same way. Restore drills into scratch clusters never serve requests and never write to the production witness.

### Declared restores at the witness

ADR-010 leaves to this ADR how a known restore is recorded at the witness, so that it is told apart from tampering. Everything in this subsection is interim, pending Daniel.

- A restore that will serve production is a destructive job under the two-operator rule of ADR-011. The declaration is the job `DeclareRestore`, now listed in ADR-011's job table. Which jobs carry the restore itself is open.
- Before the restored cell or vault serves, `fstp-control` sends the witness `RestoreDeclared { cell, chain, head_n, head_link, job }`. It is composite-signed with the restore declaration key, now listed in ADR-004's signing key placement table. The witness appends it to its per-cell chain, copies it to the second-provider bucket like its other records, and returns a receipt.
- `fstp-control` reaches the witness over mutual TLS with a control-plane CA certificate, for declarations only. ADR-009 now lists it as a witness client.
- The verdict `LostInRestore` is now listed in ADR-010's verifier table.
- The next prepare for that chain must extend the declared head.
- The verifier still lists every receipted link beyond the declared head. With a declaration it reports them as `LostInRestore { from, to, job }`. Without one, the verdict stays `Truncated` or `Deleted`.
- A declaration never removes a finding. Every lost link stays visible to tenant admins and in the auditor view, and each needs a tenant admin acknowledgement. A deletion therefore stays detectable (I-24). The declaration only names its cause.
- A declaration covers only links receipted before it. It cannot cover a later link.
- Self-hosted: there is no control plane. The local witness accepts a declaration only from a root-only console command, which the cell's audit chain also records. ADR-010 open point 7 on host root applies.

### Finding the newest backup

No listing call exists in M3, so a restore needs another way to find the newest base backup.

- Interim, pending Daniel: `fstp-backup` reports each completed base backup to `fstp-control` as a job result, with the cluster id, backup id, time and size. `fstp-control` records it in `cp`. These are cluster facts, not tenant data.
- That record has no metadata register entry yet. It belongs in the `Infrastructure` class that ADR-009 proposes, which Daniel has not settled.
- A self-hosted install has no control plane and no `cp`. Proposed: the local `fstp-backup` keeps an append-only index file of completed base backups on the node, outside the key volume. It holds the same four fields. Interim, pending Daniel.
- WAL segment names follow from the timeline and position, so a restore fetches segments in order until the next one is absent.
- The alternative is a fourth XML shape for `ListObjectsV2`, with its own fuzz coverage.

### WAL-archive standby

- There is no streaming replica (Q4 R1). The standby is a self-operated server of the same cluster kind, on another host. It restores continuously from the sealed archive through `restore_command`, which calls `fstp-backup`.
- The standby follows the same `pg_hba` and role rules as the primary (ADR-005 amendment, ADR-011). Its superuser and replication lines are loopback only.
- Interim, pending Daniel: the standby's `fstp-backup` holds its own custody credential, limited to unwrapping on that cluster's ClusterBackup chain. The writer on the primary still holds the public key only.
- The recovery point objective is about one minute, from `archive_timeout` of 60 seconds plus upload time (ADR-005 amendment).
- Promotion is manual. Interim, pending Daniel: an operator promotes through a `fstp-pgagent` job with a passkey and a step-up, recorded in `cp.job`.
- Whether the standby sits in the same EU region or in a second one is decided with Q25.

### Copies and the second provider

- The primary copy is OVHcloud Object Storage with object lock, in an EU region.
- The second EU-owned provider is decided later with L-15 (Q25, Daniel, 2026-10-28). The options are Scaleway, Hetzner or IONOS, or an OVHcloud primary region pair inside the EU. The design prefers one with object lock.
- Interim, pending Daniel: `fstp-backup` uploads each container to each provider separately, with the same bytes. A container counts as backed up only when every configured copy is complete.
- Until Q25 is decided, one provider holds the copies. The ADR-005 exit row stays blocked.

### Retention

- Retention is decided later with L-15, together with Q25. That covers base backup frequency, WAL retention, and the object lock mode and period.
- Erasure never waits for retention. I-81, R-ID-03 and R-SW-02 hold through key destruction alone.
- After cell erasure, shared-cluster backups still hold the cell's rows until their retention ends. Every tenant byte in them is sealed under a destroyed chain. Only random ids, sequence numbers, times and enums stay readable (`m3-design.md` section 3.7).

### Restore drills

- A monthly job restores the latest backup into a scratch cluster and verifies every cell's chains against the witness.
- The first drill records the recovery time objective in ADR-005.

## Record of lane L10 `prod/backup`

Written by lane L10 on 2026-11-21, before its code, for the single-host pilot of ADR-026 (D1: `fstp-keyd` custody, no control plane). Every row is interim, pending Daniel, unless it says otherwise. The rows fill what this ADR leaves to the first use.

| Topic | Reading | Basis |
| --- | --- | --- |
| Configuration | One JSON object in the file that `FSTP_BACKUP_CONFIG` names, at most 4 KiB, decoded by `fstp_json` with depth and string limits. The member set is closed. Members: `cluster` (32 lowercase hex digits, the `ClusterId` that owns the ClusterBackup group), `credentials_dir`, `state_dir`, `pg_bindir` (absolute paths), `database` (`host`, a loopback address literal, and `port`), `object_store` (`endpoint`, a host name; `port`, optional, 443 by default; `region`; `bucket`) and `keyd_socket` (optional, absolute). The decoder is fuzzed (`backup_config_decode`). A refusal names its rule and never quotes the input | ADR-026 "File"; R-NF-02 |
| Secrets | No secret is in the configuration. The credentials directory holds, by fixed name: `s3-access-key-id`, `s3-secret-access-key` and optionally `s3-ca.pem`; `repl.pem`, `repl.key`, `repl.password` and `db-ca.pem` for `fstp_repl`; and `cluster-backup.key`. Each command reads only the files it needs, so the `postgres` OS user that runs `archive_command` needs no replication credential | ADR-026 "Secrets"; ADR-005 "Superuser and replication" |
| ClusterBackup group key | `fstp-backup init-keys` draws a hybrid KEM key pair (X25519 plus ML-KEM-768 through `fstp-crypto`), a group id and generation 1. It creates a root `{cell: none, chain: ClusterBackup, epoch: 1}` through the `fstp-keyd` socket of `keyd_socket`, which is the console socket (`fstp-keyd` serves ClusterBackup there only). It wraps a fresh seal key `S` under that root and seals the group secret under `S` with AES-256-GCM. No erasure destroys this root. Its rotation is not built | ADR-004; ADR-012 "Writer"; R-CR-01 |
| Key file | `cluster-backup.key` = `"fstp-cluster-backup-v1"` (22) \|\| cluster (16) \|\| group (16) \|\| be32(generation) \|\| be64(epoch) \|\| public key (1216) \|\| be16(len) \|\| custody handle \|\| be16(len) \|\| wrapped `S` \|\| nonce (12) \|\| sealed secret (2432 + 16). The wrap and the seal take the AAD of the bytes before the public key. The writer reads the public key only. Opening needs the root. The decoder is fuzzed (`backup_key_file_decode`) | I-80; ADR-012 "Writer" |
| Base backup | `pg_basebackup -D - -F t -X none -c fast -w --no-manifest` over loopback as `fstp_repl`, with TLS verify-full and the client certificate. The tar stream is cut into parts of 64 MiB of plaintext. Each part is one container of kind 1 with `part` = its index, named `<cluster>/base/<backup id>/<part>`. The WAL it needs comes from the archive, so a base backup restores only with the archived WAL from its start | ADR-012 "Object names"; ADR-005 |
| Upload | A container of at most 32 MiB goes up with `PutObject`, a larger one with the multipart calls in parts of 16 MiB. A failed multipart upload is aborted. No object is deleted | ADR-012 "S3 subset" |
| Base backup index | `<state_dir>/base-backups.index`, append-only, one line per completed base backup: cluster, backup id (32 hex digits each), Unix seconds and plaintext bytes, in decimal, separated by one space. It is written only after the last part is uploaded. The decoder is fuzzed (`backup_index_decode`). A restore without a backup id takes the last line of its cluster | ADR-012 "Finding the newest backup" |
| WAL archive | `archive_command = 'FSTP_BACKUP_CONFIG=<file> fstp-backup wal-archive %p %f'`. A segment is named by `parse_wal_name`, and a timeline history file `<8 hex>.history` is archived under `<cluster>/wal/` too. A backup history file (`.backup`) and a `.partial` file are skipped with success. A name already in the store (`HeadObject`) is not uploaded again | ADR-012 "Object names"; PostgreSQL archive rules |
| Restore | `fstp-backup restore <new data dir> [<backup id>]`, run as root, opens the key file through the console socket. It fetches the parts in order, checks kind, cluster, part number and total size, and extracts the tar with the host's `tar`. It then fetches the archived segments from the start segment named in `backup_label`, on that timeline, until the next one is absent, into `pg_wal`. PostgreSQL then replays them at its next start. A restore that crosses a timeline switch is not built | ADR-012 "Restore rule" |
| Standby | `restore_command = 'FSTP_BACKUP_CONFIG=<file> fstp-backup wal-restore %f %p'` fetches and opens one segment or history file. A missing one exits with status 1. It needs custody access to the ClusterBackup root, which `fstp-keyd` grants only to the console socket. So the pilot has no continuous standby, and this command serves manual archive recovery as root | ADR-012 "WAL-archive standby" |
| S3 requests | Path-style URLs `https://<endpoint>:<port>/<bucket>/<key>`. SigV4 over HMAC-SHA256 and SHA-256 from `fstp-crypto`, with the signed headers `host`, `x-amz-content-sha256` and `x-amz-date`. The payload hash is always signed. TLS verifies the endpoint against the public roots plus `s3-ca.pem` | ADR-012 "S3 subset"; ADR-009 |
| Response bounds | Record at first use: an XML response body of at most 16 KiB, at most 64 elements, depth 4, names of at most 64 bytes and texts of at most 2048 bytes. The parser takes an optional XML declaration at the very start, the five predefined entity references and nothing else: no DTD, comment, CDATA, processing instruction or numeric character reference | ADR-012 "S3 subset"; V16 |
| Second provider | One `object_store` only, until Q25 | Q25 |
| Keystore snapshots | Not built by this lane. `fstp-cell` writes them (ADR-012 "Keystore snapshots"), and the cell's I-81 holds through key destruction alone | ADR-012 |
| Exit status | 0 on success, 1 for a failure or a missing WAL file, 2 for a refused configuration or argument. No line names a secret | R-NF-02 |

Tests: `r_cr_01_*`, `i81_*`, `r_nf_02_*` and `adr012_*` in `crates/fstp-backup` and `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs`.

## Record of lane L11 `prod/vault-erase`

Written by lane L11 on 2026-11-21. Interim, pending Daniel. It departs from the interim line under "Keystore snapshots" that no Vault chain rotation passes step 5 before option A or B is accepted.

- On the single-host pilot, the vault keystore rows live in `v_<cell>` on the vault cluster. That cluster's base backups and WAL archive (record of lane L10) are the copies a restore reads.
- Step 5 of a Vault chain rotation therefore reads the committed rows back from the database and opens them under `R(e+1)` through custody: every group secret, data key and identity tuple. No separate snapshot container is written, and no `VaultDestination::KeystoreSnapshots` connection is opened.
- Option A or B still decides how a vault snapshot container is sealed, once one is written. ADR-004 records the rotation itself (record of lane L11).

## Record of lane L16 `prod/backup-custody`

Written by lane L16 on 2026-11-21, before its code, for the single-host pilot of ADR-026 (D1). It closes "a key held outside this host" in the record of lane L10. The custody side is recorded in ADR-004 (record of lane L16).

Decided by Daniel on 2026-11-21: on the pilot, the key that opens every backup must survive the loss of the host, by both of the following. (1) An off-host sealed copy of the `fstp-keyd` state, with an operator command to make it, an import onto a fresh host and a runbook. It respects erasure: a destroyed root epoch never comes back from an old copy. (2) A second custodian: a second `fstp-keyd` on another machine holds its own custody of the ClusterBackup chain, with a key ceremony as an operator command and a runbook. (3) `zeroize` may be used in `fstp-backup` (ADR-001 record of 2026-11-21).

Every row below is interim, pending Daniel, unless it says otherwise.

| Topic | Reading | Basis |
| --- | --- | --- |
| Second custodian | A second `fstp-keyd` entry on another machine, reached through its own console socket. It never receives a root of the first host. It creates its own ClusterBackup root and holds its own hybrid KEM key pair, the custodian key. The first host seals the ClusterBackup group secret to that key's public half. So a root never leaves either custody (I-80), and the group secret travels only sealed through the hybrid KEM (R-CR-01) | Daniel 2026-11-21 (2); I-80 |
| Custodian key file | `custodian.key` in the second host's credentials directory has the layout of `cluster-backup.key` with the magic `"fstp-backup-custodian1"` (22 bytes). Its group field is a random custodian id. Its root is `{cell: none, chain: ClusterBackup, epoch: 1}` in the second `fstp-keyd`. The two magics keep a custodian key from being read as a group key file, and the reverse. The decoder is fuzzed (`backup_key_file_decode`) | ADR-012 record of lane L10 "Key file" |
| Custodian request | `custodian.pub` = `"FCP1"` \|\| version u8 = 1 \|\| cluster (16) \|\| custodian id (16) \|\| custodian public key (1216). It holds no secret. The operator compares its SHA-256 on both hosts before the escrow step. The decoder is fuzzed (`backup_custodian_decode`) | R-CR-01 |
| Escrow container | `cluster-backup.escrow` is one ADR-012 container of the new kind 4, "custodian escrow", on the ClusterBackup chain. The owner is the cluster, the group is the custodian id, the generation is 1 and the part is 0. It is sealed to the custodian public key. Its plaintext is group (16) \|\| be32(generation) \|\| group public key (1216) \|\| group secret key (2432), exactly 3668 bytes. The plaintext decoder is fuzzed (`backup_custodian_decode`) | ADR-012 "Container format"; R-CR-01 |
| Opening on the second host | When the credentials directory holds `cluster-backup.escrow`, the restore commands open `custodian.key` through the configured console socket, open the escrow with it, and check that its group, generation and public key are those of `cluster-backup.key`, and that the secret's public half is that public key. The second host keeps a copy of `cluster-backup.key`, which holds the public key and a secret sealed under the first host's root only | ADR-012 "Restore" |
| Ceremony | `fstp-backup custodian-init` on the second host writes `custodian.key` and `custodian.pub`. `fstp-backup custodian-escrow <custodian.pub> <out file>` on the first host opens the group secret through its console socket and writes the escrow. Both run as root. Neither writes a line of its own (R-NF-02). The operator carries both files and `cluster-backup.key` by hand, then runs a restore drill on the second host | Daniel 2026-11-21 (2) |
| Erasure and the second custodian | The second custodian holds only a ClusterBackup root and its custodian key. ClusterBackup is never rotated or destroyed by erasure (ADR-004 part 2 "Chains"). `custodian-init` creates only that chain, and the console role reaches no App or Vault chain. So no root epoch that an erasure destroys is ever held there, and none opens from it (I-81) | I-81; ADR-004 "Chains" |
| What the second custodian restores | The cluster's base backups and WAL. The rows inside that are sealed under the App and Vault chains open only with those chains' roots. Those come from the off-host copy of their `fstp-keyd` entries (ADR-004 record of lane L16). After the loss of the host, a full restore needs both | Daniel 2026-11-21 (1), (2) |
| Rotation of the ClusterBackup group | Not built. A new group generation needs a new escrow for each custodian | ADR-004 "Chains" |
| Zeroize | `fstp-backup` wraps every plain copy of a group secret in `Zeroizing`: the escrow plaintext on both sides and the secret bytes before they are sealed. `HybridSecretKey`, `SealKey` and the KEM shared secret already wipe on drop in `fstp-crypto` and `fstp-custody` | Daniel 2026-11-21 (3); ADR-001 A1 |

Tests: `i80_second_custodian_never_receives_a_root`, `i81_second_custodian_holds_no_erasable_root`, `i80_i81_host_loss_restore_from_the_second_custodian`, `i80_escrow_never_holds_the_group_secret_in_the_clear` and `adr012_custodian_files_round_trip` in `crates/fstp-backup/tests/second_custodian.rs`. The off-host copy has its tests in `crates/fstp-keyd` (ADR-004 record of lane L16).

## Record of lane L17 `prod/vault-snapshots`

Written by lane L17 on 2026-11-21, before its code. It closes the open point "Keystore snapshot path, tied to ADR-004 erasure step 5" for the single-host pilot of ADR-026 (D1). The chain and the key files are recorded in ADR-004 (record of lane L17). Every row is interim, pending Daniel, unless it says otherwise.

Decided by Daniel on 2026-11-21: (1) option A of "Keystore snapshots", a vault-held snapshot key. The vault seals its snapshots to a backup group under its own custody entry and verifies its own snapshot as `fstp-cell` does for the App chain. (2) Accepting option A also accepts the two proposed destinations `Destination::KeystoreSnapshots` and `VaultDestination::KeystoreSnapshots` (ADR-009). (3) The reading of lane L11, which reads committed rows back from the database, stays only as the fallback of a pilot with no bucket configured.

| Topic | Reading | Basis |
| --- | --- | --- |
| Vault snapshot key | Decided by Daniel on 2026-11-21: option A. The group of `vault-snapshot.key` on the new VaultBackup chain (code 6), in the vault's own `fstp-keyd` entry. This lane chose a chain over a `Backup` purpose on the Vault chain. ADR-004 (record of lane L17) gives the reasons | Daniel 2026-11-21 (1); R-NF-08 |
| Destinations | Decided by Daniel on 2026-11-21: `Destination::KeystoreSnapshots` and `VaultDestination::KeystoreSnapshots` are accepted. Each reaches the configured object store only, for the `<cell>/keystore/` prefix | Daniel 2026-11-21 (2); ADR-009 |
| Container kinds | Kind 3 stays the App keystore snapshot, on CellBackup (3). New kind 5, "vault keystore snapshot", on VaultBackup (6). The data key's purpose is `Backup` (5) for both. The decoder now also refuses a chain that is not the kind's chain, so each kind has one spelling | ADR-012 "Container format" |
| App plaintext | The keystore image `"FKI1"` of `fstp_cell::tasks::erasure::snapshot`, already fuzzed (`keystore_image_decode`). It holds roots, group secrets, data keys, texts and the login digests, all sealed | Lane F-ERASE |
| Vault plaintext | The vault keystore image `"FVK1"` of `fstp_vault::snapshot`: `"FVK1" \| version u8 = 1 \| cell 16 \| n u32 \| root* \| n u32 \| group* \| n u32 \| key* \| n u32 \| tuple* \| has_intent u8 \| intent?`. `root = epoch u64 \| backend u8 \| state u8 \| created_at i64 \| len u16 \| handle \| len u16 \| wrapped \| len u16 \| receipt`, where an empty receipt is none. `group = group 16 \| generation u32 \| purpose u8 \| epoch u64 \| len u32 \| public \| len u32 \| sealed`. `key = id 16 \| group 16 \| generation u32 \| sealed 1210`. `tuple = identity 16 \| group 16 \| len u32 \| envelope`. `intent = id 16 \| phase i16 \| len u32 \| plan`. Integers are big-endian. Rows are strictly increasing by epoch, by group and generation, by id and by identity, so the decoder admits one spelling only. It bounds every length and refuses trailing bytes. Fuzzed (`vault_keystore_image_decode`) | ADR-012 "Decoder" |
| Object names | `<cell>/keystore/<snapshot id>`, both in 32 lowercase hex digits. The snapshot id is the container id. Both processes write under this prefix. The container's kind and its sealed key's chain tell the two apart | ADR-012 "Object names" |
| Newest snapshot | No listing call. After a snapshot verifies, the process writes its id, exactly 16 bytes, to `<cell>/keystore/latest-app` or `<cell>/keystore/latest-vault`. A restore reads it. A bucket with object lock is versioned (V14), so the write adds a version and deletes nothing. The reader accepts exactly 16 bytes. A wrong pointer names a snapshot that fails to open or opens an older copy, which the restore rule below refuses or ranks lower | ADR-012 "Finding the newest backup" |
| Configuration | Optional member `object_store` in the cell and the vault configuration, of the shape `fstp-backup` uses: `bucket`, `endpoint` (a host name), `port` (optional, 443) and `region`. The credentials directory holds `s3-access-key-id`, `s3-secret-access-key` and optionally `s3-ca.pem`, by those fixed names. The credential is per cell and limited to `<cell>/keystore/` where the service allows it (V15) | ADR-012 "Writer and upload"; usability rule |
| Writer | Step 5 "take": `fstp-cell` encodes its keystore image, and `fstp-vault` reads its committed rows back over the keys login and encodes them. Each seals one container to its own snapshot group's public key and uploads it, with `PutObject` up to 32 MiB and the multipart calls above, as lane L10 does | ADR-012 "Writer and upload" |
| Verification | Step 5 "verify": `GetObject` of that name. The container opens with the snapshot group secret, which custody unwraps through the snapshot root. The image decodes. Then custody unwraps `S(e+1)` from the image's own root row. Every live group secret, data key and tuple of the vault image opens under it. On the App chain every signing key and a data key open, as before. Only then does the planner record step 5, so only then can step 6 destroy `R(e)` | ADR-004 step 5; I-81 |
| Failure | A missing object, a container that does not open, an image that does not decode, or a row that does not open fails the step. The stored phase stays and `R(e)` lives. The next attempt takes and uploads a fresh snapshot. The vault's batch completes at its next run or start, and the cell's task retries after its idle wait | I-81; R-KY-02 |
| Pointer | The pointer is written after the check passes and before the planner records step 5. A failed pointer write fails the step, which is retried. So the pointer never names a snapshot that did not verify | ADR-012 "Finding the newest backup" |
| Fallback | Decided by Daniel on 2026-11-21: with no `object_store` configured, the vault keeps lane L11's reading (the committed rows read back from the database) and the cell keeps its in-memory copy. That pilot's restore rests on the cluster's base backups and WAL archive alone (record of lane L10). Interim, pending Daniel: the start reports nothing for it, since the configuration states it | Daniel 2026-11-21 (3) |
| Restore rule, vault | `fstp_vault::snapshot::restore_order` ranks the copies: a live keystore first, then by the epoch of the copy's current root, higher first. At an equal epoch the restored backup ranks above the snapshot, since the only snapshot of an epoch is the one step 5 took before the backup's rows. The restore takes the first copy whose rows all open through custody, whole. It never mixes rows of two copies: a mix could bring back a key that a later rotation dropped, or pair rows with a chain state that does not name them. Keys created after the snapshot exist only in the backup, which then ranks first | ADR-012 "Restore rule" |
| Restore command | `fstp-vault restore-keystore [<snapshot id>]`, with the vault stopped, after `fstp-backup restore` of the vault cluster. It takes the keystore lock and reads the restored rows. It fetches the named snapshot, or the one `latest-vault` names, and applies the rule above. It writes the chosen copy in one transaction of the keys login. It exits 0 when a copy opens, 1 when none does or a step fails, and 2 for a refused argument or configuration. It prints nothing (R-NF-02). `fstp-admin` (lane L19) wraps it | Usability rule; R-NF-02 |
| Restore rule, App | Not built by this lane. The App image of each snapshot opens through `fstp_cell::tasks::erasure::snapshot` as before | ADR-012 "Restore rule" |
| Daily snapshot | Not built. The serving vault holds the keystore lock for its lifetime, so a timer command cannot run beside it, and neither process has a daily task yet. Each rotation takes its snapshot, and the WAL archive covers the rows between rotations | ADR-012 "Keystore snapshots" |
| Erased identities | A snapshot holds `T(X)` sealed to its `Attribute` generation, whose secret is sealed only under epochs that step 6 destroys. So no snapshot opens an erased identity's tuple or facts once its batch completes (I-81, ADR-004 record of lane L13) | I-81 |

Tests, written before the code. In `crates/fstp-vault/tests/snapshots_pg.rs`, over PostgreSQL and the fake S3 of lane L10: `i81_vault_old_epoch_dies_only_after_a_fetched_snapshot_opens`, `i81_vault_tampered_snapshot_blocks_destroy`, `i81_vault_missing_snapshot_blocks_destroy`, `i81_vault_erased_identity_unreadable_from_every_snapshot` and `adr012_vault_restore_takes_the_newest_copy_that_opens`. In `fstp_vault::snapshot`: `adr012_vault_keystore_image_round_trips_in_one_spelling` and `adr012_vault_restore_order_ranks_live_then_epoch_then_backup`. In `crates/fstp-backup/tests/keystore_snapshots.rs`: `r_nf_08_snapshot_keys_never_open_each_other`, `adr004_snapshot_key_files_decode_only_under_their_magic`, `adr012_snapshot_upload_and_fetch_round_trip` and `adr012_snapshot_pointer_is_exactly_sixteen_bytes`. In `crates/fstp-cell/tests/erasure_runner.rs`: `i81_app_old_epoch_dies_only_after_a_fetched_snapshot_opens` and `i81_app_tampered_snapshot_blocks_destroy`. Also `i81_snapshot_dies_with_its_snapshot_root` in `crates/fstp-backup/tests/keystore_snapshots.rs`, `adr012_vault_config_takes_an_optional_object_store`, `adr012_cell_config_takes_an_optional_object_store` and `adr012_vault_restore_keystore_takes_an_optional_snapshot_id`. Built by lane L17 on 2026-11-21 as written above, with the changes in "Built" below.

**Built.** Two readings changed while building. (1) On the App chain, the fetched image is checked under `R(e+1)` for every group secret sealed under `S(e+1)` and one data key. Group rows of the batch's old generations are still in the image under the old epoch, and they die with it at step 6. The image holds no signing key rows yet (lane F-ERASE), so the signing keys are still checked on the in-memory copy. (2) The vault check also opens the sealed chain state of the intent row, so a restore never keeps rows whose chain state does not open.

## Record of lane L27 `prod/snapshot-ops`

Written by lane L27 on 2026-11-22, before its code. It closes points 2, 3 and 6 that lane L17 left open: the daily snapshot, the App chain restore command, and `fstp-admin`'s use of snapshots (ADR-028 record of lane L27). Every row is interim, pending Daniel, unless it says otherwise.

Lead readings, 2026-11-22, of lane L17's other open points:

- **Pointer object.** Lead reading, 2026-11-22: keep the pointer objects `latest-app` and `latest-vault`. The production reference says the bucket must be versioned, which object lock needs anyway (ADR-005 V14).
- **Yearly re-wrap.** Lead reading, 2026-11-22: no yearly re-wrap of the CellBackup and VaultBackup snapshot keys yet. It is a later item.
- **Key records.** Lead reading, 2026-11-22: no `RecordKeyOp` for an unwrap of a snapshot key, as for the root of the cell key file (ADR-004 record of lane L4).

| Topic | Reading | Basis |
| --- | --- | --- |
| Daily snapshot | Each serving process takes and verifies a keystore snapshot from inside the process, since it holds the keystore lock. It uploads, fetches back and opens the snapshot as step 5 does, with no rotation: the current root `R(e)` stays and nothing is destroyed. The first runs a minute after the start, then one runs every 24 hours. After a failure the next try comes after one hour | Daniel's brief of 2026-11-22; I-81 |
| Where it runs | `fstp-cell`: the erasure task, while no batch runs, so a snapshot never sees a half-written batch. `fstp-vault`: a task beside the keystore watch, which reads the rows through the registrar's keys connection under the registrar's lock, then works without the lock | ADR-004 record of lane L13b, row "Watch" |
| Event | One typed event per snapshot: `keystore_snapshot` with `chain` (`app` or `vault`), `trigger` (`rotation` or `daily`) and `outcome` (`verified` or `failed`). It names no id, path or key (R-NF-02) | R-NF-02 |
| Status file | `keystore-snapshot.status` in the process's credentials directory, beside its snapshot key file: one line `v1 <last verified> <last failed>`, Unix seconds, 0 for never. The process rewrites it after each snapshot, step 5 included, through a temporary file and a rename. `fstp-admin status` reads it. The codec is `fstp_obs::snapshot_status`, so the writers and `fstp-admin` share it without `fstp-admin` reaching custody. The decoder accepts exactly this form and is fuzzed (`snapshot_status_decode`, in the fuzz project of `fstp-admin`) | ADR-028 "Status" |
| App plaintext | The App snapshot now holds the keystore tables whole: the new image `"FAK1"` of `fstp_cell::tasks::erasure::rows_image`, every row of the nine `keystore` tables of `fstp_pgstore::KeystoreRows`. `"FKI1"` held no signing keys and no chain state, so a restore could not rebuild a keystore from it. `"FKI1"` stays for the test worlds. Fuzzed (`app_keystore_image_decode`) | ADR-012 "Restore rule" |
| App check | Step 5 and the daily snapshot load the fetched rows as a keystore, unwrap `S(e)` from their own root row through custody, open the sealed chain state and every current group secret, every current signing key, and one data key. This replaces lane L17's group-and-one-key check | ADR-004 step 5 |
| App restore | `fstp-cell restore-keystore [<snapshot id>]`, with the cell stopped, after `fstp-backup restore` of the application cluster. The rule is the vault's (record of lane L17, row "Restore rule, vault"): a live keystore first, then the copy at the higher chain epoch, the restored backup above the snapshot at an equal epoch. The first copy that opens is taken whole and written in one transaction of the keys role. No prompt, and nothing printed. Exit 0 when a copy opens, 1 when none does or a step fails, 2 for a refused argument or configuration | ADR-012 "Restore rule" |
| Restore order | `fstp-admin restore` restores both clusters, starts the two database clusters and the custody entries, runs `fstp-vault restore-keystore`, then `fstp-cell restore-keystore`, then starts the rest. The vault comes first, as in the start order | ADR-028 record of lane L27 |
| Status on the System page | `fstp_obs::host_status` of lane L20 was not on `main` when this lane started. `fstp_admin::status::snapshot_status` returns the fields it needs, the last verified snapshot of each process and whether the last try failed. The host status file takes them when lane L20 merges | Lane L20 |

Tests, written before the code: `adr012_snapshot_status_file_round_trips_in_one_spelling` and `adr012_daily_snapshot_is_due_daily_and_retried_hourly` in `fstp_obs::snapshot_status`; `i81_vault_daily_snapshot_verifies_without_a_rotation` and `adr012_vault_daily_snapshot_failure_shows_on_status` in `crates/fstp-vault/tests/snapshots_pg.rs`; `i81_app_daily_snapshot_verifies_without_a_rotation`, `adr012_app_snapshot_holds_the_keystore_tables_whole` in `crates/fstp-cell/tests/erasure_runner.rs`; `adr012_app_restore_takes_the_newest_copy_that_opens` in `crates/fstp-cell/tests/keystore_tables.rs`; `adr012_app_keystore_image_round_trips_in_one_spelling` and `adr012_cell_restore_keystore_takes_an_optional_snapshot_id` in `fstp-cell`; `r_nf_02_keystore_snapshot_event_names_no_id` in `fstp-obs`.

## Record of lane L26 `prod/display-names`, 2026-11-22

Each row is a lane reading, pending Daniel.

| Topic | Reading | Basis |
| --- | --- | --- |
| Display names in the App image | `"FAK1"` version 2 adds the rows of `keystore.display_name` (migration `0012_display_name.sql`, ADR-004 section "Written by lane L26"): account, text and fingerprint per name. The table is not derivable from the texts alone, since only it names the account of each name. So a restore from a snapshot keeps every display name and its uniqueness. The decoder still reads version 1 as an image with no display name. The restore's changes (`fstp_cell::tasks::erasure::restore::changes_to`) and `Keystore::table_rows` carry the rows too | SA-11 amendment; record of lane L27, row "App plaintext" |
| System page | The last verified snapshot and the failure of each process reach the host status file and the System page (ADR-028 record of lane L26). This closes the row "Status on the System page" of lane L27 | ADR-028 |

Tests: `sa11_app_keystore_image_carries_the_display_name_index` (`fstp_cell::tasks::erasure::rows_image`); `adr012_app_restore_takes_the_newest_copy_that_opens` with the display rows in its tables (`crates/fstp-cell/tests/keystore_tables.rs`).

## Consequences

- No third-party crate is added.
- Fuzz targets of `fstp-backup`: `backup_container_decode`, `s3_xml_decode` and `wal_name_parse`. They check that nothing panics, that chunk order and the final flag are enforced, and that DTDs, entity declarations and processing instructions are refused.
- Tests: `i81_erased_text_unrecoverable_from_every_backup`, `r_id_03_document_unrecoverable_after_verification`, `r_sw_02_cell_erasure_kills_every_backup`, `i81_erased_email_digest_cannot_be_recomputed_from_backups`, `i81_erased_identity_match_key_cannot_be_recomputed_from_backups` and `i80_root_canary_absent_from_logs_dumps_and_backups`. Lane W2k also adds container property tests.
- Lane W2k starts only after Daniel accepts this ADR. He accepted it on 2026-10-28.

## Open points

- The second provider, its regions and the retention values (Q25, L-15).
- The proposed container bytes (`FBC1`) need Daniel's acceptance. The test vectors are recorded (Record: container test vectors), late: the writer landed first.
- How a restore finds the newest base backup: a `cp` record or a listing call. The `cp` record needs an `Infrastructure` register entry (ADR-009), and self-hosted installs need the local index or the listing call.
- **Keystore snapshot path, tied to ADR-004 erasure step 5.** Decided by Daniel on 2026-11-21: option A and both `KeystoreSnapshots` destinations. Built by lane L17 (record of lane L17). Still open: the daily snapshot, the restore command of the App chain, and the yearly re-wrap of the snapshot keys.
- **Declared restores.** The `RestoreDeclared` statement, the restore declaration key (ADR-004 placement table), the `DeclareRestore` job (ADR-011), `fstp-control` as a witness client (ADR-009) and the `LostInRestore` verdict (ADR-010). Each is entered in its ADR as interim, pending Daniel, and they stand or fall together. Which jobs carry the production restore itself is also open.
- The standby's custody credential, its region and the promotion approval.
- The response size bound: Record at first use.
- OVHcloud facts this ADR relies on: ADR-005 verify items V14, V15 and V16, and ADR-004 verify item K4.

## Record of lane `m10/guard-key`, 2026-11-23: the guard on the second custodian

Daniel decided on 2026-11-23 that the second custodian of the record of lane L16 becomes required and also holds the guard of the key copies. The custody side is in ADR-004 ("The guard key of Q-L16-1 (F-018)"), the operator side in ADR-028 (record of lane `m10/guard-key`). Every row is interim, pending Daniel, unless it says otherwise.

| Topic | Reading | Basis |
| --- | --- | --- |
| The second custodian | The same `fstp-keyd` entry on another machine as in the record of lane L16. It now also serves the guard link over mutual TLS on port 7460, and must stay on. Its console socket and its ClusterBackup escrow are unchanged | Decided by Daniel on 2026-11-23 |
| Key copies | Every off-host copy of a pilot `fstp-keyd` entry is sealed once more to that entry's guard. A copy older than the last destroy of its entry no longer opens, wherever it is kept. So an old copy, its passphrase and a base backup of the same age open no data erased later (I-81, TH-30) | ADR-004 record of lane `m10/guard-key` |
| The custodian's own volume | Never copied. `fstp-keyd export` refuses a volume that holds a guard. The escrow files of the record of lane L16 hold no guard | I-81 |
| Restore | A full restore after the loss of the pilot host needs the custodian online to open the key copies, and either the cluster backups through its escrow or the copies of the backup chains. The restore order of the record of lane L27 is unchanged | ADR-012 record of lane L27 |
| Loss of the custodian | The base backups and WAL still open through the pilot's own entries while the pilot lives. The operator pairs a new custodian, makes new key copies at once, and runs the escrow ceremony again | ADR-004 record of lane `m10/guard-key` |
| The custodian's copy | Decided by Daniel on 2026-11-24 (Q-F018-4): after each guard rotation the pilot entry sends a fresh guarded copy to the custodian by itself. The custodian keeps one per entry, sealed to the entry's current guard, and deletes it at the next rotation. It cannot open the inner copy, which the pilot's passphrase seals. So a host loss right after an erasure loses no key, and the operator has no step. ADR-004 records the design ("The custodian's copy") | Q-F018-4; I-80; I-81 |
| Restore after host loss | Decided by Daniel on 2026-11-24 (Q-F018-5): `fstp-admin restore-keys <dir>` imports the key copies, taking each from `<dir>` or else from the custodian, and `fstp-admin restore` then releases them with the epochs of the restored databases. ADR-028 records the steps (record of lane `m10/guard-key`, part 2) | Q-F018-5 |
