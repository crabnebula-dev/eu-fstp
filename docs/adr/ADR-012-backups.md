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
- `kind`: 1 base backup file, 2 WAL segment, 3 keystore snapshot.
- `chain`: the ADR-004 code for ClusterBackup (4) or CellBackup (3). `owner` is the `ClusterId` for ClusterBackup and the `CellId` for CellBackup, as in ADR-004.
- `container` is a random id. It is also the id of the data key, so it is the `object` of the sealed key's context.
- `part` numbers the parts of a split container from 0. A container that is not split has `part = 0`.
- `chunk_size` is 1 MiB (1 048 576). Version 1 accepts no other value.
- `sealed_key` is the data key in the 1210-byte `FSK1` form of ADR-004, sealed to the chain's group key. The purpose code for backups comes from the ADR-004 purpose table: Record at first use.
- Each chunk is sealed with AES-256-GCM through `fstp_crypto::aead::seal`, which draws a random 96-bit nonce. The nonce is stored in the chunk.
- The AAD binds each chunk to its container, its position and its final flag. A chunk moved, reordered or relabelled fails to open.
- Test vectors: Record before lane W2k's first production commit, in this ADR.

Rules:

- **Data key:** fresh for every backup attempt, every WAL segment and every snapshot, so a retried upload never reuses a key. Its hybrid sealing, X25519 plus ML-KEM-768 (ADR-004), meets R-CR-01.
- **Writer:** `fstp-backup` holds only the group's public key, so the writer cannot decrypt what it wrote.
- **Seal limit:** a container whose chunk count would reach the 2^24 hard limit of ADR-004 is split. Each part gets its own data key.
- **Decoder:** one spelling only. `final` is 0 or 1. A non-final chunk has `len` equal to `chunk_size`, and the final chunk has `len` at most `chunk_size`. Exactly one chunk is final, and it is the last. Bytes after it are refused. A missing final chunk is reported as truncation.
- **Opening:** needs the group secret, which opens only through the chain's current epoch seal key, unwrapped through custody. `fstp-control` holds the ClusterBackup chain and `fstp-cell` the CellBackup chain (ADR-004). The key that seals vault snapshots is an open point (Keystore snapshots).

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

## Consequences

- No third-party crate is added.
- Fuzz targets of `fstp-backup`: `backup_container_decode`, `s3_xml_decode` and `wal_name_parse`. They check that nothing panics, that chunk order and the final flag are enforced, and that DTDs, entity declarations and processing instructions are refused.
- Tests: `i81_erased_text_unrecoverable_from_every_backup`, `r_id_03_document_unrecoverable_after_verification`, `r_sw_02_cell_erasure_kills_every_backup`, `i81_erased_email_digest_cannot_be_recomputed_from_backups`, `i81_erased_identity_match_key_cannot_be_recomputed_from_backups` and `i80_root_canary_absent_from_logs_dumps_and_backups`. Lane W2k also adds container property tests.
- Lane W2k starts only after Daniel accepts this ADR. He accepted it on 2026-10-28.

## Open points

- The second provider, its regions and the retention values (Q25, L-15).
- The proposed container bytes (`FBC1`) need Daniel's acceptance. Test vectors are recorded before W2k's first production commit.
- How a restore finds the newest base backup: a `cp` record or a listing call. The `cp` record needs an `Infrastructure` register entry (ADR-009), and self-hosted installs need the local index or the listing call.
- **Keystore snapshot path, tied to ADR-004 erasure step 5.** The writers, the two proposed `KeystoreSnapshots` destinations (ADR-009), and the vault snapshot key (option A or B under Keystore snapshots). Vault chain rotations cannot complete until Daniel accepts one option.
- **Declared restores.** The `RestoreDeclared` statement, the restore declaration key (ADR-004 placement table), the `DeclareRestore` job (ADR-011), `fstp-control` as a witness client (ADR-009) and the `LostInRestore` verdict (ADR-010). Each is entered in its ADR as interim, pending Daniel, and they stand or fall together. Which jobs carry the production restore itself is also open.
- The standby's custody credential, its region and the promotion approval.
- The response size bound: Record at first use.
- OVHcloud facts this ADR relies on: ADR-005 verify items V14, V15 and V16, and ADR-004 verify item K4.
