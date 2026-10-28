# ADR-010: Audit chain, anchors and witnesses

Status: Proposed (drafted 2026-10-28), awaiting Daniel's acceptance.

## Context

- **I-24** The audit log is tamper-evident. Any modification or deletion of a past entry is detectable.
- R-AU-01 asks for every state transition, role binding, policy change and read of proposal content or identity attributes to be logged. TH-14 names a hash chain with external anchoring as the mitigation for audit log tampering.
- R-CR-03 and ADR-001 make audit chain anchors composite Ed25519 plus ML-DSA-65 signatures. I-90 accepts a composite signature only when both halves verify.
- ADR-007, as amended on 2026-10-28, seals ledger bodies and makes the chain hash the stored bytes, ciphertext included.
- A database owner could delete entries written after the last anchor. With a receipt after each commit, an entry stays unwitnessed for a short window, and a deletion inside it goes undetected (design gap G7).
- A self-hosted cell has no control plane, and I-38 forbids sending anything with tenant data to CrabNebula hosts (design gap G17).
- Daniel answered on 2026-10-28: Q8 signatures A and tail D, and Q9 A. The design source is `docs/handoff/m3-design.md`, sections 1.1 to 1.3, 3.9, 4.1 to 4.4, 5.3, 7, 9.1, 9.5, 14.4 and 15.

Options considered:

| Question | Option | Description | Outcome |
| --- | --- | --- | --- |
| Q8 signatures | A | Composite anchors and receipts in M3, with ML-DSA-65 ACVP keyGen, sigGen and sigVer subsets | Chosen by Daniel on 2026-10-28 |
| | B | Unsigned anchors until M9, with two witnesses carrying detection | Rejected. R-CR-03 and ADR-001 require composite anchors |
| | C | Ed25519-only anchors | Rejected. Departs from the ADR-001 table |
| Q8 tail | D | Prepare, receipt, commit, with abort and in-doubt records. No committed entry is unwitnessed | Chosen by Daniel on 2026-10-28 |
| | A | A receipt after each commit; writes refused once an entry stays unwitnessed for 60 seconds | Rejected. Leaves a window for undetected deletion |
| | B | As A, with each command waiting for its receipt before it is reported | Rejected. The window remains between commit and receipt |
| | C | Periodic anchors only | Rejected. The window is the anchor period |
| Q9 self-hosted | A | A local witness is mandatory at first start; an external object-lock bucket is optional | Chosen by Daniel on 2026-10-28 |
| | B | The witness is optional, with a standing warning to tenant admins | Rejected. R-NF-05 asks for secure defaults |

## Decision

### Chains

Each cell has two audit chains. Each is written by one process only.

| Chain | `ChainId` | Writer | Table | Anchor key |
| --- | --- | --- | --- | --- |
| Application chain | `App` (byte value 1) | `fstp-cell` | `audit.chain` in `c_<cell>` | App chain level 2 key, purpose `Anchor` (ADR-004) |
| Vault chain | `Vault` (byte value 2) | `fstp-vault` | `vault_audit.chain` in `v_<cell>` | Vault chain level 2 key, purpose `Anchor` (ADR-004) |

- A chain row is either a ledger entry (kind 1) or an event (kind 2).
- A kind 1 row names its ledger sequence number. The ledger entry and its chain row commit in the same transaction.
- A kind 2 row holds a sealed event body. Events are logins, refused logins, step-ups with their action digest, sessions ended, credentials added or removed, recovery steps, break-glass grants and uses, custody calls, erasure phases, licence state changes and vault intake.
- Event bodies hold ids, enums and digests only. They are sealed under the `Ledger` purpose with a random nonce (ADR-007 amendment).
- Events without a ledger entry, such as refused logins, are grouped into one chain transaction at most every 200 ms. A login flood therefore cannot flood the witness.
- `TextErasureRequested`, `TextErased`, `DocumentErased` and `KeyEpochDestroyed` are ledger records, so each sits in the chain (ADR-007 amendment).

### Link function

The link function is the one in `docs/handoff/m3-design.md` section 7.1:

```text
link_n = SHA-256("fstp-audit-v1" || cell || chain || be64(n) || link_{n-1} || stored_hash_n)
```

- `cell` is the 16 bytes of the `CellId`. `chain` is one byte, as in the table above. `n` starts at 1.
- `link_0` is the genesis link. It binds the cell and the chain.
- `stored_hash_n` is SHA-256 over the stored row's fixed byte layout, ciphertext included.
- `fstp_audit::ChainWriter` is the only Rust code that computes links.

Proposed byte layouts. The design fixes the link but not these layouts. They are proposed here and are fixed, with vectors, before W2g writes code:

```text
genesis   = SHA-256("fstp-audit-genesis-v1" || cell || chain)
row bytes = "fstp-audit-row-v1" || be16(kind) || be64(at) || payload
  kind 1:   payload = be64(seq) || be64(entry_at) || command (16 bytes) || be16(schema)
                      || be32(key_ix) || be32(len(body)) || body
  kind 2:   payload = be32(len(body)) || body
stored_hash_n = SHA-256(row bytes)
```

- The link binds every column of the chain row, apart from `stored_hash` and `link` themselves, and every column of the referenced ledger entry. The teeth test `i24_teeth_link_omitting_a_field_is_caught` checks that.
- Record at first use: the link, genesis and stored-hash test vectors, computed by the independent reference in `fstp-celltest` (W1e).

### Database link trigger

- `audit.check_link` runs before each insert into `audit.chain`. `vault_audit.chain` has the same trigger.
- It checks that `n` is one more than the current head, or 1 on an empty chain. It reads the previous link, or the genesis link for `n = 1`.
- It recomputes `stored_hash_n` from the row and, for kind 1, from the ledger entry in the same transaction. It then recomputes `link_n` with `sha256()` and the `int2send()`, `int4send()` and `int8send()` encodings.
- It refuses a mismatch in either value. This is a second implementation of the link function, independent of `fstp-audit`.
- A differential test, `i24_pg_chain_equals_reference_chain`, compares the trigger, `fstp-audit` and the `fstp-celltest` reference byte for byte.
- Triggers refuse UPDATE, DELETE and TRUNCATE on both chain tables and on `audit.anchor`, the owner included. The writer role holds INSERT and SELECT only (ADR-007).
- A cluster superuser can bypass triggers. The verifier and the witness detect such an edit; the trigger does not prevent it.

### Anchors

An anchor commits to a chain head:

```text
Anchor { cell, chain, n, link, at, signature }
```

- `signature` is a composite Ed25519 plus ML-DSA-65 signature under the chain's `Anchor` key (ADR-001, R-CR-03).
- Proposed signed message, to be fixed with vectors before W2g code: `"fstp-anchor-v1" || cell || chain || be64(n) || link || be64(at)`.
- Ed25519 comes from aws-lc-rs. ML-DSA-65 comes from moduletto, pinned as a git dependency to a full commit hash (Q1 C). moduletto is Tier B, so the I-74 release gate applies.
- The verifier accepts a signature only when both halves verify (I-90). `i90_anchor_verifier_rejects_either_half_alone` runs in M3, although I-90 is an M9 exit.

**Composite encoding.**

The composite format is the construction of draft-ietf-lamps-pq-composite-sigs, version 19, as ADR-001 pins. This ADR transcribes the encoding from that draft text before code. It is not written from memory.

The draft text has not been read for this draft of the ADR. Each item below is a placeholder until it is transcribed from version 19, or recorded as not covered by it:

| Item | Value |
| --- | --- |
| Composite algorithm name and identifier for Ed25519 with ML-DSA-65 | Record at first use, from draft version 19 |
| How the message is prepared before each half signs it, including any prehash, label or context | Record at first use, from draft version 19 |
| Composite public key encoding | Record at first use, from draft version 19 |
| Composite signature encoding | Record at first use, from draft version 19 |
| Test vectors from the draft, if it has any for this combination | Record at first use, from draft version 19 |
| Draft section numbers that each row cites | Record at first use |

- No production code in `fstp-audit` or `fstp-witness` that signs or verifies is written before this table is filled and Daniel accepts it.

**Verification of ML-DSA-65.**

- ACVP keyGen, sigGen and sigVer vectors for ML-DSA-65 run in CI. aws-lc-rs runs them through its stable `PqdsaKeyPair::from_seed` and `ML_DSA_65` APIs.
- moduletto runs them if it exposes deterministic entry points. That is the open sub-question of Q1.
- Differential checks verify moduletto signatures with aws-lc-rs and the reverse, on random inputs (ADR-001 Post-quantum signatures).
- These are T-CR-MLDSA for TH-68. The composite verifier tests are T-CR-COMPOSITE for TH-67.

**Keys.**

| Key | Algorithm | Held in | Rotation |
| --- | --- | --- | --- |
| App chain anchor key, per cell | Composite | App chain level 2 key, purpose `Anchor` | Re-wrapped under each new root epoch. Replaced yearly. Old public keys stay in the anchor key history that the witness holds |
| Vault chain anchor key, per cell | Composite | Vault chain level 2 key, purpose `Anchor` | As above |
| Witness receipt key, SaaS | Composite | The witness's own custody entry, chain `ControlPlane`, with its own credential | Yearly. Cells pin a set of witness keys. A new key is announced signed by the old one |
| Witness receipt key, self-hosted | Composite | The local witness's own key. Custody placement is open (see Open points) | Record at first use |

### Prepare, receipt, commit

No entry is committed before the witness has receipted its link. One append is one transaction (ADR-007, design section 5.3):

1. Take the cell's advisory lock. Check the command id, then the expected head.
2. Seal and insert the ledger entries.
3. Insert one chain row per entry. `ChainWriter` computes each link. The trigger recomputes it.
4. Insert the side-effect rows.
5. **Prepare.** Send `Prepare { cell, chain, n, link, anchor }` for the prospective head to the witness. Wait for the receipt.
6. Insert the anchor and the receipt into `audit.anchor`.
7. Commit.

A batch of entries shares one prepare. Steps 1 to 6 can abort. The vault follows the same steps for the Vault chain.

**Receipt.**

- The witness appends the prepare to its own chain for that cell and chain, then returns a composite-signed receipt.
- Proposed receipt content: `Receipt { cell, chain, n, link, witness_seq, witness_link, received_at, signature }`. The signed message gets its own label, `"fstp-receipt-v1"`, and is fixed with vectors before W2g code.
- Every committed entry already holds its receipt. A response therefore waits for nothing after the commit, and no `202 witness_pending` state exists.

**One outstanding prepare per chain.**

- The witness refuses a new prepare for a chain until the previous one is extended, aborted or resolved as in doubt.
- "Extended" means that the new prepare's history contains the previous prepared link.

**Abort.**

- If the transaction fails before COMMIT is sent, or COMMIT returns an error, nothing was committed.
- The cell then sends `Abort { n, link }`, and the witness records it.
- Only after the witness has recorded the abort may the cell prepare the same `n` again with another link.

**In doubt.**

- If the outcome of COMMIT is unknown, the cell reads its chain at reconnect or restart. A lost connection or a crash can cause this.
- If row `n` with that link exists, it was committed. The next prepare extends it.
- If the row is missing, the cell cannot tell an abort from a deletion. It sends `InDoubtAbsent { n, link }`, and the witness records it.
- The cell then raises `PossibleDeletion` to tenant admins and in the auditor view. That alert is the detection, so no deletion goes unreported.
- Each `PossibleDeletion` needs a tenant admin acknowledgement in the audit view. Alerts count in-doubt events per cell (design risk R9).

**Start-up.** The cell and the vault each verify their chain against the witness before they serve requests. They resolve any in-doubt prepare first.

**Witness unavailable.** Without a reachable witness, the cell refuses writes and keeps serving reads. The refusal names the witness (design risk R8).

### Verifier

`fstp_audit::verify` takes the chain rows, the stored ledger entries, the anchors, the receipts and the anchor key history. It needs no content key. It reports one of these:

| Result | Meaning |
| --- | --- |
| `Changed { n }` | A row's stored hash or link does not match its bytes |
| `Gap { n }` | A sequence number is missing inside the chain |
| `Reordered { n }` | Rows are out of order |
| `Truncated { witnessed, have }` | The witness has receipted a head beyond the chain's last row |
| `AnchorMismatch { n }` | An anchor's link differs from the chain's link at `n` |
| `BadSignature { n }` | An anchor or receipt signature fails, including when only one half verifies |
| `LedgerWithoutRow { seq }` | A ledger entry has no chain row |
| `RowWithoutLedger { n }` | A kind 1 row names a missing ledger entry |
| `StoredHashMismatch { seq }` | A ledger entry's bytes differ from the hash its row holds |
| `Deleted { n }` | A prepared link at the witness has no chain row, no `Abort` and no `InDoubtAbsent` |
| `AbortedButPresent { n }` | An `Abort` exists for a link that is present in the chain |
| `LostInRestore { from, to, job }` | Receipted links beyond the head of a declared restore. Interim, pending Daniel, proposed by ADR-012 (Declared restores at the witness). Each needs a tenant admin acknowledgement, and it never hides a finding |

### Witnesses

**SaaS witness.**

- `fstp-witness` runs as its own process, with its own database `witness` on its own self-operated cluster. Under Daniel's Q3 answer the control-plane databases are managed, but the witness database stays self-operated. I-24 detection then does not rest on a provider's superuser.
- `witness.anchor` is INSERT and SELECT only for `witness_service`.
- The witness writes each prepare, abort, in-doubt record and receipt to its database. It also writes a copy to an object-lock bucket at a second provider. Restore declarations (ADR-012) are copied the same way, interim, pending Daniel. The provider follows Q25, which Daniel decides with the L-15 due diligence.
- Cells and vaults reach the witness directly over mutual TLS. Anchors never pass through the control plane, and `CellToCp` has no anchor variant.
- `fstp-control` reaches the witness only to send restore declarations, over mutual TLS with a control-plane CA certificate (ADR-012, ADR-009). Interim, pending Daniel. It never sends a prepare.
- The witness pins each cell CA's public key, registered at provisioning. It accepts a `cell-witness` certificate only for the App chain of that cell, and a `vault-witness` certificate only for its Vault chain.
- The witness server certificate comes from the control-plane CA.
- Anchor links at the witness are an entry of the I-19 metadata register (ADR-009). They are SHA-256 values over sealed rows, so they reveal only that a chain grew.

**Self-hosted witness (Q9 A).**

- A local `fstp-witness` is mandatory at first start. It runs under its own OS user, with its own append-only file store and its own receipt key.
- `fstp-install` starts it and registers the cell CA's public key with it (design section 9.5, step 6).
- The cell and the vault refuse writes until the local witness answers, as in SaaS.
- An external object-lock bucket is optional. The tenant chooses it.
- No anchor and no prepare ever goes to a CrabNebula host (I-38). `i38_self_hosted_witness_never_targets_crabnebula` checks that.

### The vault chain is anchored by the vault only

- The vault runs the same anchorer core for `ChainId::Vault`. It uses its own `Anchor` key and its `vault-witness` certificate.
- It reaches the witness over its `VaultDestination::Witness` connection (boundary rule B4a).
- The cell never anchors the vault's chain, and the vault never anchors the cell's.
- `i24_vault_chain_anchored_by_the_vault_only` checks both directions.

### Custody reconciliation

- ADR-004 part 2 (Reconciliation) states the rule. Every custody call carries a request id and is recorded as a `KeyOp` event. Normally the event is written before the call.
- The start-up `unwrap` of `S(e)` is the one exception. Its request id goes into an operational keystore row before the call, and its `KeyOp` event follows once the chain is open (ADR-004 part 2).
- A daily task reads the backend's usage record and compares it with these events. A backend entry without a matching event raises `CustodyAnomaly` (ADR-004).
- OKMS reconciliation waits on ADR-004 verify item K6, which Daniel is asking OVHcloud.

## Tests

- Property and integration: `i24_verifier_flags_every_mutation`, `i24_pg_chain_equals_reference_chain`, `i24_database_refuses_bad_link_and_mutation`, `i24_ledger_and_chain_commit_together`, `i24_no_commit_without_a_receipt_for_its_link`.
- Abort and in doubt: `i24_abort_recorded_before_the_same_n_is_prepared_again`, `i24_in_doubt_missing_row_raises_possible_deletion`, `i24_tail_deletion_after_commit_is_detected` (both chains).
- Scope: `i24_vault_chain_anchored_by_the_vault_only`, `i24_erasure_entries_are_chained`, `i24_custody_ops_reconcile_with_key_records`, `r_nf_08_aborted_append_never_reuses_a_nonce`.
- Signatures: `r_cr_03_anchors_carry_composite_signatures`, `i90_anchor_verifier_rejects_either_half_alone`.
- Model: `i24_m_audit` (M-AUDIT), with `always("I-24")` and `always("no-unwitnessed-commit")`.
- Teeth: `i24_teeth_verifier_without_receipt_check_is_caught`, `i24_teeth_link_omitting_a_field_is_caught`, `r_nf_08_teeth_counter_nonce_is_caught`.
- Fuzz targets from the first commit: `chain_row_decode`, `anchor_decode`, `receipt_decode` and `verify_mutations` in `fstp-audit`; `witness_message_decode` and `file_store_decode` in `fstp-witness`.

## Consequences

- No committed entry is ever unwitnessed. I-24 is claimed with no time window.
- Every append costs one witness round trip while the cell's advisory lock is held. Record at first use: the latency budget measured in W2, in the M3 exit audit.
- Writes depend on witness availability. A replicated witness in the same region, retries and event batching reduce the cost (design risk R8).
- A lost COMMIT outcome with a missing row is always reported as `PossibleDeletion`, never resolved silently.
- The monthly restore drill verifies every cell's chains against the witness (design section 3.8).
- Composite signing makes every anchor depend on moduletto. No anchor ships in a release until the I-74 confirmation for the pinned commit exists.

## Open points

1. **Composite encoding.** The table under "Composite encoding" must be transcribed from draft-ietf-lamps-pq-composite-sigs version 19 before W2g code. This blocks the signing and verifying code, not the tests against stubs.
2. **Byte layouts.** The genesis, row, anchor and receipt layouts above are proposals beyond the design. Daniel accepts or changes them, and vectors are recorded at first use.
3. **How the witness checks "extended".** The witness can only confirm that a prepare extends the previous one if it can recompute the link. Proposed: each prepare carries the previous prepared head and the stored hashes of the rows in between. These are SHA-256 values over sealed rows, but they would need their own entry in the I-19 metadata register (ADR-009).
4. **Witness records for abort and in doubt.** The `witness.anchor` table in design section 4.4 holds prepares only. W2g adds insert-only rows for `Abort` and `InDoubtAbsent`, and this ADR records their shape before code.
5. **Vault chain coverage.** The design gives `vault_audit.chain` the shape of `audit.chain`, but the vault has no ledger. Which vault rows become kind 1 rows, if any, and which become events, is fixed with W2d before code.
6. **Self-hosted receipt key custody.** The design gives the local witness its own receipt key, but not its custody. Proposed: a separate `fstp-keyd` entry with its own credential, recorded in ADR-004 part 2.
7. **Self-hosted witness and host root.** A local witness on the cell's node detects edits by any database role and by the database owner. A root user on that node can change both the database and the witness store. Only the optional external bucket would detect that. Daniel decides whether the self-hosted I-24 claim needs a scope statement under Q33, or whether the external bucket becomes mandatory.
8. **Restore to an earlier backup point.** The restore rule in design section 3.5 lets data tables come from any backup point. A restore to an earlier point leaves receipted links without rows, and the verifier reports `Deleted` or `Truncated`. ADR-012 fixes how a restore is recorded at the witness, so a known restore is told apart from tampering. Its proposal adds `LostInRestore` to the verifier table above, interim, pending Daniel.
9. **Second provider for witness copies.** Undecided until Q25 closes with L-15.
10. **Witness key announcement.** The format of the statement that announces a new witness key, signed by the old one, is fixed with the composite encoding.

Verify list for the provider (questions, not facts):

- Does the chosen object-lock bucket refuse deletion and overwrite by the account owner during its retention period?
- Which EU regions offer object lock for the bucket that holds witness copies?
- Does OKMS offer a usage log of key operations that the reconciliation task can read? This is ADR-004 verify item K6.

## Record

- Record at first use: the ML-DSA-65 ACVP vector set and its source, for aws-lc-rs and for moduletto.
- Record at first use: the moduletto repository URL, commit hash and features used for ML-DSA-65 (ADR-001, Q1).
- Record at first use: the date Daniel accepts this ADR, for the M3 exit audit.
