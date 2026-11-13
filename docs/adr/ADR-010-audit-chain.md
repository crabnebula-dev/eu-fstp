# ADR-010: Audit chain, anchors and witnesses

Status: Accepted 2026-10-28 (Daniel Thompson-Yvetot).

## Context

- **I-24** The audit log is tamper-evident. Any modification or deletion of a past entry is detectable.
- R-AU-01 asks for every state transition, role binding, policy change and read of proposal content or identity attributes to be logged. TH-14 names a hash chain with external anchoring as the mitigation for audit log tampering.
- R-CR-03 and ADR-001 make audit chain anchors composite Ed25519 plus ML-DSA-65 signatures. I-90 accepts a composite signature only when both halves verify.
- ADR-007, as amended on 2026-10-28, seals ledger bodies and makes the chain hash the stored bytes, ciphertext included.
- A database owner could delete entries written after the last anchor. With a receipt after each commit, an entry stays unwitnessed for a short window, and a deletion inside it goes undetected (design gap G7).
- A self-hosted cell has no control plane, and I-38 forbids sending anything with tenant data to CrabNebula hosts (design gap G17).
- Daniel answered on 2026-10-28: Q8 signatures A and tail D, and Q9 A. He confirmed Q8 again on 2026-10-28, after the drafts: composite signatures (A) and the strict tail D (prepare, witness receipt, commit). The design source is `docs/handoff/m3-design.md`, sections 1.1 to 1.3, 3.9, 4.1 to 4.4, 5.3, 7, 9.1, 9.5, 14.4 and 15.

Options considered:

| Question | Option | Description | Outcome |
| --- | --- | --- | --- |
| Q8 signatures | A | Composite anchors and receipts in M3, with ML-DSA-65 ACVP keyGen, sigGen and sigVer subsets | Chosen by Daniel on 2026-10-28. Confirmed 2026-10-28 |
| | B | Unsigned anchors until M9, with two witnesses carrying detection | Rejected. R-CR-03 and ADR-001 require composite anchors |
| | C | Ed25519-only anchors | Rejected. Departs from the ADR-001 table |
| Q8 tail | D | Prepare, receipt, commit, with abort and in-doubt records. No committed entry is unwitnessed | Chosen by Daniel on 2026-10-28. Confirmed 2026-10-28 |
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
- Ed25519 comes from aws-lc-rs. ML-DSA-65 comes from moduletto once the pull request below lands, pinned as a git dependency to a full commit hash (Q1 C). moduletto is Tier B, so the I-74 release gate applies.
- moduletto has no ML-DSA-65 yet. Daniel decided on 2026-10-28 that it is added to moduletto on a pull request that Claude writes and Daniel reviews and merges (ADR-001 A2).
- Until that pull request lands, the ML-DSA half sits behind the `fstp-crypto` seam, and composite signing refuses with a typed error. The anchorer core then cannot prepare, so the cell and the vault refuse writes and keep serving reads, as without a witness. Nothing falls back to Ed25519 alone or to aws-lc-rs ML-DSA in production.
- Tests of the chain, the witness protocol and the verifier run meanwhile with the aws-lc-rs ML-DSA oracle through `fstp-celltest` only.
- The verifier accepts a signature only when both halves verify (I-90). `i90_anchor_verifier_rejects_either_half_alone` runs in M3, although I-90 is an M9 exit.

**Composite encoding.**

The composite format is the construction of draft-ietf-lamps-pq-composite-sigs, version 19, as ADR-001 pins. This ADR transcribes the encoding from that draft text before code. It is not written from memory.

Transcribed on 2026-10-29 from the text of `draft-ietf-lamps-pq-composite-sigs-19` (dated 21 April 2026, SHA-256 of the text file `b4ee04416efc26e7d8de7c740dc3848ffe8b8cc9dcd035ad9d4e33e18844ec83`). Each row cites its section. Quoted values are copied from the draft text. A row marked "Not covered" names an item the draft does not settle. `crates/fstp-crypto/tests/composite_draft19.rs` checks the transcription against the draft's Appendix D and E values.

| Item | Draft 19 section | Value |
| --- | --- | --- |
| Algorithm name | 6 | `id-MLDSA65-Ed25519-SHA512`, with "ML-DSA variant: ML-DSA-65", "Traditional Algorithm: Ed25519" and "Traditional Signature Algorithm: id-Ed25519" |
| Object identifier | 6, 7, 8.1.2 | Section 6: "OID: 1.3.6.1.5.5.7.6.48". Section 7: `id-MLDSA65-Ed25519-SHA512 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) alg(6) 48 }`. Section 8.1.2 lists "Decimal: IANA Assigned" and says "these were all early allocated on 2025-10-20, so they should all already be assigned to the values used above in Section 6 and Section 7." |
| Prefix | 2.2 | "the byte encoding of the ASCII string "CompositeAlgorithmSignatures2025" which in hex is: 436F6D706F73697465416C676F726974686D5369676E61747572657332303235" |
| Label | 6, 2.2 | "Label: COMPSIG-MLDSA65-Ed25519-SHA512". "Labels are represented here as ASCII strings, but implementers MUST convert them to byte strings according to their ASCII values prior to concatenating them with other byte values as described in Section 2.2." |
| Pre-hash | 6, 2.1 | "Pre-Hash function (PH): SHA512". Section 2.1: "the ML-DSA component inside the composite is "pure" ML-DSA; implementing this specification does not require an implementation of HashML-DSA." |
| Message representative | 2.2, 3.2, 3.3 | `M' :=  Prefix \|\| Label \|\| len(ctx) \|\| ctx \|\| PH( M )`. "len(ctx): A single unsigned byte encoding the length of the context." Section 3.2 step 1: "If len(ctx) > 255:" then "return error", on two lines. Section 3.3 step 1 has the same check without the colon. The application context `ctx` "defaults to the empty string" |
| Component signatures | 3.2 step 4 | `mldsaSig = ML-DSA.Sign( mldsaSK, M', mldsa_ctx=Label )` and `tradSig = Trad.Sign( tradSK, M' )`. "the per-algorithm Label is used as the ctx for the underlying ML-DSA primitive." For EdDSA: "even if present, this is not used by Composite ML-DSA." |
| Verification | 3.3 | "Compliant applications MUST output "Valid signature" (true) if and only if all component signatures were successfully validated, and "Invalid signature" (false) otherwise." Step 2: "If Error during deserialization, or if any of the component keys or signature values are not of the correct type or length for the given component algorithm then output "Invalid signature" and stop." Step 4 checks `ML-DSA.Verify( mldsaPK, M', mldsaSig, mldsa_ctx=Label )` and `Trad.Verify( tradPK, M', tradSig )`. In `fstp-crypto` the step 1 outcome "return error" is `CryptoError::InvalidLength`, checked first. The step 2 and step 4 outcome "Invalid signature" is `CryptoError::InvalidSignature`, also for a key or signature of the wrong length |
| Key generation | 3.1 | `mldsaSeed = Random(32)`, `(mldsaPK, mldsaSK) = ML-DSA.KeyGen_internal(mldsaSeed)`, `(tradPK, tradSK) = Trad.KeyGen()`. "MUST perform, or otherwise guarantee, fresh generation of the key material for both underlying algorithms and MUST NOT reuse existing key material." |
| Public key | 4.1, 4, Table 1, Appendix A | `output mldsaPK \|\| tradPK`. For ML-DSA-65: `mldsaPK = bytes[:1952]` and `tradPK  = bytes[1952:]`. Section 4: "*ML-DSA*: MUST be encoded as specified in Section 7.2 of [FIPS.204], using a 32-byte seed as the private key. The signature and public key format are encoded as specified in Section 7.2 of [FIPS.204]." Table 1, "ML-DSA Sizes in bytes", row `\| ML-DSA-65 \| 1952       \| 32          \| 3309      \|` under the header `\| Algorithm \| Public key \| Private key \| Signature \|`. Section 4: "*EdDSA*: public key and signature MUST be encoded as per Section 3 of [RFC8032]". Appendix A Table 4: 1984 bytes |
| Private key | 4.2, 4, Table 1, Appendix A | `output mldsaSeed \|\| tradSK`, parsed as `mldsaSeed = bytes[:32]` and `tradSK  = bytes[32:]`. Section 4: "*ML-DSA*: MUST be encoded as specified in Section 7.2 of [FIPS.204], using a 32-byte seed as the private key." Table 1 gives 32 bytes as the ML-DSA-65 private key. Section 4: "the private key is a 32- or 57-byte raw value for Ed25519 and Ed448 respectively". Appendix A Table 4: 64 bytes |
| Signature | 4.3, Table 1, Appendix A | `output mldsaSig \|\| tradSig`. For ML-DSA-65: `mldsaSig = bytes[:3309]` and `tradSig  = bytes[3309:]`. Table 1 gives 3309 bytes as the ML-DSA-65 signature. Appendix A Table 4: 3373 bytes |
| Small-order Ed25519 public keys | Not covered | The draft does not address Ed25519 public keys of small order. Platform rule beyond draft 19 (I-75, I-90): `CompositePublicKey::from_bytes` refuses an Ed25519 half that encodes a point of small order, with `CryptoError::InvalidKey`. The verifier then outputs "Invalid signature" (`CryptoError::InvalidSignature`). The refused encodings are the y-coordinates 0, 1, p - 1 and the two of order 8, and the non-canonical p and p + 1, each with either sign bit. aws-lc-rs accepts such keys. Under one, a fixed Ed25519 value verifies over many messages, so the composite would rest on ML-DSA-65 alone |
| Degenerate ML-DSA-65 public keys | Not covered | The draft does not address ML-DSA-65 public keys that anyone can sign for, and FIPS 204 checks a public key for length only. Platform rule beyond draft 19 (I-75, I-90): `CompositePublicKey::from_bytes` refuses an ML-DSA-65 half `rho \|\| t1` whose every 10-bit `t1` coefficient lies in 0 to 255 or 768 to 1023, with `CryptoError::InvalidKey`. The verifier then outputs "Invalid signature" (`CryptoError::InvalidSignature`). That band is where `t1 * 2^13` lies within 2^21 of 0 modulo q. A `t1` of only 0 and 1023 has the public secret `s1 = s2 = 0`, with `t0` of 0 or 1, and keys near it may be forged by a signer that takes `s1 = 0`. Under such a key the composite would rest on Ed25519 alone. The check reads the FIPS 204 `pkEncode` bytes and does no lattice arithmetic. An honest `t1` falls in the band with probability about 2^-1536. A key whose `t1` rounds `A * s1` for some other guessable small `s1` is not detected, since that needs the matrix `A` (open point 1) |
| Component key reuse | 3.1 | "Compliant parties MUST NOT use, import or export component keys that are used in other contexts, combinations, or by themselves as keys for standalone algorithm use." The 64-byte private key from `CompositeSigningKey::to_bytes` is for sealing and reopening one composite key only. No source scan enforces that outside `fstp-crypto` yet (open point 1) |
| Test vector | Appendix E | The case `"tcId": "id-MLDSA65-Ed25519-SHA512"`. `"m": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4="` and `"ctx": "VGhlIGxldGhhcmdpYywgY29sb3JsZXNzIGRvZyBzYXQgYmVuZWF0aCB0aGUgZW5lcmdldGljLCBzdGF0aW9uYXJ5IGZveC4="`, the latter joined from two lines. `"sk": "I6V4IFKJVV5l3fVnYBy0cV+1k6d5ao9x1mjDvKh22Tdg6XQfX7imizxJC5Pkqg5dgiBu87jiJC4bz0cp8uFGqg=="`. `pk`, `s` and `sWithContext` are copied verbatim into `crates/fstp-crypto/tests/data/composite_mldsa65_ed25519_draft19.json`. SHA-256 of the decoded bytes: `pk` (1984 bytes) `10775911b6c3c2dbf3c98485be51c5cc2c1b9ca5d2047a7faedab1d6cd573c27`, `sk` (64) `e6361cda094fd0b587b192a3eb414545d181f78b53a1578e3de61b6d0de8e3d0`, `s` (3373) `e00b69d9885679613d138c6d9c0e2762d5d8b210f8cf5fe5d73402a4de460c3d`, `sWithContext` (3373) `392f002608faab90bac3d0f0aa5f5bdf57df244464225a4af3b59b5b68f51187`. `x5c` and `sk_pkcs8` are not used |
| Message representative examples | Appendix D | Two worked `M'` values, for `id-MLDSA65-ECDSA-P256-SHA512`, without and with the context `0813061205162623`. That algorithm also pre-hashes with SHA-512, so they check the `M'` construction. The draft gives no `M'` example for `id-MLDSA65-Ed25519-SHA512` |
| ML-DSA signing randomness | Not covered | The draft calls `ML-DSA.Sign` and does not say hedged or deterministic. `fstp-crypto` signs hedged, with `rnd` from aws-lc-rs, as the W1h ML-DSA lane scope sets |
| Application context of platform messages | Not covered | The draft leaves `ctx` to the application. Interim reading of lane W2g (2026-10-29), open point 2: every anchor signature passes `ctx = "fstp-anchor-v1"` and every receipt signature passes `ctx = "fstp-receipt-v1"`, each its message label. A signature under any other context, the empty default included, is refused. The constants are `fstp_audit::anchor::ANCHOR_CONTEXT` and `RECEIPT_CONTEXT` |

- Daniel accepted this table as transcribed on 2026-10-29, including the three platform rows (small-order Ed25519, degenerate ML-DSA-65, signing randomness). Production code in `fstp-audit` and `fstp-witness` may now sign and verify against it.

**Verification of ML-DSA-65.**

- ACVP keyGen, sigGen and sigVer vectors for ML-DSA-65 run in CI. aws-lc-rs runs them through its stable `PqdsaKeyPair::from_seed` and `ML_DSA_65` APIs.
- moduletto runs them once its ML-DSA-65 pull request lands. ADR-001 A2 proposes deterministic key generation and signing entry points as part of that pull request, so the same vectors apply.
- Differential checks verify moduletto signatures with aws-lc-rs and the reverse, on random inputs (ADR-001 Post-quantum signatures).
- These are T-CR-MLDSA for TH-68. The composite verifier tests are T-CR-COMPOSITE for TH-67.

**Keys.**

| Key | Algorithm | Held in | Rotation |
| --- | --- | --- | --- |
| App chain anchor key, per cell | Composite | App chain level 2 key, purpose `Anchor` | Re-wrapped under each new root epoch. Replaced yearly. Old public keys stay in the anchor key history that the witness holds |
| Vault chain anchor key, per cell | Composite | Vault chain level 2 key, purpose `Anchor` | As above |
| Witness receipt key, SaaS | Composite | The witness's own custody entry, chain `ControlPlane`, with its own credential | Yearly. Cells pin a set of witness keys. A new key is announced signed by the old one |
| Witness receipt key, self-hosted | Composite | The local witness's own key, in a separate `fstp-keyd` entry with its own credential (open point 6, ADR-004 part 2 "Self-hosted witness receipt key") | As the SaaS key |

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
- The file store keeps one append-only file per cell and chain, framed as `fstp_witness::file_store` says, and one registry file. Interim, pending Daniel (open point 4 fixed the database shape only): a prepare record is the witness message followed by its encoded receipt. An abort or in-doubt record is the witness message, `be64(received_at)` and the witness link. A registry record is a CA certificate or an anchor key of one cell.
- The local witness loads every file at start and recomputes every witness link. A store with a missing, changed or cut record does not start, so it fails closed.
- Scope of the self-hosted I-24 claim (open point 7, Daniel, 2026-11-13): the local witness detects a change or deletion by any database role and by the database owner. A root user on the cell node can change both the database and the witness file store, so that is outside what the local witness detects. Only the optional external bucket would detect it. Every self-hosted I-24 test and document states its claim within this scope.

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
- Production anchoring, and so every production write, waits on the moduletto ML-DSA-65 pull request. The M3 exit claim of I-24 with composite anchors depends on it (`SPEC/09-milestones.md` NOTE 2).

## Open points

1. **Composite encoding.** The table under "Composite encoding" was transcribed from draft-ietf-lamps-pq-composite-sigs version 19 on 2026-10-29. Daniel accepts it before W2g code relies on it. Two facts from the draft text need his reading. Its first page says "Expires: 23 October 2026", a date already past. Its OIDs are early allocations (section 8.1.2). Three rows are platform choices that need his acceptance too. The small-order Ed25519 refusal goes beyond the draft. The degenerate ML-DSA-65 refusal goes beyond the draft and FIPS 204. It mirrors the Ed25519 rule, so neither half can be one that anyone signs for. Decided by Daniel on 2026-10-29: he accepted the table as transcribed, with its draft date and early-allocated OIDs. The degenerate ML-DSA-65 check stays in `fstp-crypto`, and the gap it cannot detect (a `t1` that rounds `A * s1` for another guessable small `s1`) is accepted. This point is closed as a public key check. He also decides whether the residual it leaves is an accepted gap: a `t1` that rounds `A * s1` for a guessable small `s1` other than 0. If he decides against the check, the asymmetry with the Ed25519 rule is recorded here as an accepted gap. The component key reuse rule of section 3.1 is documented on the private key API but not yet enforced by a scan; proposed: an `fstp-keys` rule that composite private key bytes are only sealed and opened whole.
2. **Byte layouts.** The genesis, row, anchor and receipt layouts above are proposals beyond the design. Daniel accepts or changes them, and vectors are recorded at first use. Interim reading of lane W2g (2026-10-29): the draft 19 application context is `fstp-anchor-v1` for anchors and `fstp-receipt-v1` for receipts, the message labels (row "Application context of platform messages"). The label in the message and the context both keep the two kinds apart. Signing and every check use these contexts. Two W1 tests in `fstp-celltest/tests/r_cr_03_composite_anchors.rs` check production signatures with the empty context. They are `r_cr_03_anchors_carry_composite_signatures` and `r_cr_03_receipts_carry_composite_signatures`, and they stay red under this reading until Daniel decides. They are exit tests of design section 14.4, so M3 cannot close before that decision. Decision for Daniel: (a) keep these contexts, and the W1 owner changes both tests to `composite::verify_with_context` with them; or (b) take the empty context, and `ANCHOR_CONTEXT` and `RECEIPT_CONTEXT` become empty. Under (b) only the labels inside the messages keep anchors and receipts apart.
3. **How the witness checks "extended".** The witness can only confirm that a prepare extends the previous one if it can recompute the link. Proposed: each prepare carries the previous prepared head and the stored hashes of the rows in between. These are SHA-256 values over sealed rows, but they would need their own entry in the I-19 metadata register (ADR-009).
4. **Witness records for abort and in doubt.** The `witness.anchor` table in design section 4.4 holds prepares only. W2g adds insert-only rows for `Abort` and `InDoubtAbsent`, and this ADR records their shape before code. Code came first in lane int5 (2026-10-30), so the shape is recorded here after the fact. Decided by Daniel on 2026-10-30: the shape and keys below are accepted, and design section 4.4 is amended to match (design 21.0). It is in `crates/fstp-witness/migrations/witness/0003_witness.sql`:
   - `witness.withdrawal` holds aborts (kind 2) and in-doubt records (kind 3), with the columns of `witness.anchor` minus the signature and plus `kind`.
   - Prepares and withdrawals share one `witness_seq` per cell and chain, numbered from 1 with no gap under an advisory lock.
   - Design conflict: section 4.4 makes `witness_seq` unique over the table and keys `witness.anchor` on (cell_id, chain, n). int5 keys both tables on (cell_id, chain, witness_seq), with (cell_id, chain, n, link) unique. A cell may prepare the same n again with another link after its abort is recorded, and the design key would refuse that.
   - Three tables the design does not list: `witness.receipt` (the composite receipt signature per prepare), `witness.cell_ca` (each pinned cell CA, registered at provisioning) and `witness.anchor_key` (the anchor key history per chain).
   - `witness_service` holds INSERT and SELECT on anchor, receipt and withdrawal, and SELECT only on cell_ca and anchor_key. Only `witness_migrator` registers a cell. Triggers refuse UPDATE, DELETE and TRUNCATE for every role.
   - Decided by Daniel on 2026-10-30: design section 4.5 gains three public classes, for link hashes, signatures and public key material, and the witness columns use them (design 21.0).
5. **Vault chain coverage.** The design gives `vault_audit.chain` the shape of `audit.chain`, but the vault has no ledger. Which vault rows become kind 1 rows, if any, and which become events, is fixed with W2d before code. Decided by Daniel on 2026-11-13: each committed fact batch and each identity release or read (R-AU-01) is a kind 1 row. A KeyOp stays an event only.
6. **Self-hosted receipt key custody.** The design gives the local witness its own receipt key, but not its custody. Proposed: a separate `fstp-keyd` entry with its own credential, recorded in ADR-004 part 2. Accepted by Daniel on 2026-11-13.
7. **Self-hosted witness and host root.** A local witness on the cell's node detects edits by any database role and by the database owner. A root user on that node can change both the database and the witness store. Only the optional external bucket would detect that. Daniel decides whether the self-hosted I-24 claim needs a scope statement under Q33, or whether the external bucket becomes mandatory. Decided by Daniel on 2026-11-13: the self-hosted I-24 claim carries a scope statement. A root user on the cell node is outside what the local witness detects, and only the optional external bucket would. The bucket stays optional.
8. **Restore to an earlier backup point.** The restore rule in design section 3.5 lets data tables come from any backup point. A restore to an earlier point leaves receipted links without rows, and the verifier reports `Deleted` or `Truncated`. ADR-012 fixes how a restore is recorded at the witness, so a known restore is told apart from tampering. Its proposal adds `LostInRestore` to the verifier table above, interim, pending Daniel.
9. **Second provider for witness copies.** Undecided until Q25 closes with L-15.
10. **Witness key announcement.** The format of the statement that announces a new witness key, signed by the old one, is fixed with the composite encoding. Daniel accepted the composite encoding on 2026-10-29. Interim reading of lane W2g: the announcement gets its own label and application context, proposed `fstp-witness-key-v1`, so no anchor or receipt signature verifies as one. Its byte layout is not fixed yet. No code signs or reads an announcement, and it is fixed with vectors before witness key rotation is written.

Verify list for the provider (questions, not facts):

- Does the chosen object-lock bucket refuse deletion and overwrite by the account owner during its retention period?
- Which EU regions offer object lock for the bucket that holds witness copies?
- Does OKMS offer a usage log of key operations that the reconciliation task can read? This is ADR-004 verify item K6.

## Record

- Record at first use: the ML-DSA-65 ACVP vector set and its source, for aws-lc-rs and for moduletto.
- The moduletto repository is `https://github.com/crabnebula-dev/moduletto` (ADR-001 A2). Record at first use: the commit that contains ML-DSA-65 and the features used for it.
- Daniel accepted this ADR on 2026-10-28. The M3 exit audit lists that date.
