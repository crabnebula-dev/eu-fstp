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

## Rules

- **I-80** No root key exists in plaintext outside its custody backend.
- **I-81** Destroying a cell's root key, or a data key, makes the protected data unrecoverable, including from backups. This is how erasure (R-SW-02) and crypto-shredding (R-ID-03) are carried out.
- Root key use is logged by the backend, and the log is reconciled with the cell's audit chain.
- Key rotation re-wraps level 2 keys without re-encrypting data.

## Hybrid combiner

Proposed: an X-Wing style combiner. Both shared secrets, the ML-KEM ciphertext and the X25519 public values are bound through a KDF from aws-lc-rs. Test vectors and a written construction are fixed here before implementation. The construction is reviewed in hardening activity H-19.

## Signing keys

| Key | Algorithm | Held in |
| --- | --- | --- |
| Release signing key | Composite Ed25519 plus ML-DSA-65 | Offline HSM under CrabNebula control. Used only in the release ceremony (proposed) |
| Audit anchor and export manifest key, per cell | Composite | Level 2 key of the cell, wrapped by the root key |
| Notice companion key, per tenant | Composite | Level 2 key of the cell |
| Licence token, profile bundle and template keys | Ed25519 | Level 2 keys of the issuing cell or the control plane |

- Self-hosted cells and desktop clients ship with the release public keys and accept rotation only through a message signed by the current release key.
- moduletto ML-DSA signing inside an HSM depends on the HSM's ability to run it. If it cannot, the release ceremony runs on an offline, air-gapped machine with the ML-DSA key sealed by the HSM (O-42).
