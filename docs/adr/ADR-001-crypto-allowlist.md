# ADR-001: Cryptography allowlist

Status: Accepted in structure by Daniel on 2026-10-09. Exact versions and resolved trees are recorded at first use. Tier B crates are subject to the release gate below.

## Context

The platform is built in-house by default. Cryptographic code is excluded from that policy, because defects stay silent until exploited. CrabNebula's post-quantum library moduletto is part of the design. qrtc returns with realtime sessions (backlog B-01).

## Decision

Cryptography comes only from the crates below. In-house code may compose them, for example into a hybrid key exchange group or an envelope format, but never reimplements a primitive.

### Tier A: established crates

| Crate | Use |
| --- | --- |
| rustls (0.23 line; 0.24 once stable) | TLS 1.3 client and server for HTTP, SMTP, PostgreSQL and adapters |
| aws-lc-rs, through the rustls aws-lc-rs provider | X25519, ECDSA, Ed25519, RSA signing, AES-256-GCM, ChaCha20-Poly1305, SHA-2, HMAC, HKDF, system randomness |
| rustls-webpki | Certificate path validation for TLS |
| rustls-pki-types | Certificate and key types, PEM parsing |
| vodozemac | Olm and Megolm for Matrix encrypted rooms |

### Tier B: unaudited, release-gated

| Crate | Use |
| --- | --- |
| moduletto (ML-KEM-768, ML-DSA-65) | Post-quantum half of every hybrid key exchange, key encapsulation and composite signature in the platform |
| RustCrypto der, spki, x509-cert, cms | ASN.1, X.509 and CMS parsing for qualified signature validation, until an audit is confirmed |

### Not allowed

| Crate | Reason |
| --- | --- |
| rsa (RustCrypto) | RUSTSEC-2023-0071, timing side channel, unpatched as of September 2026 |
| ring as a platform provider | No post-quantum support; one TLS provider across the platform |
| graviola | New and unaudited; revisit when mature |
| rustls-pemfile | Archived; use rustls-pki-types |

## Release gate (I-74)

Tier B crates may be used throughout development. No release ships a Tier B crate until the Mythos-tier hardening review has confirmed that exact version.

- A release means a production SaaS deployment or a distributed self-hosted or desktop build.
- Each confirmation is recorded below with crate, version, source hash, review date and findings reference.
- Any version change of a Tier B crate needs a new confirmation before the next release.
- CI blocks a release build whose Tier B versions lack a matching confirmation.

| Crate | Version | Source hash | Confirmed on | Findings |
| --- | --- | --- | --- | --- |
| (none yet) |  |  |  |  |

## Hybrid rule (I-75, I-90)

moduletto is always used in a hybrid with a classical primitive from aws-lc-rs: ML-KEM with X25519, ML-DSA with Ed25519. Nothing in the platform relies on a moduletto primitive alone. A defect in either half then cannot reduce security below the other.

## Post-quantum signatures (O-35)

Platform-controlled signatures on long-lived trust use a composite of Ed25519 and ML-DSA-65.

- **I-90** A composite signature verifies only when both the Ed25519 half and the ML-DSA-65 half verify. Nothing accepts either half alone.
- Format: the composite construction of draft-ietf-lamps-pq-composite-sigs, pinned to version 19 until it is published as an RFC, then to the RFC.
- Ed25519 comes from aws-lc-rs. ML-DSA-65 comes from moduletto, which places signing under the Tier B release gate (I-74).
- moduletto needs ML-DSA-65 per FIPS 204 before the first release, with NIST ACVP vectors for keyGen, sigGen and sigVer.
- CI verifies every moduletto ML-DSA signature with the ML-DSA in aws-lc-rs, and the reverse, on random inputs.

| Artifact | Signature |
| --- | --- |
| Release metadata and update bundles (self-hosted cells, desktop client) | Composite |
| Audit chain external anchors | Composite |
| Tenant export and vault export manifests | Composite |
| Contractual notices | eIDAS seal (legally relevant) plus a composite companion signature as evidence |
| Licence tokens, profile bundles, published templates | Ed25519 |

The eIDAS seal and qualified signatures stay classical until trust services support post-quantum algorithms.

## Uses

| Use | Construction |
| --- | --- |
| TLS key exchange | Custom rustls key exchange group X25519MLKEM768: X25519 from aws-lc-rs, ML-KEM-768 from moduletto, all else from the aws-lc-rs provider. Classical X25519 stays enabled for peers without hybrid support |
| Key wrapping at rest | Per-object data keys (AES-256-GCM) wrapped by a hybrid X25519 plus ML-KEM-768 key encapsulation. Covers the identity vault, backups and crypto-shredded documents |
| Tenant export and vault export | Encrypted to a tenant-held hybrid public key |
| Profile bundles | Signed with Ed25519; encrypted to the receiving tenant's hybrid public key when transferred |
| Platform messages at rest | Stage 2 relay, mentoring notes and complaints encrypted under hybrid-wrapped data keys |
| Matrix encrypted rooms | Olm and Megolm through vodozemac, as the Matrix specification defines. Post-quantum protection there depends on the Matrix specification |
| DKIM | Ed25519 (RFC 8463), with RSA-SHA256 through aws-lc-rs for receivers that need it |
| Audit chain, evidence snapshots, contract hashes | SHA-256 through aws-lc-rs |
| Release metadata, update bundles, audit chain anchors, export manifests | Composite signature: Ed25519 from aws-lc-rs plus ML-DSA-65 from moduletto (see Post-quantum signatures above) |
| Companion signature on contractual notices | Same composite, as evidence next to the eIDAS seal |
| Licence tokens, profile bundles, published templates | Ed25519 through aws-lc-rs |
| Qualified signatures | Created in the signer's wallet or at a trust service provider. Parsing through Tier B formats crates, verification through aws-lc-rs, validation procedure in-house |

The hybrid key encapsulation combiner is proposed as X-Wing style: both shared secrets, the ML-KEM ciphertext and the X25519 public values bound through a KDF. The exact construction is fixed in ADR-004 before implementation.

## Verification

- moduletto: ACVP known-answer tests for ML-KEM-768 and ML-DSA-65 run in platform CI, plus differential tests against aws-lc-rs ML-KEM and ML-DSA on random inputs.
- The custom TLS group interoperates with the aws-lc-rs X25519MLKEM768 group in both directions.
- Every Tier B parser has a fuzz target.

## Open points

- Authentication crates: webauthn-rs and opaque-ke are candidates for Tier A, subject to review of their audit status (O-36 resolved in `03-architecture/authentication.md`).
- A PKCS#11 client crate for the CrabNebula-operated HSM (ADR-004).
- Root key custody is fixed in ADR-004.

## Evidence

Audit reports for Tier A crates and Mythos confirmations for Tier B crates are stored with this ADR.

## Record

Exact versions and resolved trees at first use. `deps/allowlist.txt` ties each crate below to ADR-001 and pins its exact version and `.crate` SHA-256. `deps/adr-roots.txt` records the features cargo enables on each root crate.

`tools/deps-check` fails CI when a crate enters this tree, changes version or checksum, or reaches a higher role, and when a root's features change. It passes again only when the allowlist and the roots file match the new tree, and this record names each allowlisted crate and version. A crate that leaves the tree, or drops to a lower role, produces a warning, not a failure.

| Crate | Tier | Version | Features | First use |
| --- | --- | --- | --- | --- |
| rustls | A | 0.23.46 (`=0.23.46`) | `std`, `aws_lc_rs`, `prefer-post-quantum`, with default features off. No `tls12`, no `logging`. Resolved: `aws-lc-rs`, `aws_lc_rs`, `prefer-post-quantum`, `std` | 2026-10-24, M1, `fstp-tls` |
| aws-lc-rs | A | 1.18.2 (`=1.18.2`) | `aws-lc-sys`, with default features off. The `aws_lc_rs` feature of rustls and the `aws-lc-rs` feature of rustls-webpki both add `prebuilt-nasm`. Resolved: `aws-lc-sys`, `prebuilt-nasm` | 2026-10-24, M1, `fstp-crypto` and the rustls provider |
| rustls-pki-types | A | 1.15.1 (`=1.15.1`) | `std`, with default features off. Resolved: `alloc`, `default`, `std` | 2026-10-24, M1, `fstp-tls` |
| rustls-webpki | A | 0.103.16 (through rustls) | `alloc`, `aws-lc-rs`, `std` | 2026-10-24, M1, through rustls |

Resolved tree. The runtime and build rows were recorded 2026-10-24 for x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu, and are the same on both. The platform row, added 2026-10-25, covers every other target.

| Role | Crates |
| --- | --- |
| Runtime | `rustls 0.23.46`, `aws-lc-rs 1.18.2`, `aws-lc-sys 0.46.0`, `rustls-pki-types 1.15.1`, `rustls-webpki 0.103.16`, `once_cell 1.21.4`, `subtle 2.6.1`, `untrusted 0.9.0`, `zeroize 1.9.1` |
| Build, for the aws-lc-sys build script only | `cc 1.10.0`, `cmake 0.1.58`, `dunce 1.0.5`, `fs_extra 1.3.0`, `pkg-config 0.3.34`, `find-msvc-tools 0.1.15`, `jobserver 0.1.35`, `libc 0.2.191`, `shlex 2.0.1` |
| Platform, never built for x86_64 or aarch64 Linux | `getrandom 0.4.3`, `cfg-if 1.0.5`, `r-efi 6.0.0` |

Platform note, recorded 2026-10-25:

- deps-check also analyses every target, not only the two Linux platforms. Crates that only another target or a custom cfg reaches carry the role `platform` in `deps/allowlist.txt`.
- jobserver, a dependency of cc in the aws-lc-sys build script, depends on `getrandom 0.4.3` under `cfg(windows)`. getrandom depends on `cfg-if 1.0.5`, and on `r-efi 6.0.0` only for UEFI with a custom `getrandom_backend` cfg.
- deps-check fails if a Linux build ever reaches one of them.

Weak dependency note:

- `ring 0.17.14` appears in `Cargo.lock` and in the `cargo metadata` resolve graph as an optional dependency of rustls-webpki.
- rustls-webpki refers to it only through the weak feature `ring?/alloc`. No enabled feature activates `dep:ring`, so cargo never builds it.
- Verified on 2026-10-24: `cargo tree --locked -i ring --target all -e all` prints nothing, and `tools/deps-check` reports the edge as not activated.
- ring's own dependencies `getrandom 0.2.17` and `windows-sys 0.52.0`, with the `windows-targets 0.52.6` crates below it, are unused for the same reason. They appear only in the lockfile and the resolve graph. `cfg-if 1.0.5` is a dependency of ring too, but getrandom 0.4.3 reaches it on other targets (see the platform note).
- ring is not allowed as a platform provider (see Not allowed). It has no allowlist entry, so deps-check fails if a feature change ever activates it.

Platform crates accepted, recorded 2026-10-25 (M1 decision D5):

- Daniel accepted the six crates with role `platform` on 2026-10-25.
- This ADR covers `getrandom 0.4.3`, `cfg-if 1.0.5` and `r-efi 6.0.0`. ADR-002 covers `windows-sys 0.61.2`, `windows-link 0.2.1` and `wasi 0.11.1+wasi-snapshot-preview1`.

rustls debug assertion note, recorded 2026-10-25 (M1 decision D4):

- In `rustls 0.23.46`, a connection that sent `close_notify` counts as if it had sent a fatal alert. When it then reads an invalid record, rustls queues a fatal alert through `CommonState::send_fatal_alert`.
- That function starts with `debug_assert!(!self.sent_fatal_alert)`. Builds with debug assertions, such as `cargo test` and fuzz builds, panic there.
- Release builds compile the assertion out. The read fails with a typed protocol error from fstp-tls, and the stream stays failed.
- Daniel decided on 2026-10-25 to keep half-close reads in fstp-tls and to document the assertion. Only a corrupted or hostile record after this side's own `close_notify` reaches it.
- The test `d4_invalid_record_after_close_notify` in `crates/fstp-tls/tests/tls.rs` pins both behaviours. Its debug run fails once a rustls update removes the assertion.

TLS session resumption, recorded 2026-10-25 (policy P2 as revised by Daniel on 2026-10-25):

- Resumption is allowed on servers with and without client authentication, and on clients.
- A session can be resumed for at most 1 hour after the full handshake that authenticated it. A chain of resumptions never extends that hour.
- After that hour, a full handshake validates every certificate again.
- fstp-tls keeps resumable sessions in in-house tables on both sides (`crates/fstp-tls/src/resumption.rs`). The server issues no stateless tickets, so no ticket encryption key exists. Nothing in those tables encrypts or derives keys.

Non-cryptographic hashing, recorded 2026-10-25 (M1 decision D6):

- Daniel decided on 2026-10-25 that std's non-cryptographic hashers are acceptable.
- Examples: fstp-json uses `HashMap` with `RandomState` against hash flooding, and fstp-mc uses `DefaultHasher` with fixed keys. Neither use is cryptographic.
