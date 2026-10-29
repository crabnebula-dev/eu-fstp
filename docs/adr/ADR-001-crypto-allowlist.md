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

- Authentication crates: webauthn-rs and opaque-ke are candidates for Tier A, subject to review of their audit status (O-36 resolved in `SPEC/03-architecture/authentication.md`).
  - Closed by A4 below, in the amendment of 2026-10-28 that Daniel accepted on 2026-10-28.
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
| zeroize | A tree, root since A1 | 1.9.1 (`=1.9.1`) | Default features, which enable `alloc`. Resolved: `alloc`, `default`. `derive` is refused | 2026-10-28, M3 lane W0: direct dependency of `fstp-crypto`, `fstp-keys`, `fstp-custody` and `fstp-keyd` |
| moduletto | B | 0.1.0, git commit `6c1ae92f2bf14eb56b5d48d1e7fc6f7ca5843683` (moved 2026-10-29 from `46754f2fccb0a501be278fb2fab63b670101a33d`, A2 pin move record) | Default features only. Resolved: `alloc`, `default`, `libm`, `std` | 2026-10-28, M3 lane W0: `fstp-crypto` only (A2) |

Resolved tree. The runtime and build rows were recorded 2026-10-24 for x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu, and are the same on both. The platform row, added 2026-10-25, covers every other target.

| Role | Crates |
| --- | --- |
| Runtime | `rustls 0.23.46`, `aws-lc-rs 1.18.2`, `aws-lc-sys 0.46.0`, `rustls-pki-types 1.15.1`, `rustls-webpki 0.103.16`, `once_cell 1.21.4`, `subtle 2.6.1`, `untrusted 0.9.0`, `zeroize 1.9.1`, and since 2026-10-28 `moduletto 0.1.0` and `libm 0.2.16` |
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

M3 first-use record, 2026-10-28 (lane W0, the dependency owner of design section 2.5):

- The tree covers x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu and is the same on both. It holds every package of the M1 rows above, plus `moduletto 0.1.0` and `libm 0.2.16`. No build or platform crate was added.
- `moduletto 0.1.0` comes from the git source of A2 and A3, with no checksum in `Cargo.lock`. `deps/allowlist.txt` records that source string byte for byte. cargo serves it from `$CARGO_HOME/git/checkouts/moduletto-<hash>/46754f2/`.
- `deps/adr-roots.txt` gains `moduletto ADR-001 alloc,default,libm,std`. Only `fstp-crypto` depends on it, as layering rule 8 requires.
- `deps/tier-b-confirmations.txt` keeps its `tier-b moduletto` marker and holds no confirmation. A development run of deps-check reports moduletto as an unconfirmed Tier B crate and passes. `deps-check --release` fails on it (I-74).
- `subtle 2.6.1` now has the feature `core_hint_black_box`, which moduletto enables. rustls enabled none. subtle has no dependencies, so the tree does not grow.
- `libm 0.2.16` resolves with `arch` and `default` and has no dependencies. It enters through moduletto's `alloc` feature.
- `zeroize 1.9.1` is unchanged in version, checksum and features (`alloc`, `default`). A1 names `fstp-custody` and `fstp-keyd` as direct users. Design sections 2.2 and 3.2 also give secret types that zeroize on drop to `fstp-crypto` and to `fstp-keys` (`open_blob` returns `Zeroizing<Vec<u8>>`). This line records those two crates as direct users too, as A1 asks of any further crate.
- Test-only edges, with no new package and no feature change: `fstp-celltest` takes aws-lc-rs as a normal dependency for the ML-KEM-768, ML-DSA-65 and X25519 oracles in its library (A6). The crate is test only and never ships (layering rule 9). `fstp-pki` takes aws-lc-rs, rustls-pki-types and rustls-webpki as dev-dependencies for its round-trip tests. rustls-webpki does not re-export rustls-pki-types, and its path validation takes `UnixTime` and `CertificateDer` from that crate. This test-only edge is outside the "no rustls-pki-types edge from fstp-pki" rule of design section 2.5, which concerns PEM in production code. The `fstp-pki` fuzz project, a separate workspace, takes rustls-pki-types 1.15.1 and rustls-webpki 0.103.16 with the workspace features for its `cert_build_roundtrip` target (design section 15). Its `Cargo.lock` gains only entries that the workspace `Cargo.lock` already holds. rustls-webpki keeps the resolved set `alloc`, `aws-lc-rs`, `std`, and rustls-pki-types keeps `alloc`, `default`, `std`.

## Amendment of 2026-10-28: M3 dependencies

Status: Accepted 2026-10-28 (Daniel Thompson-Yvetot).

This section records the dependency decisions of the M3 design (`docs/handoff/m3-design.md`, sections 2.1, 2.4, 2.5, 2.6, 8.1 and 15). It follows Daniel's answers of 2026-10-28 to Q1 (C), Q10 (A) and Q23 (Accept), in design section 21.0. A2 also records his later answer of 2026-10-28 on the moduletto repository and on ML-DSA-65. Daniel accepted this section on 2026-10-28, A8 included. A7 stays interim, pending Daniel (Q24). The text above stays as accepted.

### A1. zeroize as a root (Q23)

- `zeroize 1.9.1` becomes a direct dependency of `fstp-custody` and `fstp-keyd` (design section 2.1). In-house code then wipes key material without writing `unsafe`.
- It is already in this ADR's runtime tree through aws-lc-rs, rustls and rustls-pki-types. `deps/allowlist.txt` already pins it with `.crate` SHA-256 `e13084392c5e4bc371903e2935a5eaeed24905a7511356b883835e18a78f6879`. Version and checksum do not change.
- New line in `deps/adr-roots.txt`: `zeroize ADR-001 alloc,default`, with the note "Tier A tree: secret wiping in fstp-custody and fstp-keyd".
- Features: `alloc` and `default` only. In zeroize 1.9.1, `default` enables `alloc` and nothing else. The tree resolved these two features on 2026-10-28 (`cargo tree --locked -e features -i zeroize`), so the root line matches the current tree.
- `derive` is refused. It would add `zeroize_derive` and the proc-macro crates `syn`, `quote` and `proc-macro2`. Every other feature is refused too, and deps-check already fails on any change to a root's features.
- zeroize is not a cryptographic primitive. It sits under this ADR because its tree already contains it.
- Another in-house crate that names zeroize directly needs a line in this record first.

### A2. moduletto as a git dependency (Q1 C)

moduletto is not on crates.io for M3. Daniel chose a git dependency, pinned to one full commit. On 2026-10-28 he supplied the repository and decided how ML-DSA-65 is added.

| Item | Value |
| --- | --- |
| Repository URL | `https://github.com/crabnebula-dev/moduletto` (Daniel, 2026-10-28). The repository is public, so CI fetches it without credentials |
| Main branch head on 2026-10-28 | `46754f2fccb0a501be278fb2fab63b670101a33d`. This is a reference point, not the pin |
| Commit (full id, as `Cargo.lock` records it) | `46754f2fccb0a501be278fb2fab63b670101a33d`, the main branch head above, committed 2026-10-10 ("Merge pull request #10"). Recorded 2026-10-28 by the M3 dependency owner (lane W0), so that W1h writes code against it. Lockfile source: `git+https://github.com/crabnebula-dev/moduletto?rev=46754f2fccb0a501be278fb2fab63b670101a33d#46754f2fccb0a501be278fb2fab63b670101a33d` |
| Version in moduletto's manifest | `0.1.0` at the pinned commit (recorded 2026-10-28) |
| Primitives at the head above | ML-KEM-512 and ML-KEM-768 (FIPS 203), with deterministic `keygen_derand` and `encaps_derand` entry points. No ML-DSA |
| Primitives the platform uses | ML-KEM-768 now. ML-DSA-65 (FIPS 204) once the pull request below lands. ML-KEM-512 is not used |
| Features | `default` only in the manifest. Resolved 2026-10-28: `alloc`, `default`, `libm`, `std`. The `kem` module needs `std`. `getrandom`, `wasm` and `valgrind-ct` are refused, since system randomness comes from aws-lc-rs (Tier A) |
| Resolved tree | Recorded 2026-10-28: `subtle 2.6.1` (feature `core_hint_black_box`), `libm 0.2.16` (features `arch`, `default`; no dependencies), and `zeroize 1.9.1` (already allowlisted, A1). Checksums are in `deps/allowlist.txt` |
| First use | 2026-10-28, M3 lane W0: the dependency line of `fstp-crypto`. No code calls it yet. W1h writes the `mlkem` and `hybrid_kem` modules against it |

ML-DSA-65 (Daniel, 2026-10-28):

- moduletto has no ML-DSA-65 at the head above. Daniel decided that ML-DSA-65 (FIPS 204) is added to moduletto itself.
- Claude writes that change as a pull request on the moduletto repository. Daniel reviews and merges it.
- Until it lands, the ML-DSA half sits behind the `fstp-crypto` seam. Composite signing refuses with a typed error.
- There is no fallback to aws-lc-rs ML-DSA in production. aws-lc-rs ML-DSA stays a test oracle only, reached from `fstp-celltest` (layering rule 9, A6).
- The hybrid rule holds throughout. Nothing signs with Ed25519 alone in place of a composite (I-75, I-90).
- Once the pull request is merged, the pin moves to a commit that contains it. That move is a new commit, so it needs a new tree record here and a new I-74 confirmation before any release.
- Proposed scope of the pull request, for Daniel's review: deterministic key generation from a seed and signing with explicit randomness, so the ACVP keyGen, sigGen and sigVer vectors run against moduletto. A new crate in its dependency tree is a tree change and needs review here first.

Tree:

- `subtle 2.6` and `libm 0.2` are accepted as part of moduletto's allowlisted tree (Daniel, 2026-10-28). Transitive dependencies of an allowlisted crate are part of the allowlist, so each gets its own `deps/allowlist.txt` entry.
- `subtle 2.6.1` is already in the runtime tree through rustls. At the head above, moduletto enables subtle's `core_hint_black_box` feature. Any resulting feature change on subtle is recorded at first use.
- moduletto declares zeroize with default features off. The A1 root line for zeroize is unchanged.
- moduletto's development dependencies are not part of the platform tree. Cargo does not resolve them for a dependency.
- Any other crate in the resolved tree, or any change to it, needs review here before the pin moves.

Pinning:

- The workspace manifest declares moduletto once, with `git = "https://github.com/crabnebula-dev/moduletto"` and `rev = "<full commit id>"`. A branch, a tag or a shortened rev is refused.
- Only `fstp-crypto` depends on it (layering rule 8, design section 2.4). The modules `mlkem`, `mldsa`, `hybrid_kem` and `composite` use it (design section 2.2). Until the pull request lands, `mldsa` and `composite` refuse every signing and verifying call with a typed error.
- With that manifest, `Cargo.lock` records `source = "git+<URL>?rev=<commit>#<commit>"` and no checksum. This form was checked with cargo on 2026-10-28 against a local test repository.
- Cargo places a git checkout at `$CARGO_HOME/git/checkouts/<name>-<hash>/<short commit>/`. This was checked the same way.
- If the repository is a workspace, each package cargo takes from it shares the same source string. Each one gets its own allowlist entry and appears in the tree record.
- Each crate that moduletto brings from crates.io is part of this allowlist. It is pinned by name, version and `.crate` SHA-256, as today. A crate from any other git source is refused (A3).
- The hybrid rule (I-75, I-90) and the release gate (I-74) apply unchanged. A new commit counts as a version change for the release gate, even when the manifest version stays the same.
- Until the pin exists (design section 17.2), production code waits for it. Tests use the aws-lc-rs ML-KEM and ML-DSA oracles through `fstp-celltest` only. No classical fallback ships (I-75).
- Deterministic entry points (Q1 sub-question): answered for ML-KEM by `keygen_derand` and `encaps_derand`. ML-KEM-768 ACVP and combiner vectors therefore run against moduletto. For ML-DSA-65 the answer follows the pull request.

Pin move record, 2026-10-29 (the M3 dependency owner, design section 2.5):

- Daniel merged moduletto pull request #13 (ML-DSA-65, FIPS 204) on 2026-10-29. Its merge commit is `6c1ae92f2bf14eb56b5d48d1e7fc6f7ca5843683` ("Merge pull request #13 from crabnebula-dev/ml-dsa-65").
- The pin moves from `46754f2fccb0a501be278fb2fab63b670101a33d` to that commit. Lockfile source: `git+https://github.com/crabnebula-dev/moduletto?rev=6c1ae92f2bf14eb56b5d48d1e7fc6f7ca5843683#6c1ae92f2bf14eb56b5d48d1e7fc6f7ca5843683`. The workspace `Cargo.lock`, every fuzz project `Cargo.lock` and `deps/allowlist.txt` record that string.
- The manifest version stays `0.1.0`. The move still counts as a version change for the release gate (Pinning, below). `deps/tier-b-confirmations.txt` holds no confirmation for the new commit, so `deps-check --release` fails on it (I-74).
- Manifest changes between the two commits: the description, comments, a new `ct-bench` feature, and the required features of the `ct_dudect` example. The dependency lines are unchanged.
- Features: `default` only, as before. Resolved: `alloc`, `default`, `libm`, `std`, unchanged (`cargo tree --locked -e features -i moduletto`, 2026-10-29). `ct-bench` is refused, like `valgrind-ct`. It exposes the signing-loop count for the timing test and is not for production.
- Resolved tree: unchanged. moduletto brings `libm 0.2.16`, `subtle 2.6.1` and `zeroize 1.9.1`, with the versions, checksums and features recorded above (`cargo tree --locked -e normal -p moduletto`, 2026-10-29). No package enters or leaves the platform tree.
- Primitives at the new pin: ML-KEM-512 and ML-KEM-768 (FIPS 203), and ML-DSA-65 (FIPS 204). ML-DSA-65 has deterministic key generation from a seed and signing with explicit randomness. Its ACVP keyGen, sigGen and sigVer vectors run in moduletto's own tests at that commit.
- `mldsa` and `composite` in `fstp-crypto` may now call moduletto's ML-DSA-65. The aws-lc-rs ML-DSA stays a test oracle only (A6).

### A3. deps-check git-source rule

Today `tools/deps-check` refuses every source other than crates.io (the `non-crates-io-source` check in `src/provenance.rs`). This amendment adds one exception and nothing else.

- `deps/allowlist.txt` gains a git entry form. The checksum field holds the exact lockfile source string, `git+<URL>?rev=<commit>#<commit>`, in place of the `.crate` SHA-256. That one token records both the repository URL and the commit.
- A lockfile package with a `git+` source passes only when an allowlist entry names the same crate, the same version and the same source string, byte for byte.
- Every other git source fails. That includes another URL, another commit, a branch or tag reference, a shortened rev and the same commit at another URL. A git package that carries a checksum fails too, since cargo writes none.
- Path sources outside the repository, other registries and source replacement stay refused, as today.
- The resolve graph must place each git package under cargo's git checkout directory, at the recorded short commit. A `paths` override or source replacement then cannot shadow it.
- Only moduletto, and packages from its recorded repository, may use the git form under this amendment. Any other git entry needs its own ADR record first.
- Proposed tests: `th15_git_source_refuses_unlisted_url`, `th15_git_source_refuses_other_commit`, `th15_git_source_refuses_branch_or_tag_reference` and `th15_git_source_accepts_only_the_recorded_source`. Each gets a failing fixture, as the existing provenance tests do.
- The lockfile reader's existing fuzz target (`tools/deps-check/fuzz`, `cargo_lock`) covers the new source-string parsing.
- Open: a git commit id is a SHA-1 object id unless the repository uses SHA-256 object format. Should this record also hold a SHA-256 digest over the checked-out source, with deps-check checking it? This is raised for Daniel and not decided here.

### A4. Authentication crates (Q10 A)

This closes the "Open points" line on authentication crates. `SPEC/03-architecture/authentication.md` says these crates are chosen in this ADR.

- WebAuthn is built in-house in `fstp-webauthn`, a pure crate with no I/O (design sections 2.1 and 8.1). webauthn-rs is not used.
- It composes aws-lc-rs and implements no primitive. Signature verification covers ES256 (ECDSA P-256 with SHA-256), EdDSA (Ed25519) and RS256 (RSA PKCS#1 v1.5 with SHA-256, keys of at least 2048 bits).
- RS256 here is verification through aws-lc-rs. The Tier A row above names RSA signing; this amendment adds RSA verification as a use. The RustCrypto `rsa` crate stays not allowed.
- Attestation format `none` only. No attestation certificate is parsed, so no Tier B formats crate enters this path.
- The CBOR and COSE parsers have fuzz targets from their first commit, as `authentication.md` asks. The targets are `cbor_decode`, `cose_key_decode`, `authenticator_data_decode`, `client_data_decode`, `attestation_object_decode`, `assertion_verify` and `registration_verify` (design section 15).
- Magic links need no new crate.
- OPAQUE is deferred. opaque-ke is not used. A later addition to this ADR must cover OPAQUE and its group arithmetic before any OPAQUE code is written.
- EUDI Wallet login and verification move to M4 (Q10).
- ADR-008 holds the implementation details: methods, ceremonies, step-up binding and recovery.

New row for the Uses table:

| Use | Construction |
| --- | --- |
| WebAuthn registration and assertion | ES256, EdDSA and RS256 verification through aws-lc-rs. CBOR, COSE, authenticator data and client data parsed in-house in `fstp-webauthn`, each with a fuzz target |

### A5. Tier B confirmation mirror (design section 2.6)

M3 brings moduletto into production code, so the release gate above is built now (I-74, R-CR-02).

- `deps/tier-b-confirmations.txt` mirrors the confirmation table of the release gate, row for row. Each line holds crate, version, source hash, confirmation date and findings reference.
- The same file names each Tier B crate of the Tier B table above. Design section 2.6 places that marker in `deps/allowlist.txt`; the lead may keep it there instead. Either way, one test checks the marker list against the Tier B table here.
- A test checks that the mirror equals the confirmation rows of this ADR.
- The source hash of a crates.io package must equal the `.crate` SHA-256 that `deps/allowlist.txt` pins. For moduletto it must equal the full commit id in the allowlist source string (A3).
- `tools/deps-check/src/tier_b.rs` reads the resolved tree of each shipped `[[bin]]` target. Every Tier B package there needs a confirmation for its exact version and source hash.
- `deps-check --release` fails without a matching confirmation. Development and test builds report the missing confirmation and pass, since Tier B use in development is allowed.
- The release workflow job runs `deps-check --release` on a tag pattern only, because M3 ships no release. Its fixture test runs on every push.
- Tests: `i74_release_gate_refuses_unconfirmed_tier_b_version`, `i74_release_gate_refuses_a_confirmation_for_another_hash`, `i74_dev_build_reports_but_passes` and `i74_teeth_gate_skipping_tier_b_is_caught`.
- The mirror's parser has the fuzz target `tier_b_confirmations_decode` in `tools/deps-check/fuzz`.
- The confirmation table above stays at "(none yet)". No confirmation is recorded in M3.

### A6. No aws-lc-rs feature change

- aws-lc-rs stays at 1.18.2 with `aws-lc-sys` and `prebuilt-nasm`. The `unstable` feature is not enabled.
- The test oracles need nothing more. In 1.18.2, `signature::ML_DSA_65` (`src/signature.rs:1172`), `signature::ML_DSA_65_SIGNING` (`:1185`), `PqdsaKeyPair::from_seed` (`src/pqdsa/key_pair.rs:175`) and `kem::ML_KEM_768` (`src/kem.rs:85`) are public without a feature gate. Checked in the registry source on 2026-10-28.
- For key wrapping and signatures, these aws-lc-rs post-quantum APIs serve only as test oracles from `fstp-celltest` (layering rule 9, design section 2.4). moduletto is the post-quantum half there in production, as this ADR names it. Its ML-DSA-65 waits on the pull request of A2, and aws-lc-rs ML-DSA is never a production fallback (Daniel, 2026-10-28).
- TLS is the exception. `fstp-tls` already negotiates X25519MLKEM768 in production through the rustls aws-lc-rs provider, so its ML-KEM half comes from aws-lc-rs. A7 records this gap.

### A7. The TLS key exchange group (Q24)

Interim, pending Daniel. Q24 is not answered. This records the design's interim reading, option A.

- The Uses row "TLS key exchange" names a custom group with ML-KEM-768 from moduletto. Since M1, `fstp-tls` instead uses the X25519MLKEM768 group of the rustls aws-lc-rs provider (rustls feature `prefer-post-quantum`, Record above). Its ML-KEM-768 half comes from aws-lc-rs.
- The hybrid rule still holds for this group: X25519 and ML-KEM-768 are both always used. No moduletto primitive is involved, so I-75 and the I-74 release gate are not engaged by it.
- Interim reading of Q24 (option A): the custom group with moduletto's ML-KEM-768 is built in M9, with the ACVP work. The Uses row stays as the target until then, and this section records the gap.
- Option B, building the custom group in M3 beside key wrapping, is open to Daniel.
- The Verification line "The custom TLS group interoperates with the aws-lc-rs X25519MLKEM768 group in both directions" applies once the custom group exists.

### A8. Further aws-lc-rs uses (ADR-004 completion parts 1 and 2)

ADR-004's drafts of 2026-10-28 use two aws-lc-rs functions that the Tier A row above does not name. This section adds them as uses. It adds no crate and no feature. Both were found in the aws-lc-rs 1.18.2 registry source on 2026-10-28 without a feature gate.

| Use | Construction | Status |
| --- | --- | --- |
| File custody key table (`fstp-keyd`, ADR-004 part 2) | PBKDF2-HMAC-SHA-256 through `aws_lc_rs::pbkdf2` (`PBKDF2_HMAC_SHA256`, `src/pbkdf2.rs:129`), at least 600 000 iterations, random salt | Accepted 2026-10-28 with this section |
| AEAD fallback (ADR-004 part 1, Nonce rule) | AES-256-GCM-SIV through `aws_lc_rs::aead::RandomizedNonceKey` (`AES_256_GCM_SIV`, `src/aead/aes_gcm.rs:35`, accepted at `src/aead/rand_nonce.rs:46`) | Conditional. Used only if H-19 asks for misuse resistance, and only through a new `aead` code that ADR-004 assigns |

- Neither function is a new primitive in our code. Both are reached only through `fstp-crypto`. Its `aead` module would take the GCM-SIV algorithm.
- PBKDF2 is not new to the tree. `fstp-crypto` has exposed `pbkdf2_hmac_sha256` over `aws_lc_rs::pbkdf2` since M1, and `fstp-pgwire` uses it for SCRAM. The row above records that function as a use and adds the file custody use. `fstp-keyd` calls the existing wrapper, so no new wrapper is written.
- The PBKDF2 iteration floor and parameters are fixed in ADR-004, not here.
