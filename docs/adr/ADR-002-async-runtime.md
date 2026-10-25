# ADR-002: Async runtime

Status: Accepted by Daniel on 2026-10-09. Versions and resolved trees are recorded at first use.

## Context

The platform is built in-house by default. Daniel decided to allowlist an async runtime rather than write one, since it underpins every network-facing component.

## Decision

tokio and smol are both allowlisted.

- Each binary uses exactly one runtime. Mixing runtimes inside one process is not allowed.
- In-house networking code is written against a thin internal trait for spawning, timers and sockets, so a component can move between runtimes without rewriting protocol code.
- The first component that uses a runtime records the chosen runtime, version, enabled features and full resolved dependency tree in this ADR.
- Feature sets stay minimal. Enabling an additional feature needs a review note here.

NOTE: tokio has the wider ecosystem fit with the TLS crates under ADR-001. smol has a smaller dependency tree, which can suit the self-hosted cell and the EUPL export executable.

## Needs

- TCP listeners and clients for HTTP, SMTP, PostgreSQL and adapters.
- Timers for the timeline engine and dispatcher.
- Task scheduling across worker threads.
- Integration with the TLS crate chosen in ADR-001.
- Graceful shutdown for cell restarts and self-hosted updates.

## Record

| Component | Runtime | Version | Features | Tree recorded |
| --- | --- | --- | --- | --- |
| `fstp-rt` (M1), the tokio implementation of the runtime trait. fstp-tls, fstp-http, fstp-pgwire and fstp-migrate reach tokio only through it | tokio | 1.54.1 (`=1.54.1` in the workspace manifest) | `rt`, `rt-multi-thread`, `net`, `time`, with default features off | 2026-10-24: `tokio 1.54.1`, `mio 1.2.4`, `socket2 0.6.5`, `libc 0.2.191`, `pin-project-lite 0.2.17` |

Record notes:

- Resolved feature sets: tokio also lists `libc`, `mio`, `socket2` and `windows-sys`, which are the optional dependencies that `net` enables. mio has `net`, `os-ext` and `os-poll`, socket2 has `all`, libc has `default` and `std`.
- The tree covers x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu and is the same on both. windows-sys is not built on either. tokio has no build dependencies.
- Other targets, recorded 2026-10-25: `windows-sys 0.61.2` and its dependency `windows-link 0.2.1` serve tokio, mio and socket2 on Windows. `wasi 0.11.1+wasi-snapshot-preview1` serves mio on WASI. None of them is built for either Linux platform.
- Daniel accepted the other-target crates `windows-sys 0.61.2`, `windows-link 0.2.1` and `wasi 0.11.1+wasi-snapshot-preview1` on 2026-10-25 (M1 decision D5).
- `deps/allowlist.txt` lists the Linux crates above as runtime packages tied to ADR-002, and the other-target crates with role `platform`. Each entry pins the exact version and the `.crate` SHA-256 from every `Cargo.lock`.
- `deps/adr-roots.txt` records tokio's resolved feature set: `libc`, `mio`, `net`, `rt`, `rt-multi-thread`, `socket2`, `time`, `windows-sys`.
- `tools/deps-check` fails CI when a crate enters this tree, changes version or checksum, or reaches a higher role, and when tokio's resolved features change. It passes again only when the allowlist and the roots file match the new tree, and this record names each allowlisted crate and version. A crate that leaves the tree, or drops to a lower role, produces a warning, not a failure.
