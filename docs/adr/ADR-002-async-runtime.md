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
| (filled at first use) |  |  |  |  |
