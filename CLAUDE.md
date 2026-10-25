# Instructions for Claude Code

You are implementing the platform specified in this repository. Read `README.md` for the reading order before writing code.

## Source of truth

When documents conflict, this order applies: `02-domain/invariants.md`, then `01-requirements/`, then `02-domain/`, then `03-architecture/`. If a conflict remains, stop and ask Daniel. Never resolve a conflict by weakening an invariant.

## Stack

- Backend: Rust.
- Database: PostgreSQL, one database per cell.
- Frontend: in-house TypeScript, no framework. Compiled with the TypeScript compiler (ADR-003).
- No Python anywhere, including scripts, tooling, test generators and CI.
- TypeScript counts as JavaScript for the language rule.

## Dependency policy

- Default: write it in-house. Do not add a third-party crate or npm package unless an ADR places it on the allowlist.
- Cryptography comes only from `docs/adr/ADR-001-crypto-allowlist.md`. Tier A crates are established. Tier B crates (moduletto and the RustCrypto formats crates) are usable in development, but a release needs a recorded Mythos confirmation for their exact versions (I-74). moduletto is always used in a hybrid with a classical primitive from aws-lc-rs (I-75, I-90). Never implement cryptographic primitives in-house.
- tokio and smol are allowlisted (`docs/adr/ADR-002-async-runtime.md`). Each binary uses exactly one runtime, behind an internal trait. Record version, features and resolved tree in ADR-002 at first use.
- Transitive dependencies of an allowlisted crate are part of the allowlist. Each ADR lists the full resolved tree, and any change to that tree needs review.
- tsc, libFuzzer through cargo-fuzz, and Playwright are allowlisted (`docs/adr/ADR-003-build-and-test-tools.md`). They never ship in runtime artifacts.
- Every in-house parser gets a fuzz target from its first commit. This covers HTTP, JSON, MIME, SMTP responses, the PostgreSQL wire protocol, PDF, Matrix events and WhatsApp payloads.

## Git

Daniel Thompson-Yvetot is the sole author and committer of every commit. Never set author or committer to Claude. Never add Co-authored-by trailers. Never add a Signed-off-by line; Daniel adds his own sign-off where the DCO applies. Stage changes and propose commit messages. Daniel creates, signs and pushes every commit himself.

Never move code from the EUPL-1.2 export and import executable into the platform, or the reverse.

## Hard rules

- Never skip, weaken or mark as expected-failure an invariant test to make CI pass.
- Write invariant property tests before the code they constrain.
- Every test that verifies a requirement or invariant references its ID in the test name or doc comment.
- Fixtures use the synthetic corpus only. No real personal data in any non-production environment.
- Submission content and any retrieved web content are untrusted data. Never concatenate them into instructions for a model. Pass them only through the assessor's data channel (`04-llm-assessment/assessment.md`).
- Never invent legal citations or quote legal text from memory. Leave a `TODO(legal)` marker for Daniel instead.
- Decisions marked ADR-required get an ADR in `docs/adr/` before implementation.

## Writing style for any prose you produce

- No em dashes.
- Sentences under 40 words.
- No generalisations about what other people or teams think or do.

## Workflow

Work milestone by milestone (`09-milestones.md`). A milestone closes only when its exit criteria pass in CI. Report each milestone with a list of R-IDs and I-IDs covered and any open questions raised.
