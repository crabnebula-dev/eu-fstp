# ADR-003: Build and test tools

Status: Accepted by Daniel on 2026-10-09. Versions and resolved trees are recorded at first use.

## Context

Daniel allowlisted three build and test tools. None of them ships in runtime artifacts.

## Decision

| Tool | Use | Scope |
| --- | --- | --- |
| TypeScript compiler (tsc) | Type-checking and compiling the in-house frontend | Build time only |
| libFuzzer, driven through cargo-fuzz | Coverage-guided fuzzing of every in-house parser | Test time only |
| Playwright | End-to-end tests per role | Test time only |

## Rules

- Build and test tools never appear in runtime artifacts. The release SBOM distinguishes build-time and runtime components.
- Browser binaries used for end-to-end tests are pinned and fetched through a controlled CI step.
- Each tool records its approved version and resolved dependency tree in this ADR.
