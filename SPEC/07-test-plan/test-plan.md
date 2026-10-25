# Test plan

## Principles

- Invariant tests are written before the code they constrain.
- Every test references the R-, I- or TH- identifier it verifies.
- Only synthetic data is used outside production.
- No invariant test may be skipped or weakened to pass CI.
- Test harnesses are written in-house, except the tools allowlisted in ADR-003.

## Layers

| Layer | Harness | Scope |
| --- | --- | --- |
| Unit | Rust built-in test runner, in-house TypeScript runner | Pure functions, scoring, policy evaluation |
| Property-based | In-house harness with shrinking | Every invariant in `02-domain/invariants.md` |
| Model checking | In-house bounded model checker | State machine, contracts, payment requests, SoD over time |
| Authorisation matrix | Generated from role and policy tables | Every role, action and state combination, allowed and denied |
| Privacy | Canary PII strings | Canaries never reach reviewer views, logs, metrics, inference requests or any messaging channel |
| Isolation | Multi-cell harness | No data path between cells (I-19, I-20) |
| Export and import | Round trip with generated tenants | I-22 equivalence |
| Database | Real PostgreSQL per test run | Migrations forward-only, constraint enforcement, wire protocol conformance |
| Timeline | Simulated clock | Event derivation, recomputation on amendment, time zone rendering, working-day arithmetic across holidays and year ends |
| Dispatcher | Crash injection between send and commit | I-25, I-26 under worker crashes and retries |
| Channels | Recording fakes per adapter | Content rules, group membership, fan-out |
| Fuzzing | libFuzzer through cargo-fuzz (ADR-003) | Every in-house parser and protocol decoder |
| End-to-end | Playwright (ADR-003) | Full call cycle to final payment, SuperSAFE configuration |
| Accessibility | Automated checks plus manual review | R-NF-03 |
| LLM evaluation | `llm-evaluation.md` | Findings quality, injection resistance, fluency invariance |

## Invariant to test mapping (minimum)

| Invariant | Property or model check |
| --- | --- |
| I-01, I-02, I-06 | Random sequences of bindings, unbindings and affiliation changes never yield a violating state |
| I-03 | No read or score action succeeds for a conflicted reviewer |
| I-04 | Random Receiving bindings, affiliation changes, verifications and P-13 edits never leave a held Receiving binding for an account the vault knows to be excluded. Active and suspended bindings count as held; only voided bindings do not |
| I-05 | No payment has the same approver and releaser |
| I-07, I-08, I-09 | Scoring over random weights, thresholds and plan revisions matches a reference implementation |
| I-10 | Fuzzed findings, including adversarial content, never alter state |
| I-11 | All findings in a generated call share one config_id |
| I-12 | Random policy edits after publication leave call outcomes unchanged |
| I-13, I-14 | Random grant sequences never exceed range or cap |
| I-15 | A repeat grant or amendment for a lead whose verified identity, anywhere in the tenant, has an accepted deliverable without a public record under its own call's P-26 is rejected. Under the P-65 option "progress report", a partial claim keeps the record incomplete until the final claim |
| I-16 | Static check: no code path stores funds or initiates transfers from platform-controlled accounts |
| I-17, I-21 | Canary attributes never readable by Judging roles before NEGOTIATION |
| I-18 | No minor-flagged proposal reaches GRANTED without consent record |
| I-22 | Export then import into an empty cell yields equal state |
| I-23, I-24 | Any mutation of a past record or log entry is detected |
| I-25, I-26 | Under random crashes and retries, every sent message maps to one event and no key is delivered twice |
| I-27 | Canary content in proposals and identities never appears in any channel payload |
| I-28, I-29 | Random binding and state sequences never produce a violating group membership after P-35 |
| I-30 | Any byte change to a signed version is detected and rejected |
| I-31 | Random payment request sequences never exceed the contract amount |
| I-32 | No acceptance without passed checks and snapshots |
| I-33 | No release inside the hold window after a bank detail change; a dispute in the window freezes payments |
| I-34, I-35 | Random assignment runs over generated organisations and proximity lists never violate distinctness or proximity |
| I-36 | Generated deferral chains never allow a former reviewer to apply to a call holding a proposal they reviewed |
| I-37 | No calibration run includes a proposal without unrevoked consent; no consent request precedes an outcome notice |
| I-40 | Under crash injection, no notice email exists without a sealed PDF and audit hash |
| I-41, I-42 | Generated programmes in every state never expose non-granted proposals or minors on public pages or the feed |
| I-43 | Random programme and grantee choices never publish above the lower of the two; withdrawal removes the grant from pages and feed |
| P-54 | Generated programmes never show an aggregate covering fewer than P-54 grants |
| I-44 | Generated ledgers with seeded discrepancies always fail document generation |
| I-45, I-50 | Random grant sequences never exceed the action FSTP budget; P-05 above P-58 is rejected |
| I-46 | No generated contract or payment falls after the action end date |
| I-47, I-48, I-49 | Packages and contracts with any missing element or clause fail generation |
| I-51 | Every parameter-bound field in generated Guides matches the frozen policy |
| I-54, SoD-12 | Generated mentoring histories never allow a mentor to review the same grantee team or accept their payment requests |
| I-56, SoD-13 | Under a simulated clock, every complaint gets a recorded response or escalation; no participant in the contested decision is assigned to review it |
| I-57 | Filing complaints never changes scores, ranks or payment states without a remedy record |
| I-58 | Random concurrent request, approval, reduction, withdrawal and release sequences never push paid plus pending above a milestone amount |
| I-59, I-60 | Lines on foreign or superseded milestones are rejected; approvals above requested amounts or reductions without reasons are rejected |
| I-61 | Random amendments never lower a milestone below paid plus pending |
| I-62 | No milestone reaches fully claimed without public deliverables under P-26, under both P-65 options |
| I-63 | Random reallocation sequences preserve every task total and never strand paid or pending amounts |
| I-65, I-66, I-67 | No imported value, failing programme or single-person activation reaches an active programme |
| I-68, I-69, I-70 | Fuzzed branding packages never execute code, never hide mandatory elements and never pass with failing contrast |
| I-71 | Unverified or foreign domains never route to a cell |
| I-72 | Overrides never appear in generated contracts, notices, Guides, funder documents or emails |
| I-74 | A release build with an unconfirmed Tier B version fails in CI |
| I-75 | No code path performs ML-KEM without the X25519 half; differential tests agree with aws-lc-rs ML-KEM |
| I-77, I-79 | Management-role accounts cannot log in or recover through OPAQUE, magic links or email alone |
| I-78 | Every action in the high-risk list fails without a fresh step-up; stale step-ups older than P-71 fail |
| I-80, I-81 | No root key appears in memory dumps, logs or backups; destroyed keys make backup restores fail for the affected data |
| I-82, I-83 | Cross-database queries between cells fail for every role; vault and application databases are never placed on one cluster |
| I-84 | For every tool, the authorisation matrix result through MCP equals the result through the web API |
| I-85, I-86 | High-risk actions and identity data are unreachable through MCP for every role |
| I-87 | Public MCP responses equal public page data for generated programmes in every state |
| I-88, I-89 | Platform-initiated write calls without approval fail; undeclared fields never leave the cell |
| I-90 | Signatures with one valid and one invalid half are rejected everywhere; moduletto and aws-lc-rs ML-DSA verify each other's signatures |
| I-91 | Updates with missing, partial or rotated-out composite signatures are refused by cells and clients |
| I-73 | Templates with seeded personal data are blocked; single-person publication is rejected; templates never carry people or proposal records |
| I-64 | After closure, I-45 headroom grows by exactly the grant's unclaimed balance under "return", and by zero spend under "lapse" |
| I-52 | Guides missing any required section fail generation |
| I-53 | Any change to a published Guide produces a new numbered corrigendum and notifications |
| I-38 | Captured outbound requests from a self-hosted cell contain only permitted fields |
| I-39 | With both services unreachable, a full call cycle, payment and export still complete |
| P-11 handles | No handle value appears on two proposals across generated calls |

## CI gates

- All invariant and authorisation tests green.
- Fuzz targets exist for every in-house parser.
- Allowlisted dependencies only, each with an ADR.
- SBOM generated.
- Fuzz targets run for a fixed minimum duration on each release candidate.
