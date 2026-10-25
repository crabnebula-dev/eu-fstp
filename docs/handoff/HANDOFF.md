# Handoff: FSTP platform build

Written on 2026-10-25 at the end of the cloud session that built M1. It carries the state, the decisions and the next steps into a local Claude Code session. Read it together with `.claude/CLAUDE.md` and `SPEC/README.md`.

## Where things stand

| Item | State |
| --- | --- |
| `main` | Specification import (`d1d7cb3`), M1 (`9b93ca6`), merge of PR #1 (`5f70566`) |
| CI on PR #1 and on `main` | Green: deps-check, fmt and clippy, tests against PostgreSQL 16, fuzz smoke (26 targets, 60 s each) |
| M0 | Done |
| M1 | Done and closed by green CI, as `.claude/CLAUDE.md` requires |
| Branch `m1-decisions-and-spec-move` | Three commits from patches 0003 (M1 decisions), 0004 (move into `SPEC/`) and 0005 (this handoff). Merge only after CI is green. |
| M2 | Designed in `docs/handoff/m2-design.md`. Questions Q1 to Q3 are answered. Q4 to Q19 are open. No M2 code exists yet. |

## How the work was done

- Milestone by milestone, as `SPEC/09-milestones.md` sets out.
- Each milestone went through four steps:
  1. Build, with invariant tests before the code they constrain.
  2. An independent review in which every finding of medium or higher severity came with an executable reproducer.
  3. Fixes, each with a regression test that failed before the fix.
  4. An adversarial verification pass that tried to bypass each fix, then the full gates.
- Commits follow the Git section of `.claude/CLAUDE.md`. Claude stages changes and proposes messages. Daniel creates, signs and pushes every commit.
- New third-party crates need an ADR and a `deps/allowlist.txt` entry with the exact version and checksum. `tools/deps-check` fails CI otherwise.

Gates, run before every proposed commit:

```sh
export FSTP_PG_BIN=/usr/lib/postgresql/16/bin
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run -q -p deps-check --locked
bash crates/fstp-pgwire/tools/gen-sqlstate.sh --check
tools/fuzz-all.sh 60
```

Practical notes:
- PostgreSQL tests start their own server through `fstp-pgtest`, with one server per test binary and a fresh database per test. When run as root, the server runs as the `postgres` user. On macOS, point `FSTP_PG_BIN` at a PostgreSQL 16 installation; this path has only been exercised on Linux.
- Test client certificates for the database roles `fstp_super` and `fstp_app` come from `bash crates/fstp-tls/testdata/gen.sh roles`. Running `gen.sh` with no argument regenerates every fixture, including the CA.
- Fuzzing uses the nightly that `tools/fuzz-all.sh --print-toolchain` prints. It is bumped monthly, or earlier when a fuzz build breaks, with a record line in ADR-003.
- Each PostgreSQL 16 test database costs about 15 MB of disk, so a full run needs a few GB free.

## Decisions taken by Daniel on 2026-10-25

| Topic | Decision | Recorded in |
| --- | --- | --- |
| Money | Decimal strings in the currency's fixed scale (EUR `"1234.50"`), other spellings rejected, never negative | ADR-006 |
| Database authentication | Mutual TLS on every role, `clientcert=verify-full`, one certificate per role, SCRAM-SHA-256-PLUS on top | ADR-005, `fstp-pgtest`, `fstp-pgwire` |
| Hybrid database link | Decided with the hosting provider. It needs a PostgreSQL whose TLS group setting accepts hybrid groups, built against OpenSSL 3.5 or later. PostgreSQL 16 with OpenSSL 3.0 cannot. | ADR-005 |
| rustls debug assertion | rustls 0.23.46 asserts in debug builds when an invalid record arrives after our `close_notify`. Kept and documented. Release builds return a typed error, and CI checks that. | ADR-001 record, `fstp-tls` |
| Platform-role crates | windows-sys, windows-link, wasi, getrandom 0.4.3, cfg-if and r-efi accepted | ADR-001, ADR-002 and ADR-003 records |
| Hashers | std's non-cryptographic hashers are acceptable | ADR-001 record |
| Fuzzing nightly | Bumped monthly with a record line | ADR-003 record |
| HTTP router | Path segments that decode to `/`, `\` or control characters, or still hold `%XX`, get 400 | `fstp-http` |
| Server errors | Display shows severity, SQLSTATE, condition name and schema names only, never the message | `fstp-pgwire` |
| TLS resumption | Allowed at most one hour after the full handshake that authenticated the session | `fstp-tls` |
| SCRAM | Iteration counts below 4096 are refused | `fstp-pgwire` |
| Migration ledger | Configurable schema, default `fstp_migrate`; the runner refuses a schema owned by another role | `fstp-migrate` |
| Dependency gate | Strict: checksums, all platforms and features, no `[patch]`, no cargo config in the repository | `tools/deps-check` |
| Repository layout | Specification in `SPEC/`, `CLAUDE.md` in `.claude/`, ADRs in `docs/adr/` | Patch 0004 |
| M2 Q1, scoring | Integer scale 0 to N per criterion. Mean of reviewers' weighted sums as a fraction of the maximum. P-02 a percentage with two decimals, compared exactly. Weights are positive integers with no required total. | Not yet in the spec |
| M2 Q2, stage 1 close | Closes when every active assignee has a valid score and at least P-03 exist. Released or conflicted reviewers' scores never count. Scores seal at stage exit, reopened only by a complaint remedy. The FSTP coordinator records the close and cannot choose its outcome. | Not yet in the spec |
| M2 Q3, stage 2 | Assigned reviewers rescore a revised plan, and P-03 valid stage 2 scores are needed. The latest scored revision counts. On a P-24 tie the original plan carries forward. When reviewers record "no questions", the window closes at once and the proposal moves on to RANKED. | Not yet in the spec |

The Q3 answer changes a guard in `SPEC/02-domain/state-machine.md`. Under `.claude/CLAUDE.md`, the specification is the source of truth. So the Q1 to Q3 answers go into the spec before M2 code depends on them.

## Defaults taken without an explicit decision

Revisit any of these if they are wrong.

- `fstp-pgwire`: `Config::new` takes a `ClientTls`, which cannot exist without a client certificate. The lower-level `Session::startup` and `tls_handshake` stay public and can run without one; the server still refuses such a login.
- A client certificate whose CN names another role fails like a wrong password (28P01). Only the server log says "CN mismatch".
- TLS resumption details:
  - Within the hour, a resumed session keeps the client certificate it authenticated with, without checking it again.
  - The server issues one ticket per handshake.
  - Store sizes are constants: 1024 server sessions, and 8 tickets for each of 256 server names.
  - Stored session secrets are not zeroed on drop.
  - Tickets advertise 24 hours, because rustls fixes that, but the server refuses them after one hour.
- Migration runner: `verify` and `plan` also refuse a schema owned by another role. `information_schema` is rejected. A schema owned by a group role the migrator belongs to is refused. `SET LOCAL search_path` is still refused.
- SQLSTATE table: the 11 rows for classes 00, 01 and 02 come from the server's `errcodes.txt`, because PL/pgSQL has no names for them. A code without its own name prints as `class <name>`.
- Production client certificates per role: issuance, storage and rotation are not designed yet. This belongs with the hosting work in M3.
- `#[non_exhaustive]` is not yet on `fstp_prop::Failure`, `fstp_json::ParseLimits` or `fstp_json::Limit`. Add it before any release.

## Open items from M1

- Two low-severity review findings are only partly fixed.
  - A panic inside a thread that a property spawns loses its message.
  - The HTTP client loses an early error response when the server stops reading but never closes.
- The `fstp-json` memory budget defaults to 32 MiB. `fstp-pgwire` raises only the input limit for `jsonb`, so a value above about 4 MB of typical JSON fails to decode.
- Spec gaps raised during M1:
  - No test identifiers for the harness self-tests, migrations or HTTP smuggling rules.
  - The "SBOM generated" CI gate predates the SBOM work in M9.
  - R-NF-02 does not say whether IP addresses are identity attributes.
  - ADR-001's moduletto interoperability check cannot run before M9.
  - "SoD over time" needs a bounded clock inside M2 models.
- `main` has no branch protection yet. Recommended: require the `deps-check`, `fmt and clippy`, `tests (PostgreSQL 16)` and `fuzz smoke (60 s per target)` checks before merging.
- The licence texts are not in the repository.

## Next steps

1. Merge `m1-decisions-and-spec-move` once its CI is green.
2. Answer M2 questions Q4 to Q19 in section 12 of `docs/handoff/m2-design.md`. Section 9.3 there lists the strict interim reading for each.
3. Record the answers in the specification, staged for Daniel's commit, before code depends on them.
4. Implement M2 with the work plan in section 10 of the design. Write the invariant tests first, then run an independent review, fixes and a verification pass.
5. M2 closes when I-01 to I-15 and I-23 are green in CI. Section 11 of the design maps each invariant to its tests.
