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

## Record

| Tool | Approved version | Pinned by | Recorded |
| --- | --- | --- | --- |
| cargo-fuzz | 0.13.2, crate SHA-256 `5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2` | `cargo install cargo-fuzz --version 0.13.2 --locked` in CI, which builds it from its published lockfile | 2026-10-24 |
| libfuzzer-sys | 0.4.13, crate SHA-256 `a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2`. Resolved features: `default`, `link_libfuzzer` | `libfuzzer-sys = "=0.4.13"` in each fuzz project manifest (`crates/*/fuzz/Cargo.toml`, `tools/*/fuzz/Cargo.toml`), plus that project's committed `Cargo.lock` | 2026-10-24 |
| Nightly toolchain for fuzzing | `nightly-2026-10-24`, rustc 1.101.0-nightly (48f4b0553 2026-10-23) | `FUZZ_TOOLCHAIN` in `tools/fuzz-all.sh`, which CI installs through rustup | 2026-10-24 |
| TypeScript compiler (tsc) | Recorded at first use |  |  |
| Playwright | Recorded at first use |  |  |

libFuzzer resolved tree. The test and build rows were recorded 2026-10-24 for x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu. They are the same in every fuzz project and on both platforms. The platform row, added 2026-10-25, covers every other target.

| Role | Crates |
| --- | --- |
| Test, linked into fuzz binaries only | `libfuzzer-sys 0.4.13`, `arbitrary 1.5.0` |
| Build script of libfuzzer-sys, test time only | `cc 1.10.0`, `find-msvc-tools 0.1.15`, `jobserver 0.1.35`, `libc 0.2.191`, `shlex 2.0.1` |
| Platform, never built for x86_64 or aarch64 Linux | `getrandom 0.4.3`, `cfg-if 1.0.5`, `r-efi 6.0.0`, through jobserver on Windows (see the ADR-001 platform note) |

Record notes:

- Fuzz projects live at `crates/<crate>/fuzz/` and `tools/<tool>/fuzz/`. Each is its own workspace, with a `[workspace]` table and a committed lockfile, so libFuzzer never enters a runtime build graph. `tools/deps-check/fuzz` fuzzes deps-check's own parsers.
- `tools/fuzz-all.sh` proves before each fuzz build that the project's lockfile is current (`cargo metadata --locked`), and after the runs that the lockfile is unchanged. cargo-fuzz itself has no `--locked` option.
- `deps/allowlist.txt` lists libfuzzer-sys and arbitrary with role `test`. `tools/deps-check` fails CI if either one becomes reachable from a build or runtime path.
- Daniel accepted the platform-row crates `getrandom 0.4.3`, `cfg-if 1.0.5` and `r-efi 6.0.0` on 2026-10-25 (M1 decision D5).
- cargo-fuzz's own dependencies come from its published lockfile and run only on the CI runner. They never appear in a repository lockfile, so deps-check does not see them. The tree below is recorded instead.

cargo-fuzz 0.13.2 resolved tree, recorded 2026-10-25 from the `Cargo.lock` published in the crate. It holds 101 packages, including cargo-fuzz itself. `cargo tree --locked -e normal,build` gives the same split for x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu.

| Part | Crates |
| --- | --- |
| Built by `cargo install` on Linux, 55 crates | `anstream 1.0.0`, `anstyle 1.0.14`, `anstyle-parse 1.0.0`, `anstyle-query 1.1.5`, `anyhow 1.0.102`, `bitflags 2.11.1`, `camino 1.2.2`, `cargo-platform 0.3.3`, `cargo_metadata 0.23.1`, `cfg-if 1.0.4`, `clap 4.6.1`, `clap_builder 4.6.0`, `clap_derive 4.6.1`, `clap_lex 1.1.0`, `colorchoice 1.0.5`, `crossbeam-deque 0.8.6`, `crossbeam-epoch 0.9.18`, `crossbeam-utils 0.8.21`, `current_platform 0.2.0`, `either 1.16.0`, `fastrand 2.4.1`, `getrandom 0.4.2`, `heck 0.5.0`, `is_terminal_polyfill 1.70.2`, `itoa 1.0.18`, `libc 0.2.186`, `linux-raw-sys 0.12.1`, `memchr 2.8.0`, `num_cpus 1.17.0`, `once_cell 1.21.4`, `proc-macro2 1.0.106`, `quote 1.0.45`, `rayon 1.12.0`, `rayon-core 1.13.0`, `rustc_version 0.4.1`, `rustix 1.1.4`, `semver 1.0.28`, `serde 1.0.228`, `serde_core 1.0.228`, `serde_derive 1.0.228`, `serde_json 1.0.150`, `serde_spanned 1.1.1`, `strsim 0.11.1`, `syn 2.0.117`, `tempfile 3.27.0`, `thiserror 2.0.18`, `thiserror-impl 2.0.18`, `toml 1.1.2+spec-1.1.0`, `toml_datetime 1.1.1+spec-1.1.0`, `toml_parser 1.1.2+spec-1.1.0`, `toml_writer 1.1.1+spec-1.1.0`, `unicode-ident 1.0.24`, `utf8parse 0.2.2`, `winnow 1.0.3`, `zmij 1.0.21` |
| In the lockfile only, 45 crates: dev-dependencies of cargo-fuzz, and crates for other targets or for features it does not enable | `aho-corasick 1.1.4`, `anstyle-wincon 3.0.11`, `assert_cmd 2.2.2`, `autocfg 1.5.1`, `bstr 1.12.1`, `difflib 0.4.0`, `equivalent 1.0.2`, `errno 0.3.14`, `float-cmp 0.10.0`, `foldhash 0.1.5`, `hashbrown 0.15.5`, `hashbrown 0.17.1`, `hermit-abi 0.5.2`, `id-arena 2.3.0`, `indexmap 2.14.0`, `leb128fmt 0.1.0`, `log 0.4.29`, `normalize-line-endings 0.3.0`, `num-traits 0.2.19`, `once_cell_polyfill 1.70.2`, `predicates 3.1.4`, `predicates-core 1.0.10`, `predicates-tree 1.0.13`, `prettyplease 0.2.37`, `r-efi 6.0.0`, `regex 1.12.3`, `regex-automata 0.4.14`, `regex-syntax 0.8.10`, `termtree 0.5.1`, `unicode-xid 0.2.6`, `wait-timeout 0.2.1`, `wasip2 1.0.3+wasi-0.2.9`, `wasip3 0.4.0+wasi-0.3.0-rc-2026-01-06`, `wasm-encoder 0.244.0`, `wasm-metadata 0.244.0`, `wasmparser 0.244.0`, `windows-link 0.2.1`, `windows-sys 0.61.2`, `wit-bindgen 0.51.0`, `wit-bindgen 0.57.1`, `wit-bindgen-core 0.51.0`, `wit-bindgen-rust 0.51.0`, `wit-bindgen-rust-macro 0.51.0`, `wit-component 0.244.0`, `wit-parser 0.244.0` |

Fuzzing nightly updates, decided by Daniel on 2026-10-25 (M1 decision D7):

- `FUZZ_TOOLCHAIN` in `tools/fuzz-all.sh` moves to a newer nightly once a month, or earlier when a fuzz build breaks.
- Each move adds a line to the table below. The nightly row in the record table above always names the current pin.

| Date | Nightly | rustc | Reason |
| --- | --- | --- | --- |
| 2026-10-24 | `nightly-2026-10-24` | 1.101.0-nightly (48f4b0553 2026-10-23) | First pin, M1 |
