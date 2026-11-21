# ADR-029: In-house Unicode normalisation

Status: Proposed. Drafted 2026-11-22 by lane L21 `prod/unicode-normaliser`, before its code, as CLAUDE.md asks. Every row is interim, pending Daniel, unless it says otherwise.

## Context

- Daniel decided on 2026-11-21 that identity tuple names are normalised with Unicode NFC plus case folding, in-house, with no new crate (ADR-004, "Decided by Daniel, 2026-11-21: lane L13b's open points").
- Lane L13b left one seam for it: `fstp_vault::codec::tuple_name`, and the tuple label `fstp-identity-tuple-v1` (ADR-004, record of lane L13b, rows "Tuple" and "Normaliser seam"). Its estimate of the tables is in ADR-004, "NFC and case folding: what an in-house normaliser needs".
- CLAUDE.md: no third-party crate without an ADR allowlist, no Python anywhere, and every in-house parser gets a fuzz target from its first commit.
- No workspace crate applies a normalisation form or full case folding today. `fstp_api_core::display_name::normalised` trims, collapses and lower-cases only.

## Decision

| Topic | Decision (interim, pending Daniel) | Basis |
| --- | --- | --- |
| Unicode version | 18.0.0, the latest final version of the Unicode Character Database on 2026-11-22. The version is a constant of the crate, `fstp_unorm::UNICODE_VERSION` | Latest stable with data files |
| Data files | `UnicodeData.txt` (canonical decompositions and combining classes), `CompositionExclusions.txt` (script-specific and post-composition exclusions), `CaseFolding.txt` (statuses C and F), and `NormalizationTest.txt` (conformance, test only). `DerivedNormalizationProps.txt` is not vendored: the generator derives the full composition exclusion from the first two files, and the conformance test proves the result | UAX #15; UAX #44 |
| Where they live | `third_party/unicode/18.0.0/`, with the licence file `license.txt` beside them, unchanged from `https://www.unicode.org/Public/18.0.0/ucd/` and `https://www.unicode.org/license.txt` | Provenance |
| Licence | Unicode License v3, as printed in `third_party/unicode/18.0.0/license.txt`. Pending Daniel: licence review, for the vendored files and for the tables derived from them. `TODO(legal)`: whether the derived tables need the notice in a shipped artefact | Unicode License v3 |
| Crate | `crates/fstp-unorm`, in-house, with no dependency at all. It offers `nfd`, `nfc`, `casefold` and `fold_nfc` over `&str`. It never panics and does no I/O | CLAUDE.md dependency policy |
| Decomposition | Canonical decomposition from `UnicodeData.txt` field 5 without a `<tag>`, applied recursively. Hangul syllables are decomposed by computation (Unicode chapter 3.12), so they need no table | UAX #15 |
| Ordering | Each run of non-starters is sorted by combining class with a stable sort, so equal classes keep their order | Canonical Ordering Algorithm |
| Composition | The Canonical Composition Algorithm over primary composites. A pair is a primary composite when its canonical decomposition has two code points and it is not fully excluded. The full exclusion is the union of `CompositionExclusions.txt`, the singleton decompositions, and the non-starter decompositions. Hangul LV and LVT syllables compose by computation | UAX #15 |
| Case folding | Full case folding: status C and F of `CaseFolding.txt`. Status S and T are not used, so the folding is the same for every language | `CaseFolding.txt` header |
| Match key | `fold_nfc(s) = NFC(casefold(NFD(s)))`. The standard canonical caseless match key is `NFD(casefold(NFD(s)))` (Unicode chapter 3.13, D145). NFC of a string is unique for its canonical equivalence class, as NFD is. So two strings have equal `fold_nfc` exactly when they have equal canonical caseless keys. The NFC form is shorter, and it is the form the tuple stores | Unicode chapter 3.13 |
| Stability | A test proves `fold_nfc(fold_nfc(s)) == fold_nfc(s)` for every code point alone, for every code point before and after each of a set of combining marks, for the conformance strings, and for random strings. It also proves `nfc(nfc(s)) == nfc(s)` | Brief of lane L21 |
| Expansion bound | `nfc` and `fold_nfc` never return more than `MAX_EXPANSION` times the input length in UTF-8 bytes. The bound is computed over every code point by a test, so a new Unicode version that breaks it fails the test | Bounded output |
| Tables | Sorted arrays of packed `u64` values, searched by binary search: combining class ranges, one-level canonical decompositions, primary composites, and simple case foldings. The few full case foldings of more than one code point sit in a small table of their own. About 41 KB of static data: 422 class ranges, 2,081 decompositions, 961 composites, 1,501 one-point foldings and 105 longer foldings | Compact tables |
| Generator | `tools/unorm-gen`, a Rust binary with no dependency. It reads the vendored files and writes `crates/fstp-unorm/src/tables.rs`. With `--check` it compares instead and writes nothing. It prints nothing (R-NF-02) and answers with its exit status only: 0 for success, 1 for a stale or missing table file under `--check`, 2 for a usage, I/O or parse error. No Python and no shell parsing | CLAUDE.md |
| Committed tables | The generated `tables.rs` is committed, so the build needs no network and no generator run. A test of `fstp-unorm` generates the tables again from the vendored files and compares them byte for byte with the committed file | Reproducible build |
| Conformance | Every line of `NormalizationTest.txt` for NFC and NFD: `c2 == NFC(c1) == NFC(c2) == NFC(c3)`, `c4 == NFC(c4) == NFC(c5)`, `c3 == NFD(c1) == NFD(c2) == NFD(c3)`, `c5 == NFD(c4) == NFD(c5)`. Every code point that Part 1 does not list is its own NFC and NFD | UAX #15 conformance |
| Fuzzing | `crates/fstp-unorm/fuzz`, target `fold_nfc`: any UTF-8 input through every form, checking idempotence, the expansion bound and canonical equivalence of NFC and NFD. `tools/unorm-gen/fuzz`, target `ucd_parse`: any input through each file parser. Both crates join `deps/fuzz-required.txt` | CLAUDE.md fuzz rule; TH-26 |
| Dependencies | None. `fstp-unorm` and `unorm-gen` are in-house workspace members, and their fuzz projects take only `libfuzzer-sys`, as every fuzz project does (ADR-003) | CLAUDE.md dependency policy |

## Wiring into the identity tuple

`fstp_vault::codec::tuple_name` lives on branch `prod/identity-registration` (lane L13b), which had not merged into `main` when lane L21 finished. The wiring is a one-function follow-up once it merges:

- `tuple_name(s)` becomes `fstp_unorm::fold_nfc` of the trimmed, collapsed name. The white space collapse runs first, then `fold_nfc`. `fold_nfc` turns no character that is not white space into white space (test `adr029_fold_nfc_makes_no_white_space`), so no new run of white space appears after the collapse.
- The tuple label becomes `fstp-identity-tuple-v2`, and ADR-004's row "Normalisation" changes with it.
- Stored tuples are recomputed and the match keys rekeyed, and pilot vaults are recreated (ADR-004, record of lane L13b).

## Vendored files

The SHA-256 of each file as downloaded on 2026-11-22:

| File | SHA-256 |
| --- | --- |
| `UnicodeData.txt` | `0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950` |
| `CompositionExclusions.txt` | `c759b100e9ae8960ae6b50fc5765950a7581fd9f30d4ef95f68f25a6d97e818e` |
| `CaseFolding.txt` | `a004797658a457bec4dc11683e39f69249ea3b595b752dbea6721c4c9f587b0d` |
| `NormalizationTest.txt` | `25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3` |
| `license.txt` | `e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96` |

## Open points, pending Daniel

- Licence review of the vendored Unicode files and the derived tables (Unicode License v3). `TODO(legal)` on the notice in shipped artefacts.
- The Unicode version moves only by a new row here: new files under `third_party/unicode/<version>/`, a fresh generation, and a new tuple label, since a new version may change a fold.
- Compatibility forms (NFKC) are not used. Two names that differ only by a compatibility character, such as a ligature or a full-width letter, stay two identities. This over-separates and never merges two persons, as ADR-004 already accepts for the first label.
