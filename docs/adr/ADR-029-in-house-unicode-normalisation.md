# ADR-029: In-house Unicode normalisation

Status: Accepted in part. Drafted 2026-11-22 by lane L21 `prod/unicode-normaliser`, before its code, as CLAUDE.md asks. Daniel decided the licence, the compatibility forms and the Unicode version on 2026-11-21 (section "Decided by Daniel"). Every other row is interim, pending Daniel, unless it says otherwise.

## Context

- Daniel decided on 2026-11-21 that identity tuple names are normalised with Unicode NFC plus case folding, in-house, with no new crate (ADR-004, "Decided by Daniel, 2026-11-21: lane L13b's open points").
- Lane L13b left one seam for it: `fstp_vault::codec::tuple_name`, and the tuple label `fstp-identity-tuple-v1` (ADR-004, record of lane L13b, rows "Tuple" and "Normaliser seam"). Its estimate of the tables is in ADR-004, "NFC and case folding: what an in-house normaliser needs".
- CLAUDE.md: no third-party crate without an ADR allowlist, no Python anywhere, and every in-house parser gets a fuzz target from its first commit.
- No workspace crate applies a normalisation form or full case folding today. `fstp_api_core::display_name::normalised` trims, collapses and lower-cases only.

## Decided by Daniel on 2026-11-21

- **Licence.** Decided by Daniel on 2026-11-21: Unicode License v3 accepted; the notice ships in the product's third-party notices. The repository had no third-party notices file, so lane L21 created `THIRD_PARTY_NOTICES.md` at the root with this entry.
- **Compatibility forms.** Decided by Daniel on 2026-11-21: compatibility forms match. Two names that differ only by a compatibility character, such as a ligature or a full-width letter, are one name. The tuple uses the compatibility caseless key `fold_nfkc` (row "Match key"). NFC and NFD stay in the crate.
- **Unicode version.** Decided by Daniel on 2026-11-21: 18.0.0, the lead's reading, unless a newer final exists. On 2026-11-22 the newest final version on `https://www.unicode.org/Public/` was 18.0.0.

## Lead decisions, 2026-11-22

- **Key construction.** The construction of `fold_nfkc` in row "Match key" is accepted as the lead's reading. It matches the Unicode `NFKC_CF` mapping for every code point.
- **Notices.** `THIRD_PARTY_NOTICES.md` lists every third-party component: the Unicode data, the fonts (IBM Plex Sans of ADR-017, and the Lohit fonts named in LibPDF's FontBox licence), the vendored LibPDF of ADR-016, the allowlisted crates with the licences their manifests declare, and the npm build and test tools. The release step that ships the file, with the full licence texts of the crates, comes later.
- **Wiring.** `prod/identity-registration` merged into `main` (PR 35), so lane L21 wired the normaliser into the tuple. See section "Wiring into the identity tuple".

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| Unicode version | 18.0.0, the latest final version of the Unicode Character Database on 2026-11-22. The version is a constant of the crate, `fstp_unorm::UNICODE_VERSION`. Decided by Daniel on 2026-11-21 | Latest stable with data files |
| Data files | `UnicodeData.txt` (canonical and compatibility decompositions, combining classes), `CompositionExclusions.txt` (script-specific and post-composition exclusions), `CaseFolding.txt` (statuses C and F), `DerivedNormalizationProps.txt` (the `NFKC_CF` mapping: its empty mappings give the removed code points, and the whole mapping is a test oracle), and `NormalizationTest.txt` (conformance, test only). The generator derives the full composition exclusion from the first two files, and the conformance test proves the result. Interim, pending Daniel | UAX #15; UAX #44 |
| Where they live | `third_party/unicode/18.0.0/`, with the licence file `license.txt` beside them, unchanged from `https://www.unicode.org/Public/18.0.0/ucd/` and `https://www.unicode.org/license.txt` | Provenance |
| Licence | Unicode License v3, as printed in `third_party/unicode/18.0.0/license.txt`. Decided by Daniel on 2026-11-21: Unicode License v3 accepted; the notice ships in the product's third-party notices (`THIRD_PARTY_NOTICES.md`) | Unicode License v3 |
| Crate | `crates/fstp-unorm`, in-house, with no dependency at all. It offers `nfd`, `nfc`, `nfkd`, `nfkc`, `casefold`, `fold_nfc`, `fold_nfkc` and `name_key` over `&str`. It never panics and does no I/O. Interim, pending Daniel | CLAUDE.md dependency policy |
| Decomposition | Canonical decomposition from `UnicodeData.txt` field 5 without a `<tag>`, applied recursively. Compatibility decomposition adds the mappings with a `<tag>`, applied recursively as well. Hangul syllables are decomposed by computation (Unicode chapter 3.12), so they need no table. Interim, pending Daniel | UAX #15 |
| Ordering | Each run of non-starters is sorted by combining class with a stable sort, so equal classes keep their order. Interim, pending Daniel | Canonical Ordering Algorithm |
| Composition | The Canonical Composition Algorithm over primary composites. A pair is a primary composite when its canonical decomposition has two code points and it is not fully excluded. The full exclusion is the union of `CompositionExclusions.txt`, the singleton decompositions, and the non-starter decompositions. Hangul LV and LVT syllables compose by computation. Interim, pending Daniel | UAX #15 |
| Case folding | Full case folding: status C and F of `CaseFolding.txt`. Status S and T are not used, so the folding is the same for every language. Interim, pending Daniel | `CaseFolding.txt` header |
| Match key | `fold_nfkc(s) = toNFKC_Casefold(NFD(s))`. Accepted as the lead's reading on 2026-11-22. The input goes to NFKD. Then case folding, the removal of the code points that `NFKC_CF` removes (the default ignorables, such as the soft hyphen and the zero width joiner), and NFKD repeat until nothing changes. The result is composed to NFC. `DerivedNormalizationProps.txt` constructs `NFKC_CF` the same way. Starting from the decomposed input makes canonically equivalent spellings give one key. Decided by Daniel on 2026-11-21: compatibility forms match | Unicode chapter 3.13; UAX #44 `NFKC_CF` |
| Canonical key | `fold_nfc(s) = NFC(casefold(NFD(s)))` stays in the crate. It is the standard canonical caseless key `NFD(casefold(NFD(s)))` (Unicode chapter 3.13, D145) composed to NFC. The tuple does not use it. Interim, pending Daniel | Unicode chapter 3.13 |
| Name form | `name_key(s)` is `fold_nfkc(s)` with leading and trailing white space removed and each inner run of white space replaced by one space. White space is the `White_Space` property. The collapse runs after the fold, because compatibility decomposition can make spaces, as U+00A0 and U+3000 do. Interim, pending Daniel | ADR-004 row "Normalisation" |
| Stability | Tests prove that `fold_nfkc`, `name_key` and `fold_nfc` are idempotent and in NFC. They cover every code point alone, every code point before and after each of a set of combining marks, and random strings. They also prove that `fold_nfkc` equals `NFKC_CF` followed by NFC for every code point, and `toNFKC_Casefold(NFD(s))` for random strings. Interim, pending Daniel | Brief of lane L21 |
| Expansion bound | The canonical forms never return more than `MAX_EXPANSION` (3) times the input length in UTF-8 bytes. The compatibility forms, `fold_nfkc` and `name_key` never return more than `MAX_COMPAT_EXPANSION` (11) times, the factor of U+FDFA. Tests compute both bounds over every code point, so a new Unicode version that breaks one fails its test. A name of 200 characters gives at most 8,800 bytes, which fits the tuple's `be16` length. Interim, pending Daniel | Bounded output |
| Tables | Sorted arrays of packed `u64` values, searched by binary search: combining class ranges, one-level canonical decompositions, primary composites, simple case foldings, compatibility decompositions (an index into a pool of `u32` code points) and removed ranges. The few full case foldings of more than one code point sit in a small table of their own. About 95 KB of static data: 422 class ranges, 2,081 canonical decompositions, 961 composites, 1,501 one-point foldings, 105 longer foldings, 3,901 compatibility decompositions over 5,685 pooled code points, and 17 removed ranges. Interim, pending Daniel | Compact tables |
| Generator | `tools/unorm-gen`, a Rust binary with no dependency. It reads the vendored files and writes `crates/fstp-unorm/src/tables.rs`. With `--check` it compares instead and writes nothing. It prints nothing (R-NF-02) and answers with its exit status only: 0 for success, 1 for a stale or missing table file under `--check`, 2 for a usage, I/O or parse error. No Python and no shell parsing. Interim, pending Daniel | CLAUDE.md |
| Committed tables | The generated `tables.rs` is committed, so the build needs no network and no generator run. A test of `fstp-unorm` generates the tables again from the vendored files and compares them byte for byte with the committed file. Interim, pending Daniel | Reproducible build |
| Conformance | Every line of `NormalizationTest.txt` for all four forms: `c2 == NFC(c1) == NFC(c2) == NFC(c3)`, `c4 == NFC(c4) == NFC(c5)`, `c3 == NFD(c1) == NFD(c2) == NFD(c3)`, `c5 == NFD(c4) == NFD(c5)`, `c4 == NFKC(c1) == ... == NFKC(c5)`, `c5 == NFKD(c1) == ... == NFKD(c5)`. Every code point that Part 1 does not list is its own NFC, NFD, NFKC and NFKD | UAX #15 conformance |
| Fuzzing | `crates/fstp-unorm/fuzz`, target `fold_nfc`: any UTF-8 input through every form, checking idempotence, both expansion bounds, and that NFC and NFD of the input give one key. `tools/unorm-gen/fuzz`, target `ucd_parse`: any input through each file parser, and through `build` and `render`. Both crates join `deps/fuzz-required.txt` | CLAUDE.md fuzz rule; TH-26 |
| Dependencies | None. `fstp-unorm` and `unorm-gen` are in-house workspace members, and their fuzz projects take only `libfuzzer-sys`, as every fuzz project does (ADR-003) | CLAUDE.md dependency policy |

## Wiring into the identity tuple

Built by lane L21 on 2026-11-22, after `prod/identity-registration` merged into `main` (ADR-004, "Built by lane L21"):

- `fstp_vault::codec::tuple_name(s)` is `fstp_unorm::name_key(s)`. It folds first and collapses white space after, so it replaces the trim and collapse of the first label. A name that folds to nothing is refused.
- The tuple label is `fstp-identity-tuple-v2`, and ADR-004's row "Normalisation" says so: case, canonical equivalence, compatibility variants and default ignorables no longer separate two spellings of one name.
- A vault that stores a tuple under the label `fstp-identity-tuple-v1` refuses to start, and `verify-first-admin` refuses it too, as for shared-key identity facts. Such a pilot vault is recreated: a fresh vault database, then `init-keys`. The operator guide `docs/guide/claude-connector-production.md` says so.

## Vendored files

The SHA-256 of each file as downloaded on 2026-11-22:

| File | SHA-256 |
| --- | --- |
| `UnicodeData.txt` | `0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950` |
| `CompositionExclusions.txt` | `c759b100e9ae8960ae6b50fc5765950a7581fd9f30d4ef95f68f25a6d97e818e` |
| `CaseFolding.txt` | `a004797658a457bec4dc11683e39f69249ea3b595b752dbea6721c4c9f587b0d` |
| `DerivedNormalizationProps.txt` | `98ac7f67d985fe781e317f6182e885e94cabb0c314769e6dd73e48b226931ccd` |
| `NormalizationTest.txt` | `25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3` |
| `license.txt` | `e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96` |

## Open points, pending Daniel

- The Unicode version moves only by a new row here: new files under `third_party/unicode/<version>/`, a fresh generation, and a new tuple label, since a new version may change a fold.
- No release step copies `THIRD_PARTY_NOTICES.md` into a shipped artefact yet, and the full licence and copyright texts of the crates are not collected. A later release step does both (lead decision, 2026-11-22).
