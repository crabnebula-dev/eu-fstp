# M5 LibPDF review (ADR-016)

Lane L-LIBPDF, 2026-11-06. This file records the security review plan of ADR-016 for the vendored LibPDF at `web/vendor/libpdf/`. Item 1 (provenance) has results. Items 2 to 6 are open or partly done, as marked.

## 1. Provenance

### Pin and import

| Check | Result |
| --- | --- |
| Upstream fetched | `https://github.com/LibPDF-js/core` at `6bb53b8c7574c1a91992812bcfca8121a11eace8` (tag `v0.5.3`), by `git fetch` of that commit. No upstream build, install or script ran |
| `src/` tree hash | `2d817a095f34f4177b1b50f92392336ac5200cb1`, as ADR-016 records |
| `LICENSE.md` blob | `03e95b9d30aa4957489f78f576a66d241e08b368`, as ADR-016 records |
| `package.json` blob | `483fa32573f8662ac09d1d5889b55e9fb59da91b`, as ADR-016 records. Not vendored |
| PDFBox `NOTICE.txt` | Fetched from `apache/pdfbox` at `b6c88b8a4252f10a23593907e3439d168877de0e`. Blob `4da75301eaf795d26cd31b56c86937c70d084978`, as ADR-016 records. Vendored as `src/fontbox/NOTICE` |
| Upstream manifest | `web/vendor/libpdf/UPSTREAM-TREE` holds `git ls-tree -r` of `src/` and `LICENSE.md` at the pin: 423 `src/` blobs and the licence |
| Imported | 280 `src/` files and `LICENSE.md`, each byte-identical to its upstream blob |
| Left out | 143 test files: every `*.test.ts`, `src/test-utils.ts`, `src/integration/` and `src/signatures/formats/test-helpers.ts`. No fixtures, docs or benchmarks |

`web/test/libpdf.test.ts` checks this on every run:

- `adr016_provenance_upstream_manifest_is_the_pinned_tree` rebuilds the git tree objects from `UPSTREAM-TREE` and compares the `src/` tree hash and the licence blob with the pin.
- `adr016_provenance_every_vendored_file_matches_its_upstream_blob_or_is_declared` hashes every vendored file as a git blob. Each one must equal its upstream blob, or be declared in `web/vendor/libpdf/CHANGED-FILES`. A declared file that equals upstream also fails, so the list stays exact.

At the import commit the list is absent and all 281 files match. Both tests passed on the import alone, before any change.

### Commits

| Commit | Content | `CHANGED-FILES` |
| --- | --- | --- |
| 1, import | `LICENSE.md`, `UPSTREAM`, `UPSTREAM-TREE`, `src/` (280 files) and `src/fontbox/NOTICE` | Absent |
| 2, mechanical | `#src/` and `.ts` specifiers become relative `.js` specifiers, in 191 modules. `src/fontbox/` stays byte-identical, so its Apache-2.0 files need no change notice | 191 `modified` lines |
| 3, reductions | Sections 3 below, `tsconfig.json`, and one in-house file, `src/parser/limits.ts` | 193 `modified`, 1 `added` |

`src/index.ts` keeps its upstream `../package.json` import. It is unbuilt.

### Headers and history of the used files

The 35 shipped modules are the `files` list of `web/vendor/libpdf/tsconfig.json`.

- No shipped module carries a copyright or licence header from pdf.js, pdf-lib, PDFBox or DSS.
- The comments name PDFBox once, in `src/parser/token-reader.ts`, for the handling of `--5` as a number. The strict parser removed two other mentions in `document-parser.ts`.
- Upstream keeps pdf.js (Apache-2.0), pdf-lib (MIT), PDFBox (Apache-2.0) and DSS as reference submodules under `checkouts/`. Its `AGENTS.md` names pdf.js as the parsing reference and PDFBox as the architecture reference.
- 272 upstream commits; 213 by Lucas Smith. No commit message on a shipped file says code was ported or copied. "DSS" in commit `1a6b300` names the PDF Document Security Store, not the DSS project.

Open: the headers and messages show no copied code, but they cannot exclude it. The line review (item 2) compares the parser modules with the pdf.js parser and the PDFBox `COSParser` for copied structure. `TODO(legal)`: whether reference use of pdf.js and PDFBox needs any attribution beyond the existing notices.

## 2. Line review

Open. One reviewer reads the 35 shipped modules and `web/src/sign/` before the first merge.

## 3. Hardening changes

| Change | Where |
| --- | --- |
| Hard limits: 32 MiB file, 65536 objects, depth 32, 65536-byte strings and names, 64 xref sections. Each refuses with `RefusedError("limit")` | `src/parser/limits.ts`, used by the token reader, object parser, xref parser and document parser |
| Strict parse: header at offset 0, no lenient mode, no brute-force recovery, `endobj` required, direct `/Length` that must reach `endstream`, unterminated or non-hex strings refused, strict `startxref` and `%%EOF` tail, a duplicate object number in one xref section refused, an object at an offset that is not the object named refused | `document-parser.ts`, `indirect-object-parser.ts`, `token-reader.ts`, `xref-parser.ts` |
| Encrypted files, xref streams, hybrid `/XRefStm` files and object streams refused with typed errors | `document-parser.ts`, `xref-parser.ts` |
| Filters not built: a filtered stream's decoded bytes are refused | `objects/pdf-stream.ts` |
| Writer reduced to the incremental table save, with no compression, encryption or xref streams | `writer/pdf-writer.ts` |
| Placeholder search limited to the new increment; `patchContents` removed, since the server writes `/Contents` | `signatures/placeholder.ts` |
| In-house LRU cache for `PdfRef` interning; the registry keys each object by one canonical ref, so an evicted ref never splits an object | `helpers/lru-cache.ts`, `document/object-registry.ts` |
| Dictionaries keyed through `Map` | Upstream `PdfDict` already does |
| No `eval`, `Function`, dynamic import or bare specifier in a shipped module | `adr016_no_shipped_vendored_module_imports_a_bare_package`, and the web scan of `tools/deps-check` |

`web/src/sign/prepare.ts` also loads every in-use object of the revision before it prepares, so a refused feature anywhere refuses the file. It refuses a `/Size` below an object number, a duplicate field name and an `/ID` other than two strings.

## 4. Threats checked

| Threat | Browser side (this lane) | Server side |
| --- | --- | --- |
| Parser denial of service | Limits above; fuzz targets `pdf_token`, `pdf_xref`, `pdf_document` with a 2-second bound per call | Rust verifier, lane L-PDF |
| `/ByteRange` gaps or overlaps | `pdf_prepare` checks `[0 a b c]` against the `/Contents` string | Rust verifier |
| A field change outside the party's own field | The increment holds the signature dictionary and the party's field only (`pdf_prepare_differential`) | Rust verifier refuses any other object |
| Incremental update and shadow attacks, duplicate object numbers | Not a browser concern; the server concatenates its own stored revision | Rust verifier, lane L-PDF |

## 5. Fuzzing

The five targets of ADR-016 run under the in-house harness of `web/fuzz` until the ADR-003 amendment for Jazzer.js lands. Seeded runs of 20000 inputs on seeds 1 to 7 found two defects, both fixed: a lenient `startxref` tail, and an `/ID` the preparation dropped when it was not two strings. The corpus `web/fuzz/seeds/pdf_prepare_differential/expect.tsv` is the one the Rust verifier will share. Its seeds are synthetic and hand-built until `fstp-pdf` renders synthetic contracts.

## 6. Upstream tracking

Open. Monthly comparison of upstream releases with the pin starts after the first merge.

## Readings for lane L-PDF

The strict parser accepts only what M5 design section 3.1 step 1 describes. It also reads these points, which the server's writer must meet:

- the header `%PDF-x.y` starts the file;
- every stream has a direct `/Length`;
- the trailer `/Size` is above every object number, and `/ID`, when present, is two strings;
- each party field is a top-level indirect field with `/FT /Sig`, a `/T` name and no `/Kids`;
- the increment's trailer carries `/Size`, `/Root`, `/Prev`, and `/Info` and `/ID` unchanged when present. `/ID` is rewritten as hex strings.
