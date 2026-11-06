# ADR-016: Vendored LibPDF for browser-side signature preparation

Status: Proposed, 2026-11-06. Awaits Daniel's acceptance. Lane L-LIBPDF of `docs/handoff/m5-design.md` does not start before it.

## Context

Daniel decided on 2026-11-06 (M4 design section 15.0, Q28) that online signing in M5 builds on a vendored copy of LibPDF-js/core. The project then enhances and secures that copy itself. The signing cryptography still comes from ADR-001.

Constraints that shape the decision:

- Node.js never runs on a cell, vault, control-plane, witness or edge host (ADR-003 amendment of 2026-10-28). LibPDF can therefore run only in a browser, or in tests and fuzzing.
- `contracts.md` says a party's signature is created in the signer's wallet or at a qualified trust service provider, never by the platform.
- Every in-house parser gets a fuzz target from its first commit. Once vendored, LibPDF's parser is in-house code.
- The frontend has no framework and no bundler, and tsc is its only compiler (ADR-003, ADR-014).

## Decision

### Source and pin

| Item | Value |
| --- | --- |
| Repository | `https://github.com/LibPDF-js/core`, package `@libpdf/core` |
| Version | 0.5.3, released 2026-10-16 |
| Commit | `6bb53b8c7574c1a91992812bcfca8121a11eace8` (lightweight tag `v0.5.3`) |
| `src/` tree hash at that commit | `2d817a095f34f4177b1b50f92392336ac5200cb1` |
| `LICENSE.md` blob | `03e95b9d30aa4957489f78f576a66d241e08b368` |
| `package.json` blob | `483fa32573f8662ac09d1d5889b55e9fb59da91b` |
| Fetched | 2026-11-06, through the GitHub API |

The import is verifiable without extra tools. Each vendored file of the first import commit must have the same git blob hash as the upstream file at the commit above.

### Licence

- The library is MIT (`LICENSE.md`, copyright 2026 Lucas Smith). The MIT notice is kept in the vendored root and in the third-party notices file that ships with the web assets.
- `src/fontbox/` is Apache-2.0. Its `LICENSE.md` states it is derived from Apache PDFBox FontBox. It also carries the earlier fontbox.org BSD-style notice and the SIL OFL 1.1 text for Lohit fonts.
- `src/fontbox/` ships no NOTICE file of its own. The vendored copy adds `src/fontbox/NOTICE`, copied byte for byte from `NOTICE.txt` of `apache/pdfbox` at commit `b6c88b8a4252f10a23593907e3439d168877de0e`. That is the commit LibPDF pins as its `checkouts/pdfbox` submodule. The upstream blob is `4da75301eaf795d26cd31b56c86937c70d084978`.
- Modified files under `src/fontbox/` carry a notice that they were changed, as Apache-2.0 asks.
- `TODO(legal)`: confirm that the PDFBox NOTICE is the right attribution for the derived fontbox code, and that the three licences sit with the platform licence of `web/` (PolyForm-Noncommercial-1.0.0).
- LibPDF keeps pdf.js, pdf-lib and the DSS project as reference submodules. None is vendored. The provenance review below checks that no used file derives from them, since DSS is not under a permissive licence.

### Runtime dependencies

Upstream `package.json` at 0.5.3 declares seven runtime packages. The resolved tree in upstream `bun.lock` holds twelve:

| Package | Version | Reached through |
| --- | --- | --- |
| `@noble/ciphers` | 2.2.0 | Direct |
| `@noble/hashes` | 2.2.0 | Direct |
| `@noble/hashes` | 1.4.0 | `pkijs` |
| `@scure/base` | 2.2.0 | Direct |
| `asn1js` | 3.0.10 | Direct and `pkijs` |
| `lru-cache` | 11.5.1 | Direct |
| `pako` | 2.1.0 | Direct |
| `pkijs` | 3.4.0 | Direct |
| `bytestreamjs` | 2.0.1 | `pkijs` |
| `pvtsutils` | 1.3.6 | `asn1js`, `pkijs` |
| `pvutils` | 1.1.5 | `asn1js`, `pkijs` |
| `tslib` | 2.8.1 | `asn1js`, `pkijs`, `pvtsutils` |

The optional peers `@google-cloud/kms` and `@google-cloud/secret-manager` serve signer modules this ADR excludes.

None of these packages enters the platform. The vendored subset compiles with zero npm runtime dependencies:

- the cryptographic modules that need `@noble/*`, `asn1js` and `pkijs` are excluded (below);
- encrypted PDFs are refused, so `@noble/ciphers` has no use;
- the server writes structural objects without filters, so `pako` has no use and FlateDecode on structural objects is refused;
- `lru-cache` and `@scure/base` uses are replaced by small in-house helpers.

A CI source check fails if any vendored file imports a bare package specifier. `deps/npm-allowlist.txt` gains nothing.

### Location and build

- The vendored copy lives at `web/vendor/libpdf/`, with `LICENSE.md`, the fontbox licence and NOTICE, and an `UPSTREAM` file naming the repository, version, commit and tree hash.
- Commit 1 imports `src/` and `LICENSE.md` byte-identical to upstream. Tests, fixtures, docs and benchmarks are not imported. Commit 2 makes only mechanical changes: `#src/` and `.ts` import specifiers become relative `.js` specifiers for `NodeNext` resolution. Every later change is a reviewed commit, so `git diff` against commit 1 shows the whole enhancement.
- `web/vendor/libpdf/tsconfig.json` is its own composite tsc project with `strict` on. `web/src/sign/` references it, and `tsc -b` builds both. No bundler, no other compiler.
- The emitted modules load in a module Worker under the ADR-014 CSP and asset manifest. The vendored code touches no DOM, so the ADR-014 source scan applies to it unchanged.
- The stricter flags of `web/tsconfig.json` (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) are a hardening goal for the vendored project, not a gate for the first import.

### Parts used

Built and shipped:

| Upstream path | Use |
| --- | --- |
| `src/io/` | Scanners and byte writers |
| `src/objects/` | PDF object model |
| `src/parser/`, except `brute-force-parser.ts` | Strict parse of the server's revision. No recovery of broken files |
| `src/writer/` | Incremental save |
| `src/document/` object registry, change collector, AcroForm signature field and widget code | Set the party's signature field value |
| `src/api/` `pdf`, `pdf-catalog`, `pdf-context`, `pdf-page-tree`, `pdf-page`, and the placeholder path of `pdf-signature` | Entry points |
| `src/signatures/placeholder.ts` | `/ByteRange` and `/Contents` placeholders and patching |
| `src/helpers/` as reached by the above | Support |

Vendored but not built: `src/fontbox/`, `src/fonts/`, `src/drawing/`, `src/text/`, `src/svg/`, `src/images/`, `src/layers/`, `src/attachments/`, `src/annotations/` other than the widget, `src/security/`, `src/filters/`, and every module under `src/signatures/` other than `placeholder.ts`. A build check fails if a shipped module imports one of them.

### Division of work and cryptography

LibPDF prepares one incremental revision in the browser: the signature dictionary, the field value, the placeholders and `/ByteRange`. It sends only the appended bytes. It does no hashing, no signing and no font work.

The server concatenates those bytes with its stored revision and checks the increment with the strict in-house verifier of `fstp-pdf`. It then computes the `/ByteRange` digest with aws-lc-rs and encodes the CMS signed attributes in-house (`fstp-pki`). The signature value comes from the wallet or QTSP, or from the tenant seal key in custody for seals. The server verifies it with aws-lc-rs before embedding it (m5-design section 3.1).

So no signature, digest or certificate operation runs in vendored code. LibPDF's own CMS, PKCS#12, timestamp, revocation and LTV code is excluded. The server never trusts the browser's bytes beyond the exact increment shape the verifier accepts.

### Fuzz targets

The targets use Jazzer.js, which Daniel chose on 2026-11-06 (M4 Q33 B), once the ADR-003 amendment records its version and resolved tree. Until then they run under the in-house seeded harness of `web/fuzz`. Each exists from the first commit of lane L-LIBPDF.

| Target | Entry | Property |
| --- | --- | --- |
| `pdf_token` | Token reader and object parser | Returns an object or a typed parse error. Never hangs, never exceeds the depth and size limits |
| `pdf_xref` | Xref and trailer parser | Same, including `/Prev` loops and offsets past the end |
| `pdf_document` | Document parser on arbitrary bytes | Same; refuses encrypted files, object streams and xref streams with a typed error |
| `pdf_prepare` | Prepare a signature on a mutated server revision | Output starts with the input bytes exactly; `/ByteRange` covers every byte except `/Contents`; the increment parses again |
| `pdf_prepare_differential` | Shared corpus with the Rust `fstp-pdf` increment verifier | Every increment LibPDF emits from a valid server revision is accepted by the Rust verifier |

Seeds come from `fstp-pdf` output on synthetic contracts only.

### Security review plan

1. **Provenance.** Check the blob hashes of commit 1. Read the headers and history of every used file for code derived from pdf.js, pdf-lib or DSS.
2. **Line review.** One reviewer reads the whole used subset before the first merge. The review records findings in `docs/handoff/m5-libpdf-review.md`.
3. **Hardening changes.** Hard limits on file size, object count, nesting depth, string length and xref chain length. Dictionaries keyed through `Map`, never plain objects, against prototype pollution. No `eval`, no `Function`, no dynamic import.
4. **Threats checked.** Parser denial of service, incremental update and shadow attacks, `/ByteRange` gaps or overlaps, duplicate object numbers, and a field change outside the party's own field. The Rust verifier refuses each of them independently.
5. **Fuzzing.** The targets above run in CI and in the M10 hardening campaign.
6. **Upstream tracking.** Once a month, compare upstream releases with the pin. Security fixes are ported by hand and reviewed. Each move records the new commit and tree hash here.

## Consequences

- The project owns the vendored code from commit 1, including its defects.
- Removing LibPDF later costs little. The server already defines the increment exactly, so a server-side preparation path could replace it.
- The signing page needs JavaScript. A signer without it cannot sign online.
- The fontbox code stays vendored but unbuilt. It keeps its licence and NOTICE, so a later lane can build on it without a new import.
