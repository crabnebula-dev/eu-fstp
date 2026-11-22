# Third-party notices

This file lists every third-party component of the platform, with its licence (lead decision, 2026-11-22, ADR-029). The licence identifiers of the Rust crates and npm packages are the SPDX expressions their own manifests declare, read from `cargo metadata` and the npm lockfiles. They were not written from memory.

Which components ship: the column "Use" of the crate table is the scope of `deps/allowlist.txt`. `runtime` crates are compiled into the shipped binaries. `build` crates run only in build scripts. `platform` crates are compiled only for targets other than Linux. `test` crates build only the fuzz projects. The npm packages are build and test tools only (ADR-003).

No release step copies this file into a shipped artefact yet, and the full licence and copyright texts of the crates are not collected here yet. Both are a later release step (ADR-029, open points).

## Unicode Character Database 18.0.0

- Used by: `crates/fstp-unorm`, whose tables in `src/tables.rs` are generated from these files (ADR-029).
- Files: `third_party/unicode/18.0.0/` (`UnicodeData.txt`, `CompositionExclusions.txt`, `CaseFolding.txt`, `DerivedNormalizationProps.txt`, `NormalizationTest.txt`).
- Source: `https://www.unicode.org/Public/18.0.0/ucd/`.
- Licence: Unicode License v3, accepted by Daniel on 2026-11-21. The text below is copied unchanged from `third_party/unicode/18.0.0/license.txt`.

```text
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2026 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```

## Fonts

| Font | Where | Licence | Basis |
| --- | --- | --- | --- |
| IBM Plex Sans Regular | `crates/fstp-pdf/assets/IBMPlexSans-Regular.ttf`, embedded in contract and Guide PDFs | SIL Open Font License 1.1, full text in `crates/fstp-pdf/assets/IBMPlexSans-LICENSE.txt` | ADR-017 |
| Lohit fonts, named in the FontBox licence of LibPDF | `web/vendor/libpdf/src/fontbox/LICENSE.md` | SIL Open Font License 1.1, as that file states | ADR-016 |

The IBM Plex Sans notice, copied from the first line of its licence file:

```text
Copyright © 2017 IBM Corp. with Reserved Font Name "Plex"
```

## Vendored code

| Component | Where | Licence | Basis |
| --- | --- | --- | --- |
| LibPDF v0.5.3 | `web/vendor/libpdf/` | MIT, full text in `web/vendor/libpdf/LICENSE.md` | ADR-016 |
| FontBox, derived from Apache PDFBox, inside LibPDF | `web/vendor/libpdf/src/fontbox/` | Apache-2.0, with the earlier fontbox.org notice, in `web/vendor/libpdf/src/fontbox/LICENSE.md`, and the PDFBox notice in `web/vendor/libpdf/src/fontbox/NOTICE` | ADR-016 |

The LibPDF notice, copied unchanged from `web/vendor/libpdf/LICENSE.md`:

```text
MIT License

Copyright (c) 2026 Lucas Smith

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Rust crates

The allowlisted crates of `deps/allowlist.txt`, with their resolved versions.

| Crate | Version | Licence (SPDX) | Use | ADR |
| --- | --- | --- | --- | --- |
| `arbitrary` | 1.5.0 | MIT OR Apache-2.0 | test | ADR-003 |
| `aws-lc-rs` | 1.18.2 | ISC AND (Apache-2.0 OR ISC) | runtime | ADR-001 |
| `aws-lc-sys` | 0.46.0 | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) | runtime | ADR-001 |
| `base64ct` | 1.8.3 | Apache-2.0 OR MIT | runtime | ADR-001 |
| `cc` | 1.10.0 | MIT OR Apache-2.0 | build | ADR-001,ADR-003 |
| `cfg-if` | 1.0.5 | MIT OR Apache-2.0 | platform | ADR-001,ADR-003 |
| `cmake` | 0.1.58 | MIT OR Apache-2.0 | build | ADR-001 |
| `cms` | 0.2.3 | Apache-2.0 OR MIT | runtime | ADR-001 |
| `const-oid` | 0.9.6 | Apache-2.0 OR MIT | runtime | ADR-001 |
| `der` | 0.7.10 | Apache-2.0 OR MIT | runtime | ADR-001 |
| `der_derive` | 0.7.3 | Apache-2.0 OR MIT | runtime | ADR-001 |
| `dunce` | 1.0.5 | CC0-1.0 OR MIT-0 OR Apache-2.0 | build | ADR-001 |
| `errno` | 0.3.14 | MIT OR Apache-2.0 | runtime | ADR-002 |
| `find-msvc-tools` | 0.1.15 | MIT OR Apache-2.0 | build | ADR-001,ADR-003 |
| `flagset` | 0.4.7 | Apache-2.0 | runtime | ADR-001 |
| `fs_extra` | 1.3.0 | MIT | build | ADR-001 |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 | platform | ADR-001,ADR-003 |
| `jobserver` | 0.1.35 | MIT OR Apache-2.0 | build | ADR-001,ADR-003 |
| `libc` | 0.2.191 | MIT OR Apache-2.0 | runtime | ADR-001,ADR-002,ADR-003 |
| `libfuzzer-sys` | 0.4.13 | (MIT OR Apache-2.0) AND NCSA | test | ADR-003 |
| `libm` | 0.2.16 | MIT | runtime | ADR-001 |
| `mio` | 1.2.4 | MIT | runtime | ADR-002 |
| `moduletto` | 0.1.0 | MIT OR Apache-2.0 | runtime | ADR-001 |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 | runtime | ADR-001 |
| `pem-rfc7468` | 0.7.0 | Apache-2.0 OR MIT | runtime | ADR-001 |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT | runtime | ADR-002 |
| `pkg-config` | 0.3.34 | MIT OR Apache-2.0 | build | ADR-001 |
| `proc-macro2` | 1.0.107 | MIT OR Apache-2.0 | runtime | ADR-001 |
| `quote` | 1.0.47 | MIT OR Apache-2.0 | runtime | ADR-001 |
| `r-efi` | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | platform | ADR-001,ADR-003 |
| `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT | runtime | ADR-001 |
| `rustls-pki-types` | 1.15.1 | MIT OR Apache-2.0 | runtime | ADR-001 |
| `rustls-webpki` | 0.103.16 | ISC | runtime | ADR-001 |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 | build | ADR-001,ADR-003 |
| `signal-hook-registry` | 1.4.8 | MIT OR Apache-2.0 | runtime | ADR-002 |
| `socket2` | 0.6.5 | MIT OR Apache-2.0 | runtime | ADR-002 |
| `spki` | 0.7.3 | Apache-2.0 OR MIT | runtime | ADR-001 |
| `subtle` | 2.6.1 | BSD-3-Clause | runtime | ADR-001 |
| `syn` | 2.0.119 | MIT OR Apache-2.0 | runtime | ADR-001 |
| `tokio` | 1.54.1 | MIT | runtime | ADR-002 |
| `unicode-ident` | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 | runtime | ADR-001 |
| `untrusted` | 0.9.0 | ISC | runtime | ADR-001 |
| `wasi` | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | platform | ADR-002 |
| `webpki-roots` | 1.0.9 | CDLA-Permissive-2.0 | runtime | ADR-001 |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 | platform | ADR-002 |
| `windows-sys` | 0.61.2 | MIT OR Apache-2.0 | platform | ADR-002 |
| `x509-cert` | 0.2.5 | Apache-2.0 OR MIT | runtime | ADR-001 |
| `zeroize` | 1.9.1 | Apache-2.0 OR MIT | runtime | ADR-001 |

## npm packages

Build and test tools only. They never ship in a runtime artefact (ADR-003).

| Package | Version | Licence (SPDX) | Use |
| --- | --- | --- | --- |
| `@playwright/test` | 1.64.1 | Apache-2.0 | e2e tests |
| `playwright` | 1.64.1 | Apache-2.0 | e2e tests |
| `playwright-core` | 1.64.1 | Apache-2.0 | e2e tests |
| `typescript` | 6.0.3 | Apache-2.0 | build of `web/` and `e2e/` |

## Other tools

These run only in CI or on a developer's machine, and nothing of them ships. Their licences are not recorded in the repository, `TODO(legal)` if any is ever shipped.

- The Rust toolchain and cargo-fuzz (ADR-003).
- Chrome Headless Shell for the Playwright tests (ADR-003).
