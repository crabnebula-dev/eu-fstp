# M10 hardening, H-18: review of the Tier B formats crates (I-74)

This is the findings reference for the Tier B confirmations of 2026-11-23 in `deps/tier-b-confirmations.txt` and in the release gate table of `docs/adr/ADR-001-crypto-allowlist.md`.

- Review date: 2026-11-23.
- Model: Claude Mythos 5.2 (`claude-mythos-5-2`). The hardening plan names 5.1. 5.2 is the model actually used.
- Platform commit reviewed: `268e5079a172a5ef6fe00cd7a8e0577b26415f68`.
- Scope: `der` 0.7.10, `spki` 0.7.3, `x509-cert` 0.2.5 and `cms` 0.2.3, and the rest of the Tier B formats tree as far as enabled code reaches it. The confirmation is for the crates as `fstp-pki::cms` and `fstp-sigval` use them.
- moduletto 0.1.0 at `ded73e57` was confirmed on 2026-11-20 and is not part of this review. Its pin did not move.

This file is a summary. The full review report is kept with the M10 findings register.

## Hash check

Each `.crate` file was hashed with SHA-256 and compared with `deps/allowlist.txt`. All match.

| Crate | Version | SHA-256 of the `.crate` | Result |
| --- | --- | --- | --- |
| der | 0.7.10 | `e7c1832837b905bbfb5101e07cc24c8deddf52f93225eee6ead5f4d63d53ddcb` | match |
| spki | 0.7.3 | `d91ed6c858b01f942cd56b37a94b3e0a1798290327d1236e4d9cf4eaca44d29d` | match |
| x509-cert | 0.2.5 | `1301e935010a701ae5f8655edc0ad17c44bad3ac5ce8c39185f75453b720ae94` | match |
| cms | 0.2.3 | `7b77c319abfd5219629c45c34c89ba945ed3c5e49fcde9d16b6c3885f118a730` | match |
| const-oid | 0.9.6 | `c2459377285ad874054d797f3ccebf984978aa39129f6eafde5cdc8315b612f8` | match |
| der_derive | 0.7.3 | `8034092389675178f570469e6c3b0465d3d30b4505c294a6550db47f3c17ad18` | match |
| flagset | 0.4.7 | `b7ac824320a75a52197e8f2d787f6a38b6718bb6897a35142d749af3c0e8f4fe` | match |
| pem-rfc7468 | 0.7.0 | `88b39c9bfcfc231068454382784bb460aae594343fb030d46e9f50a645418412` | match |

`base64ct` 1.8.3 was not hashed. It is reached only through PEM code that the platform never calls.

## Features and reached surface

| Crate | Resolved features | Off, or on but never called |
| --- | --- | --- |
| der | `alloc`, `derive`, `flagset`, `oid`, `pem`, `zeroize` | `real`, `std`, `bytes`, `time`, `arbitrary` are off. `pem` is on, but no platform code calls a PEM function |
| spki | `alloc`, `pem` | `std`, `fingerprint`, `base64`, `arbitrary` are off |
| x509-cert | `pem` | `std`, `builder`, `hazmat`, `sct`, `arbitrary` are off |
| cms | none | `builder`, `std`, `pem` are off |

Platform callers at the reviewed commit: `crates/fstp-pki/src/cms.rs` and `crates/fstp-sigval/src/lib.rs`, reached from `crates/fstp-contract/src/signing.rs`. No other crate names `der`, `spki`, `x509_cert` or `cms`.

Entries that can carry outside bytes: `decode_signed_data` (a CMS of at most 65,536 bytes), certificate parsing in `fstp-pki::cms` and `fstp-sigval`, the extension reads of `fstp-sigval`, and the RSA key bit string.

At the reviewed commit the production cell builds its core with a signature port and a trusted list that refuse every signature. No production request reaches the Tier B decoders. Test and demo cells feed them bytes from the platform's own fake.

## What was read

| Crate | Read in full | Pattern scan only | Not read |
| --- | --- | --- | --- |
| der | length, header, tag, reader, decode, ordering, the owned byte and array types, the slice writer, date and time, and the ASN.1 types for sets, any, optional, context-specific, integers, bit strings, booleans, object identifiers and both time forms | the string types, octet strings, null, sequences, choice, encoding, errors | `real` (off), documents and the PEM reader and writer (no platform caller) |
| spki | `algorithm`, `spki` | none | `traits`, `error`, `fingerprint` (off) |
| x509-cert | certificate, attributes, name, serial number, time, extensions, macros, CRL, basic and name constraints, general names, key usage | the other `ext/pkix` files | `anchor`, `request`, `builder` (off), `sct` (off) |
| cms | `lib`, `cert`, `content_info`, `signed_data`, `revocation`, `attr` | none | `builder` (off) and the content types the platform never decodes |
| const-oid | `from_bytes`, `arcs` | none | the generated database, the compile-time parser and encoder |
| der_derive | value ordering, sequence fields, the decoder part of attributes, the choice generator | none | the rest. It runs at compile time only |
| flagset | both `unsafe` sites, `new_truncated` | none | the rest |
| pem-rfc7468, base64ct | none | `unsafe` sites listed | all. No platform caller |

`der`, `spki`, `x509-cert`, `cms`, `const-oid` and `der_derive` forbid `unsafe` code. The two `unsafe` sites of `flagset` 0.4.7 only wrap an integer and touch no memory.

## Result

No memory-safety defect, no reachable panic and no signature-bypass path was found in the reached code.

The review recorded two bounded-work items in decoding (register ids F-014 and F-015) and four informational notes (F-016). None is reachable in a production cell at the reviewed commit, because that cell refuses every signature. They are the subject of condition C1.

Advisories: the local RustSec database of 2026-11-20 holds no advisory for `der`, `spki`, `x509-cert`, `cms`, `const-oid`, `der_derive`, `flagset`, `pem-rfc7468`, `base64ct` or `zeroize`. Upstream changelogs were not read.

Existing coverage: the fuzz targets `cms_signed_data_decode` and `signed_revision_verify`, and the tests `crates/fstp-pki/tests/cms.rs` and `crates/fstp-sigval/tests/sigval.rs`.

## Verdicts

| Crate | Verdict | Conditions |
| --- | --- | --- |
| der 0.7.10 | Confirm with conditions | C1, C2, C3 |
| spki 0.7.3 | Confirm | C3 |
| x509-cert 0.2.5 | Confirm with conditions | C1, C2, C3 |
| cms 0.2.3 | Confirm with conditions | C1, C2, C3 |

- C1: no path may carry outside bytes to `fstp-pki::cms` or `fstp-sigval` until F-014 and F-015 are closed with their regression tests. The production cell meets this today. A production `SignaturePort` or `TrustedList` ends that, so both items close before either lands.
- C2: `decode_signed_data` keeps its re-encode comparison of `ContentInfo` and `SignedData`.
- C3: the features stay as recorded above and in ADR-001. No platform code calls the PEM functions of these crates, `ContextSpecific<T>` as a value type, or `bool::try_from(AnyRef)`.

Daniel accepted confirmation with these conditions on 2026-11-23.

## Not reviewed

- `base64ct` 1.8.3 and `pem-rfc7468` 0.7.0, and the PEM modules of `der`, `spki` and `x509-cert`. No platform code calls them.
- The CMS content types other than `SignedData`, and the `builder` modules.
- The `const-oid` database and the proc-macro tree (`proc-macro2`, `quote`, `syn`, `unicode-ident`).
- Side channels. These crates handle public data only in the platform.
- The validation logic of `fstp-sigval` as such. That is activity H-15.
- No fuzz run was made for this review.
