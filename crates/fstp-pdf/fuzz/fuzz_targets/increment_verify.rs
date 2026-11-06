//! Fuzz target `increment_verify` of `fstp-pdf` (TH-26, ADR-016, M5
//! design sections 8 and 11, I-30).
//!
//! The input is an increment appended to a fixed synthetic contract. For
//! every party name the verifier must return a typed result without
//! panicking. An accepted increment must keep every other object of the
//! stored revision, and its `/ByteRange` must cover every byte except
//! `/Contents`, with the digest over exactly those bytes. The input is
//! also read as a whole file, so the file and object parsers are covered.

#![no_main]

use std::sync::OnceLock;

use fstp_pdf::{Block, BlockKind, Document, PdfFile, SignatureField, verify_increment, write};
use libfuzzer_sys::fuzz_target;

const PARTIES: [&str; 3] = ["lead", "member-1", "signatory"];

fn base() -> &'static [u8] {
    static BASE: OnceLock<Vec<u8>> = OnceLock::new();
    BASE.get_or_init(|| {
        let doc = Document {
            title: "Sub-grant agreement SYN-0001".into(),
            lang: "en".into(),
            blocks: vec![Block {
                kind: BlockKind::Paragraph,
                text: "Synthetic clause for the fuzz base.".into(),
            }],
            signature_fields: PARTIES
                .iter()
                .map(|p| SignatureField {
                    name: (*p).into(),
                    label: format!("Signature of {p}"),
                })
                .collect(),
        };
        write(&doc).expect("the synthetic base renders")
    })
}

fuzz_target!(|data: &[u8]| {
    let base = base();
    let before = PdfFile::open(base).expect("the base parses");
    for party in PARTIES {
        let Ok(v) = verify_increment(base, data, party) else {
            continue;
        };
        let full = [base, data].concat();
        let [a, b, c, d] = v.byte_range;
        assert_eq!(a, 0);
        assert_eq!(b as usize, v.contents.start);
        assert_eq!(c as usize, v.contents.end);
        assert_eq!((c + d) as usize, full.len());
        let covered = [&full[..v.contents.start], &full[v.contents.end..]].concat();
        assert_eq!(v.digest, fstp_crypto::sha256(&covered));
        let after = PdfFile::open(&full).expect("an accepted revision parses");
        for (num, entry) in before.xref() {
            if *num != v.field.num && entry.in_use {
                assert_eq!(after.xref().get(num), Some(entry), "object {num} moved");
            }
        }
    }
    if let Ok(file) = PdfFile::open(data) {
        let _ = file.parse_all();
    }
});
