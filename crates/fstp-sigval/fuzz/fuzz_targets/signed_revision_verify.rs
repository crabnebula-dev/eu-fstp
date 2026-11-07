//! Fuzz target `signed_revision_verify` of `fstp-sigval` (TH-26, I-30,
//! M5 design sections 3.1 step 7 and 11).
//!
//! The input is the signed increment appended to a fixed synthetic
//! contract, as a stored revision would hold it. For every party the
//! validator must return a typed result without panicking: the
//! `/Contents` locator, the DER length reader, the CMS decoder and the
//! chain validation all see attacker bytes. The input is also read as a
//! bare CMS and as a certificate. Nothing may validate, since the fake
//! trusted list holds no anchor.

#![no_main]

use std::sync::OnceLock;

use fstp_pdf::{Block, BlockKind, Document, SignatureField, write};
use fstp_sigval::{
    FakeTrustedList, Level, der_tlv_len, issuer_and_serial, validate_cms, verify_signed_revision,
};
use libfuzzer_sys::fuzz_target;

const PARTIES: [&str; 2] = ["lead", "signatory"];
const AT: i64 = 1_798_761_600;

fn base() -> &'static [u8] {
    static BASE: OnceLock<Vec<u8>> = OnceLock::new();
    BASE.get_or_init(|| {
        write(&Document {
            title: "Sub-grant agreement SYN-0003".into(),
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
        })
        .expect("the synthetic base renders")
    })
}

fuzz_target!(|data: &[u8]| {
    let base = base();
    let trust = FakeTrustedList::default();
    let revision = [base, data].concat();
    for party in PARTIES {
        let r = verify_signed_revision(base, &revision, party, AT, Level::Advanced, &trust);
        assert!(r.is_err(), "nothing validates without an anchor");
    }
    let _ = der_tlv_len(data);
    let _ = validate_cms(data, &[0; 32], AT, Level::Advanced, None, &trust);
    let _ = issuer_and_serial(data);
});
