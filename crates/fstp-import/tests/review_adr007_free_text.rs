//! Review reproducer, ADR-007 and M4 design section 4.2: every envelope
//! record, import records included, keeps free text behind a `TextRef`.
//!
//! A proposed value is text read from an untrusted document. It can hold
//! personal data, such as a coordinator's name. ADR-007 erases free text
//! by destroying its key, which works only when the ledger body holds a
//! reference and never the text itself (I-23, I-81).
//!
//! The test needs a real field, so it runs against lane W1a's
//! `fstp-programme`. On the W0 stub it fails at the field lookup.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_import::{
    ImportConfigId, ImportDocumentId, ImportProposal, ImportProposalId, ImportRecord, SaltedDigest,
    Span, UntrustedValue, ValueTextId, ValueTextRef, encode_record,
};
use fstp_programme::FieldId;

/// ADR-007, design 4.2: the stored body of `ProposalsRecorded` must not
/// hold the proposed value's text.
#[test]
fn review_adr007_proposals_recorded_body_holds_no_free_text() {
    let field = FieldId::from_key("identity.name")
        .expect("fstp-programme names no field identity.name: W0 stub (lane W1a)");
    let secret = "Synthetic Coordinator Erasable Name";
    let value = UntrustedValue::parse(format!("\"{secret}\"").as_bytes()).unwrap();
    let record = ImportRecord::ProposalsRecorded {
        document: ImportDocumentId::from_raw(1),
        proposals: vec![
            ImportProposal {
                id: ImportProposalId::from_raw(2),
                document: ImportDocumentId::from_raw(1),
                field,
                value,
                text: ValueTextRef::new(
                    ValueTextId::from_raw(4),
                    SaltedDigest::from_bytes([2; 32]),
                ),
                evidence: vec![Span { start: 0, end: 9 }],
                config: ImportConfigId::from_raw(3),
                conflicts_with_profile: Vec::new(),
            }
            .recorded(),
        ],
    };
    let body = encode_record(&record);
    assert!(
        !body.contains(secret),
        "ADR-007: the ledger body of ProposalsRecorded holds the proposed free text in clear, \
         so key destruction cannot erase it"
    );
}
