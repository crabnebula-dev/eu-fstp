//! Adversarial review reproducers for lane W2c, fix round 1. Each test
//! fails against the reviewed code and passes once its defect is fixed.
//! Fixtures come from the synthetic corpus only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{admin_granted, cid, ledger, state_of};
use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{
    CellCommand, CellCtx, CellRecord, ERASURE_CAUSES, decide, decode_cell_record,
    encode_cell_record,
};
use fstp_domain::oracle::Answers;
use fstp_domain_testkit::r#gen::roster::{ADMIN, T0};

/// A text id from a number.
fn text_id(n: u16) -> [u8; 16] {
    let mut id = [0x7E; 16];
    id[14..].copy_from_slice(&n.to_be_bytes());
    id
}

/// I-23, ADR-007, design sections 5.3 and 5.6: every record `decide`
/// gives must be stored and read back, since `PgRecordStore` keeps the
/// canonical text and replays through `record_from_canonical_at`. An
/// erasure of more texts than the codec's `MAX_TEXT_IDS` decides today
/// into records the decoder refuses, so the committed ledger no longer
/// replays.
#[test]
fn review_i23_erasure_records_beyond_the_codec_limit_are_never_decided() {
    let n: u16 = 1025;
    let puts: Vec<CellRecord> = (0..n)
        .map(|i| CellRecord::Text(TextRecord::TextPut { id: text_id(i) }))
        .collect();
    let entries = ledger(&[(T0, cid(1), vec![admin_granted(ADMIN)]), (T0, cid(2), puts)]).unwrap();
    let s = state_of(&entries).unwrap();
    let cmd = CellCommand::Text(TextCommand::EraseTexts {
        ids: (0..n).map(text_id).collect(),
        cause: ERASURE_CAUSES[1],
    });
    let x = CellCtx {
        actor: ADMIN,
        at: T0.micros(),
    };
    if let Ok(batch) = decide(&s, &cmd, &x, &Answers::new()) {
        for r in &batch {
            let back = decode_cell_record(&encode_cell_record(r));
            assert!(
                back.as_ref().ok() == Some(r),
                "decide gave a record the store cannot read back: {:?}",
                back.err()
            );
        }
    }
}

/// ADR-007 "Erasure-log entries", design section 5.6: the authoriser of a
/// retention expiry is the system, with a reference to the P-41 rule. A
/// tenant admin's command must not record an erasure-log entry whose cause
/// is retention expiry under the admin's own name. Today any tenant admin
/// erases any live text at once and labels it a routine retention expiry.
#[test]
fn review_adr007_account_cannot_record_a_retention_expiry_erasure() {
    let entries = ledger(&[
        (T0, cid(1), vec![admin_granted(ADMIN)]),
        (
            T0,
            cid(2),
            vec![CellRecord::Text(TextRecord::TextPut { id: text_id(1) })],
        ),
    ])
    .unwrap();
    let s = state_of(&entries).unwrap();
    // ERASURE_CAUSES[0] is retention expiry (P-41).
    let cmd = CellCommand::Text(TextCommand::EraseTexts {
        ids: vec![text_id(1)],
        cause: ERASURE_CAUSES[0],
    });
    let x = CellCtx {
        actor: ADMIN,
        at: T0.micros(),
    };
    let r = decide(&s, &cmd, &x, &Answers::new());
    assert!(
        r.is_err(),
        "a tenant admin recorded a retention-expiry erasure as its own: {r:?}"
    );
}
