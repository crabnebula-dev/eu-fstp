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
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, T0};

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

/// ADR-007 "Erasure-log entries" as Daniel decided on 2026-11-15 ("Tenant
/// admin for all"): a tenant admin requests every erasure cause, retention
/// expiry (P-41) included, and the system only reminds. Any other account
/// is still refused a retention-expiry erasure.
#[test]
fn review_adr007_only_a_tenant_admin_records_a_retention_expiry_erasure() {
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
    let admin = CellCtx {
        actor: ADMIN,
        at: T0.micros(),
    };
    let r = decide(&s, &cmd, &admin, &Answers::new());
    assert!(
        r.is_ok(),
        "a tenant admin was refused a retention-expiry erasure: {r:?}"
    );
    let other = CellCtx {
        actor: A,
        at: T0.micros(),
    };
    let r = decide(&s, &cmd, &other, &Answers::new());
    assert!(
        r.is_err(),
        "an account that is no tenant admin recorded a retention-expiry erasure: {r:?}"
    );
}
