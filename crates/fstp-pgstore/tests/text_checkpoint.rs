//! The text store and the sealed checkpoints (M3 design sections 5.5 and
//! 5.6, ADR-007 "Retention and erasure" and its 2026-10-28 amendment,
//! R-NF-08, I-81).
//!
//! The W2e test author wrote these tests before the production code. They
//! are red until `fstp_pgstore` exports its migrations, its text store
//! (`common::TEXT_SEAM`) and its checkpoints (`common::CHECKPOINT_SEAM`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{
    CellDb, FakeWitness, Rec, Store, TextGot, canary, fresh16, holds_canary, must, uuid_text,
};
use fstp_ledger::Seq;

/// A time inside the bound, in UTC microseconds (2026-10-29).
const AT: i64 = 1_793_232_000_000_000;

fn world() -> (CellDb, FakeWitness, Store) {
    let db = must(CellDb::provision());
    let w = FakeWitness::new(db.cell_id());
    let s = must(Store::open(&db, &w));
    (db, w, s)
}

/// Appends `n` single-record batches, so checkpoints have entries to name.
fn fill(s: &mut Store, n: u64) {
    let mut head = Seq::ZERO;
    for _ in 0..n {
        head = match must(s.append(head, AT, fresh16(), vec![Rec::new(0, "x")])) {
            Ok(h) => h,
            Err(e) => panic!("append: {e}"),
        };
    }
}

// ---------------------------------------------------------------------------
// Checkpoints (design section 5.5).

/// ADR-007 amendment, design section 5.5: a checkpoint reads back as
/// written, and the state inside it appears in no form at rest.
#[test]
fn adr007_checkpoint_round_trips_and_is_sealed() {
    let (db, _w, mut s) = world();
    fill(&mut s, 2);
    let c = canary(&db.hex, "state");
    let state = format!("{{\"fold\":\"{c}\"}}").into_bytes();
    must(s.put_checkpoint(Seq::from_raw(2), &state)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        must(s.latest_checkpoint()),
        Ok(Some((Seq::from_raw(2), state))),
        "ADR-007: the checkpoint"
    );
    assert!(
        !holds_canary(&db.dump(), &c),
        "R-NF-08: a checkpoint is readable at rest"
    );
}

/// ADR-007, design section 5.5: with checkpoints at two sequences, the
/// latest is the one at the higher sequence, whatever the write order.
#[test]
fn adr007_latest_checkpoint_is_the_highest_sequence() {
    let (_db, _w, mut s) = world();
    fill(&mut s, 3);
    assert_eq!(must(s.latest_checkpoint()), Ok(None), "no checkpoint yet");
    must(s.put_checkpoint(Seq::from_raw(3), b"three")).unwrap_or_else(|e| panic!("{e}"));
    must(s.put_checkpoint(Seq::from_raw(1), b"one")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        must(s.latest_checkpoint()),
        Ok(Some((Seq::from_raw(3), b"three".to_vec()))),
        "ADR-007: the latest checkpoint"
    );
}

/// ADR-007 amendment: a checkpoint is sealed like a ledger body, so a
/// body moved to another sequence by a superuser does not open.
#[test]
fn adr007_checkpoint_moved_to_another_sequence_does_not_open() {
    let (db, _w, mut s) = world();
    fill(&mut s, 2);
    must(s.put_checkpoint(Seq::from_raw(1), b"one")).unwrap_or_else(|e| panic!("{e}"));
    must(s.put_checkpoint(Seq::from_raw(2), b"two")).unwrap_or_else(|e| panic!("{e}"));
    db.psql(
        "UPDATE ops.checkpoint c SET body = o.body FROM ops.checkpoint o \
         WHERE (c.seq = 1 AND o.seq = 2) OR (c.seq = 2 AND o.seq = 1);",
    )
    .unwrap_or_else(|e| panic!("the swap: {e:?}"));
    let got = must(s.latest_checkpoint());
    assert!(got.is_err(), "ADR-007: a moved checkpoint opened: {got:?}");
}

// ---------------------------------------------------------------------------
// Texts (design section 5.6).

/// ADR-007, design section 5.6: `TextStore::put` then `TextStore::get`
/// returns the text, and the text appears in no form at rest.
#[test]
fn adr007_text_round_trips_and_is_sealed_at_rest() {
    let (db, _w, mut s) = world();
    let c = canary(&db.hex, "proposal-text");
    let r = must(s.put_text(&c)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        must(s.get_text(&r)),
        Ok(TextGot::Text(c.clone())),
        "ADR-007: the text"
    );
    assert!(
        !holds_canary(&db.dump(), &c),
        "R-NF-08: a text is readable at rest"
    );
}

/// ADR-007 (decided 2026-10-25): the digest of a `TextRef` is keyed with
/// a random salt per text. Two puts of one text get different ids and
/// different digests, and neither digest is the unkeyed SHA-256.
#[test]
fn adr007_text_digest_is_keyed_by_a_fresh_salt() {
    let (_db, _w, mut s) = world();
    let text = "the same rationale";
    let a = must(s.put_text(text)).unwrap_or_else(|e| panic!("{e}"));
    let b = must(s.put_text(text)).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(a.id, b.id, "ADR-007: one id for two texts");
    assert_ne!(a.digest, b.digest, "ADR-007: an unsalted digest");
    let plain = fstp_crypto::sha256(text.as_bytes());
    assert!(
        a.digest != plain && b.digest != plain,
        "ADR-007: the digest confirms a guessed text"
    );
}

/// I-81, ADR-007 "After erasure, a TextRef resolves to the text's entry
/// in the erasure log": once the keys role deletes the `blob.text` row of
/// a completed erasure, the reference resolves as erased, never to the
/// text. Another text still resolves.
#[test]
fn i81_text_without_its_blob_row_never_resolves_to_text() {
    let (db, _w, mut s) = world();
    let gone = must(s.put_text("to be erased")).unwrap_or_else(|e| panic!("{e}"));
    let kept = must(s.put_text("kept")).unwrap_or_else(|e| panic!("{e}"));
    db.psql_as(
        "keys",
        &format!(
            "DELETE FROM blob.text WHERE id = '{}'::uuid;",
            uuid_text(&gone.id)
        ),
    )
    .unwrap_or_else(|e| panic!("the keys role's delete: {e:?}"));
    let got = must(s.get_text(&gone));
    assert!(
        !matches!(got, Ok(TextGot::Text(_))),
        "I-81: an erased text resolved to its text: {got:?}"
    );
    assert_eq!(
        must(s.get_text(&kept)),
        Ok(TextGot::Text("kept".to_owned())),
        "I-81: a kept text"
    );
}

/// ADR-007: a reference to a text the store never held names no text.
#[test]
fn adr007_unknown_text_ref_names_no_text() {
    let (_db, _w, s) = world();
    let r = common::TextRefView {
        id: fresh16(),
        digest: [0x11; 32],
    };
    let got = must(s.get_text(&r));
    assert!(
        !matches!(got, Ok(TextGot::Text(_))),
        "ADR-007: an unknown reference resolved: {got:?}"
    );
}
