//! The API core's tables and the API side effects of an append
//! (ADR-026, ADR-010 amendment of 2026-11-20, I-21, I-24, I-85).
//!
//! Lane L1 wrote these before `ApiStore`, the `pending_confirmed` side
//! effect and the event rows. Each test provisions its own cell database
//! with the reference grants, plus the `api` and `workspace` rows of the
//! production plan (`fstp_control::pg`), granted here by the superuser.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{CellDb, FakeWitness, Rec, Store, api_store, block_on, fresh16, must};
use fstp_ledger::Seq;
use fstp_pgstore::{
    AppendFault, PendingConfirm, PendingRow, SideEffects, StoredPendingStatus, open_event_body,
};

/// A time inside the bound, in UTC microseconds.
const AT: i64 = 1_793_232_000_000_000;

/// The cell database with the `api` and `workspace` grants of the
/// production plan.
fn world() -> (CellDb, FakeWitness, Store) {
    let db = must(CellDb::provision());
    let app = db.role("app");
    let writer = db.role("writer");
    db.psql(&format!(
        "GRANT USAGE ON SCHEMA api, workspace TO {app}; \
         GRANT USAGE ON SCHEMA api TO {writer}; \
         GRANT SELECT, INSERT, UPDATE, DELETE ON api.pending_actions, workspace.drafts, workspace.anonymous_drafts TO {app}; \
         GRANT SELECT ON api.pending_confirmed TO {app}; \
         GRANT SELECT, INSERT ON api.pending_confirmed TO {writer};"
    ))
    .unwrap();
    let w = FakeWitness::new(db.cell_id());
    let s = must(Store::open(&db, &w));
    (db, w, s)
}

fn pending(id: [u8; 16], account: [u8; 16]) -> PendingRow {
    PendingRow {
        id,
        account,
        client: [0xC1; 16],
        op: "programme.prepare_draft".to_owned(),
        request: b"{\"op\":\"synthetic-canary-request\"}".to_vec(),
        digest: [0xD1; 32],
        created: AT,
        expires: AT + 86_400_000_000,
        status: StoredPendingStatus::Open,
        closed: None,
        confirmed: None,
    }
}

/// I-85, ADR-026: the append that confirms a pending action inserts its
/// one confirmation row, naming the batch's entry. A second append that
/// confirms the same action violates the primary key, and the whole
/// append aborts: no entry, no chain row and no witness prepare.
#[test]
fn i85_second_confirmation_aborts_the_whole_append() {
    let (db, _w, mut s) = world();
    let api = api_store(&db);
    let id = fresh16();
    block_on(api.insert_pending(&pending(id, [0xA1; 16]))).unwrap();
    let side = SideEffects {
        pending_confirmed: Some(PendingConfirm { id, record: 0 }),
        ..SideEffects::default()
    };
    let head = s
        .append_effects(
            Seq::ZERO,
            AT,
            fresh16(),
            vec![Rec::new(1, "confirm")],
            &side,
        )
        .unwrap();
    assert_eq!(head, Seq::from_raw(1));
    let row = block_on(api.pending(id)).unwrap().unwrap();
    assert_eq!(
        row.confirmed,
        Some(1),
        "I-85: the confirmation names entry 1"
    );
    let before = db.row_counts();
    let again = s.append_effects(head, AT, fresh16(), vec![Rec::new(1, "again")], &side);
    assert_eq!(again, Err(AppendFault::PendingConfirmed), "I-85");
    assert_eq!(db.row_counts(), before, "I-85: rows of the aborted append");
    // A confirmed action cannot be discarded or marked expired.
    assert!(!block_on(api.close_pending(id, StoredPendingStatus::Discarded, AT)).unwrap());
    assert!(!block_on(api.close_pending(id, StoredPendingStatus::Expired, AT)).unwrap());
}

/// I-85, ADR-026: a pending action is found by its id and listed for its
/// account only. Its request is sealed at rest and opens to what was
/// stored. A discard closes an open action once.
#[test]
fn i85_pending_rows_round_trip_sealed() {
    let (db, _w, _s) = world();
    let api = api_store(&db);
    let (a, b) = ([0xA1; 16], [0xA2; 16]);
    let one = pending(fresh16(), a);
    let two = pending(fresh16(), b);
    block_on(api.insert_pending(&one)).unwrap();
    block_on(api.insert_pending(&two)).unwrap();
    let got = block_on(api.pending(one.id)).unwrap().unwrap();
    assert_eq!(got, one);
    let listed = block_on(api.pending_of(a)).unwrap();
    assert_eq!(listed, vec![one.clone()]);
    assert_eq!(block_on(api.open_count(a, AT)).unwrap(), 1);
    assert_eq!(block_on(api.open_count(a, one.expires)).unwrap(), 0);
    let raw = db
        .psql("SELECT encode(request, 'hex') FROM api.pending_actions;")
        .unwrap();
    let canary: String = b"synthetic-canary-request"
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(!raw.contains(&canary), "R-NF-08: a clear request at rest");
    assert!(block_on(api.close_pending(one.id, StoredPendingStatus::Discarded, AT + 1)).unwrap());
    assert!(!block_on(api.close_pending(one.id, StoredPendingStatus::Discarded, AT + 2)).unwrap());
    let closed = block_on(api.pending(one.id)).unwrap().unwrap();
    assert_eq!(closed.status, StoredPendingStatus::Discarded);
    assert_eq!(closed.closed, Some(AT + 1));
}

/// I-21, ADR-026: a workspace slot holds the sealed bytes it was given,
/// and a second put replaces them and counts a revision.
#[test]
fn i21_workspace_rows_hold_sealed_bytes_only() {
    let (db, _w, _s) = world();
    let api = api_store(&db);
    let keys = common::ledger_keys_reusing_last(db.cell);
    let proposal = fresh16();
    let first =
        fstp_pgstore::seal_workspace(&keys, &db.cell, &proposal, b"synthetic-draft-one").unwrap();
    let second =
        fstp_pgstore::seal_workspace(&keys, &db.cell, &proposal, b"synthetic-draft-two").unwrap();
    assert_eq!(block_on(api.workspace(proposal, "draft")).unwrap(), None);
    block_on(api.put_workspace(proposal, "draft", &first, AT)).unwrap();
    block_on(api.put_workspace(proposal, "draft", &second, AT + 1)).unwrap();
    let got = block_on(api.workspace(proposal, "draft")).unwrap().unwrap();
    assert_eq!(got, second);
    assert_eq!(
        fstp_pgstore::open_workspace(&keys, &db.cell, &proposal, &got).unwrap(),
        b"synthetic-draft-two"
    );
    assert_eq!(db.count("SELECT revision FROM workspace.drafts;"), 2);
    let raw = db
        .psql("SELECT encode(sealed, 'escape') FROM workspace.drafts;")
        .unwrap();
    assert!(
        !raw.contains("synthetic-draft"),
        "I-21: a clear value at rest"
    );
    assert!(block_on(api.put_workspace(proposal, "draft", b"clear", AT)).is_err());
}

/// ADR-032, R-NF-08, R-NF-02: an anonymous draft rests sealed under its
/// token digest, never as clear text and never under the token. It opens
/// while live only, a digest in use stores nothing, a save replaces the
/// text, and the sweep deletes exactly the expired rows.
#[test]
fn adr032_anonymous_drafts_rest_sealed_under_the_token_digest() {
    let (db, _w, _s) = world();
    let api = api_store(&db);
    let token = [0x7A_u8; 32];
    let digest = fstp_crypto::sha256(&token);
    let call = fresh16();
    let one = b"{\"narrative\":\"synthetic-anon-one\",\"summary\":\"\",\"title\":\"\"}";
    let two = b"{\"narrative\":\"synthetic-anon-two\",\"summary\":\"\",\"title\":\"\"}";
    block_on(api.anon_start(digest, call, one, AT, AT + 100)).unwrap();
    assert!(block_on(api.anon_start(digest, call, one, AT, AT + 100)).is_err());
    let got = block_on(api.anon_open(digest, AT + 1)).unwrap().unwrap();
    assert_eq!((got.call, got.plain.as_slice()), (call, &one[..]));
    assert!(block_on(api.anon_save(digest, two, AT + 2)).unwrap());
    let got = block_on(api.anon_open(digest, AT + 3)).unwrap().unwrap();
    assert_eq!(got.plain.as_slice(), &two[..]);
    let raw = db
        .psql("SELECT encode(sealed, 'escape') || encode(token_hash, 'hex') FROM workspace.anonymous_drafts;")
        .unwrap();
    assert!(
        !raw.contains("synthetic-anon"),
        "R-NF-08: a clear value at rest"
    );
    let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!raw.contains(&hex), "the token itself is stored");
    let other = fstp_crypto::sha256(&[0x7B_u8; 32]);
    block_on(api.anon_start(other, call, one, AT, AT + 10)).unwrap();
    assert_eq!(block_on(api.anon_live(AT + 5)).unwrap(), 2);
    assert!(block_on(api.anon_open(other, AT + 10)).unwrap().is_none());
    assert!(!block_on(api.anon_save(other, two, AT + 10)).unwrap());
    assert_eq!(block_on(api.anon_sweep(AT + 10)).unwrap(), 1);
    assert_eq!(block_on(api.anon_live(AT + 10)).unwrap(), 1);
    assert!(block_on(api.anon_remove(digest)).unwrap());
    assert!(!block_on(api.anon_remove(digest)).unwrap());
    assert!(block_on(api.anon_open(digest, AT + 4)).unwrap().is_none());
}

/// I-24, ADR-010 amendment of 2026-11-20: audit events commit as kind 2
/// rows after their batch's entries, under the batch's anchor, and alone
/// in an event transaction. Each body opens under its row number only,
/// and holds no clear byte of the event.
#[test]
fn i24_audit_events_commit_with_their_batch_and_alone() {
    let (db, w, mut s) = world();
    let side = SideEffects {
        events: vec![b"synthetic-event-one".to_vec()],
        ..SideEffects::default()
    };
    let c = s
        .append_committed(Seq::ZERO, AT, fresh16(), vec![Rec::new(1, "x")], &side)
        .unwrap();
    assert_eq!(c.head, Seq::from_raw(1));
    assert_eq!(c.n, 1, "the commit reports the chain row of its last entry");
    let alone = s
        .append_events(
            AT + 1,
            vec![b"synthetic-event-two".to_vec(), b"three".to_vec()],
        )
        .unwrap();
    assert_eq!(
        alone.head,
        Seq::from_raw(1),
        "an event moves no ledger head"
    );
    assert_eq!(alone.n, 4);
    assert!(s.append_events(AT, Vec::new()).is_err());
    let rows = s.read_chain_rows();
    let kinds: Vec<u16> = rows
        .rows
        .iter()
        .map(|r| match r.row.kind {
            fstp_audit::RowKind::Ledger { .. } => 1,
            fstp_audit::RowKind::Event { .. } => 2,
        })
        .collect();
    assert_eq!(kinds, vec![1, 2, 2, 2]);
    let keys = common::ledger_keys_reusing_last(db.cell);
    let mut opened = Vec::new();
    for r in &rows.rows {
        if let fstp_audit::RowKind::Event { body } = &r.row.kind {
            assert!(!body.windows(9).any(|x| x == b"synthetic"), "a clear event");
            opened.push(open_event_body(&keys, &db.cell, r.row.n, body).unwrap());
            assert!(open_event_body(&keys, &db.cell, r.row.n + 1, body).is_err());
        }
    }
    assert_eq!(
        opened,
        vec![
            b"synthetic-event-one".to_vec(),
            b"synthetic-event-two".to_vec(),
            b"three".to_vec()
        ]
    );
    // Every chain row was prepared at the witness: the last prepare names
    // the last row.
    let last = w.recorded().into_iter().rev().find_map(|p| match p {
        common::Recorded::Prepare { n, .. } => Some(n),
        _ => None,
    });
    assert_eq!(last, Some(4), "I-24: an unwitnessed event row");
    // The verifier of ADR-010 reads the event rows as it reads entries.
    common::verify_production(&db, &w, &s).unwrap();
}
