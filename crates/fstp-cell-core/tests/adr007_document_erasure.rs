//! Document erasures in the erasure log (ADR-007 section "Built by lane
//! L37", R-KY-02, I-81, I-24). Lane L37.
//!
//! A document's data key id names its entry. The erasure runner appends
//! the request as `KeystoreErasureRequested` with the document kind, and
//! `ErasuresCompleted` completes it once the key's root epoch died. Every
//! id is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{NOW, admin_granted, cid, ledger, state_of};
use fstp_cell_core::text::TextRecord;
use fstp_cell_core::{
    CellCommand, CellCtx, CellRecord, CellState, ERASURE_KIND_DISPLAY_NAME, ERASURE_KIND_DOCUMENT,
    ERASURE_KIND_LEDGER_TEXT, KEYSTORE_ERASURE_KINDS, KeyCommand, KeyRecord, SystemCtx, SystemTask,
    decide, decide_system, decode_cell_command, decode_cell_record, encode_cell_command,
    encode_cell_record,
};
use fstp_domain::oracle::Answers;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN};

const DOC: [u8; 16] = [0xD0; 16];
const DOC_2: [u8; 16] = [0xD1; 16];
const LEDGER_TEXT: [u8; 16] = [0x7E; 16];

fn at(minutes: i64) -> Timestamp {
    Timestamp::from_micros(NOW.micros() + minutes * 60_000_000)
}

fn document(ids: Vec<[u8; 16]>) -> KeyCommand {
    KeyCommand::RecordKeystoreErasure {
        ids,
        cause: 2,
        by: ADMIN,
        kind: ERASURE_KIND_DOCUMENT,
    }
}

fn requested(ids: Vec<[u8; 16]>) -> CellRecord {
    CellRecord::Key(KeyRecord::KeystoreErasureRequested {
        ids,
        cause: 2,
        by: ADMIN,
        kind: ERASURE_KIND_DOCUMENT,
    })
}

/// A ledger with a tenant admin, a ledger text, and the given batches.
fn state(extra: Vec<(Timestamp, [u8; 16], Vec<CellRecord>)>) -> CellState {
    let mut batches = vec![
        (at(0), cid(1), vec![admin_granted(ADMIN)]),
        (
            at(1),
            cid(2),
            vec![CellRecord::Text(TextRecord::TextPut { id: LEDGER_TEXT })],
        ),
    ];
    batches.extend(extra);
    state_of(&ledger(&batches).unwrap()).unwrap()
}

fn decide_runner(s: &CellState, cmd: KeyCommand, t: Timestamp) -> Result<Vec<CellRecord>, String> {
    decide_system(
        s,
        &CellCommand::Key(cmd),
        &SystemCtx {
            task: SystemTask::ErasureRunner,
            at: t.micros(),
        },
        cid(90),
        &Answers::new(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// R-KY-02, I-81, ADR-007 (lane L37): a document erasure is an entry of
/// the log with the document kind, its cause and its authoriser, and no
/// completion. The destruction of its root epoch completes it.
#[test]
fn r_ky_02_i81_document_erasure_is_logged_then_completed_by_its_epoch() {
    assert!(KEYSTORE_ERASURE_KINDS.contains(&ERASURE_KIND_DOCUMENT));
    assert!(
        ![ERASURE_KIND_LEDGER_TEXT, ERASURE_KIND_DISPLAY_NAME].contains(&ERASURE_KIND_DOCUMENT),
        "a kind of its own"
    );
    let s = state(vec![]);
    let records = decide_runner(&s, document(vec![DOC]), at(5)).unwrap();
    assert_eq!(records, vec![requested(vec![DOC])]);
    let s = state(vec![(at(5), cid(3), records.clone())]);
    let e = s.erasure(DOC).expect("the entry");
    assert_eq!((e.cause, e.by, e.kind), (2, ADMIN, ERASURE_KIND_DOCUMENT));
    assert_eq!(e.requested_at, at(5));
    assert_eq!(
        e.completed_at, None,
        "I-81: no completion before the key died"
    );
    assert_eq!(e.destroyed_epoch, None);
    let destroyed = (
        at(9),
        cid(4),
        vec![CellRecord::Key(KeyRecord::EpochDestroyed {
            epoch: 6,
            receipt: [0xD6; 32],
        })],
    );
    let s = state(vec![(at(5), cid(3), records.clone()), destroyed.clone()]);
    let completed = decide_runner(
        &s,
        KeyCommand::RecordErasuresCompleted {
            epoch: 6,
            ids: vec![DOC],
        },
        at(9),
    )
    .unwrap();
    let s = state(vec![
        (at(5), cid(3), records),
        destroyed,
        (at(9), cid(5), completed),
    ]);
    let e = s.erasure(DOC).unwrap();
    assert_eq!(e.kind, ERASURE_KIND_DOCUMENT);
    assert_eq!(e.completed_at, Some(at(9)), "R-KY-02: completed");
    assert_eq!((e.destroyed_epoch, e.destroyed_at), (Some(6), Some(at(9))));
}

/// ADR-007 (lane L37): a document erasure names no ledger text, no id with
/// an entry, no unknown cause and no empty list. Only the erasure runner
/// decides it. The fold refuses a second request of the same document.
#[test]
fn adr007_document_erasure_refusals() {
    let s = state(vec![(at(5), cid(3), vec![requested(vec![DOC])])]);
    for bad in [
        document(vec![LEDGER_TEXT]),
        document(vec![DOC]),
        document(vec![DOC_2, DOC_2]),
        document(vec![]),
        KeyCommand::RecordKeystoreErasure {
            ids: vec![DOC_2],
            cause: 9,
            by: ADMIN,
            kind: ERASURE_KIND_DOCUMENT,
        },
        KeyCommand::RecordKeystoreErasure {
            ids: vec![DOC_2],
            cause: 2,
            by: ADMIN,
            kind: 4,
        },
    ] {
        assert!(decide_runner(&s, bad.clone(), at(6)).is_err(), "{bad:?}");
    }
    assert!(decide_runner(&s, document(vec![DOC_2]), at(6)).is_ok());
    let cmd = CellCommand::Key(document(vec![DOC_2]));
    let timeline = SystemCtx {
        task: SystemTask::Timeline,
        at: at(6).micros(),
    };
    assert!(decide_system(&s, &cmd, &timeline, cid(91), &Answers::new()).is_err());
    let account = CellCtx {
        actor: A,
        at: at(6).micros(),
    };
    assert!(decide(&s, &cmd, &account, &Answers::new()).is_err());
    let twice = ledger(&[
        (at(0), cid(1), vec![admin_granted(ADMIN)]),
        (at(5), cid(3), vec![requested(vec![DOC])]),
        (at(6), cid(4), vec![requested(vec![DOC])]),
    ])
    .unwrap();
    assert!(
        state_of(&twice).is_err(),
        "a second request of one document"
    );
    let text = ledger(&[
        (at(0), cid(1), vec![admin_granted(ADMIN)]),
        (
            at(1),
            cid(2),
            vec![CellRecord::Text(TextRecord::TextPut { id: LEDGER_TEXT })],
        ),
        (at(5), cid(3), vec![requested(vec![LEDGER_TEXT])]),
    ])
    .unwrap();
    assert!(state_of(&text).is_err(), "a ledger text is no document");
}

/// I-24, ADR-007 (lane L37): the document kind round trips through the
/// ledger codec.
#[test]
fn i24_document_erasure_round_trips() {
    let r = requested(vec![DOC, DOC_2]);
    assert_eq!(decode_cell_record(&encode_cell_record(&r)).unwrap(), r);
    let c = CellCommand::Key(document(vec![DOC]));
    assert_eq!(decode_cell_command(&encode_cell_command(&c)).unwrap(), c);
}
