//! The erasure log of the production cell in the ledger (ADR-007 section
//! "Built by lane L33", R-KY-02, I-81, I-24). Lane L33.
//!
//! A text the keystore keeps and no ledger record names, such as a
//! replaced display name, gets its request entry from the erasure runner's
//! `RecordKeystoreErasure`. Every erased text gets the destroyed root
//! epoch from `RecordErasuresCompleted` once its key died. Only the
//! erasure runner decides either record. Every id is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{NOW, admin_granted, cid, ledger, state_of};
use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{
    CellCommand, CellCtx, CellRecord, CellState, ERASURE_KIND_DISPLAY_NAME,
    ERASURE_KIND_LEDGER_TEXT, KeyCommand, KeyRecord, SystemCtx, SystemTask, decide, decide_system,
    decode_cell_command, decode_cell_record, encode_cell_command, encode_cell_record,
};
use fstp_domain::id::AccountId;
use fstp_domain::oracle::Answers;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN};

const NAME: [u8; 16] = [0x4E; 16];
const NAME_2: [u8; 16] = [0x4F; 16];
const LEDGER_TEXT: [u8; 16] = [0x7E; 16];

fn at(minutes: i64) -> Timestamp {
    Timestamp::from_micros(NOW.micros() + minutes * 60_000_000)
}

fn runner(t: Timestamp) -> SystemCtx {
    SystemCtx {
        task: SystemTask::ErasureRunner,
        at: t.micros(),
    }
}

fn keystore_erasure(ids: Vec<[u8; 16]>, by: AccountId) -> KeyCommand {
    KeyCommand::RecordKeystoreErasure {
        ids,
        cause: 2,
        by,
        kind: ERASURE_KIND_DISPLAY_NAME,
        reason: None,
    }
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
        &runner(t),
        cid(90),
        &Answers::new(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// R-KY-02, I-81, ADR-007 (lane L33): a keystore text's erasure request
/// is an entry of the log with its cause, its authoriser and its kind, and
/// no completion. The destruction of its root epoch completes it, with the
/// epoch and the instant.
#[test]
fn r_ky_02_i81_keystore_erasure_is_logged_then_completed_by_its_epoch() {
    let s = state(vec![]);
    let requested = decide_runner(&s, keystore_erasure(vec![NAME], A), at(5)).unwrap();
    assert_eq!(
        requested,
        vec![CellRecord::Key(KeyRecord::KeystoreErasureRequested {
            ids: vec![NAME],
            cause: 2,
            by: A,
            kind: ERASURE_KIND_DISPLAY_NAME,
            reason: None,
        })]
    );
    let s = state(vec![(at(5), cid(3), requested)]);
    let e = s.erasure(NAME).expect("the entry");
    assert_eq!(e.requested_at, at(5));
    assert_eq!(e.completed_at, None, "no completion before the key died");
    assert_eq!((e.cause, e.by, e.kind), (2, A, ERASURE_KIND_DISPLAY_NAME));
    assert_eq!(e.destroyed_epoch, None);
    let destroyed = vec![CellRecord::Key(KeyRecord::KeystoreErasureRequested {
        ids: vec![NAME],
        cause: 2,
        by: A,
        kind: ERASURE_KIND_DISPLAY_NAME,
        reason: None,
    })];
    let s = state(vec![
        (at(5), cid(3), destroyed),
        (
            at(9),
            cid(4),
            vec![CellRecord::Key(KeyRecord::EpochDestroyed {
                epoch: 4,
                receipt: [0xD5; 32],
            })],
        ),
    ]);
    let completed = decide_runner(
        &s,
        KeyCommand::RecordErasuresCompleted {
            epoch: 4,
            ids: vec![NAME],
        },
        at(9),
    )
    .unwrap();
    let mut batches = vec![
        (
            at(5),
            cid(3),
            vec![CellRecord::Key(KeyRecord::KeystoreErasureRequested {
                ids: vec![NAME],
                cause: 2,
                by: A,
                kind: ERASURE_KIND_DISPLAY_NAME,
                reason: None,
            })],
        ),
        (
            at(9),
            cid(4),
            vec![CellRecord::Key(KeyRecord::EpochDestroyed {
                epoch: 4,
                receipt: [0xD5; 32],
            })],
        ),
    ];
    batches.push((at(9), cid(5), completed));
    let s = state(batches);
    let e = s.erasure(NAME).unwrap();
    assert_eq!(
        e.completed_at,
        Some(at(9)),
        "R-KY-02: completed by the destruction"
    );
    assert_eq!(e.destroyed_epoch, Some(4), "I-81: the epoch that died");
    assert_eq!(e.destroyed_at, Some(at(9)));
    let all: Vec<[u8; 16]> = s.erasures().map(|(id, _)| id).collect();
    assert_eq!(all, vec![NAME]);
}

/// ADR-007 (lane L33): a ledger text keeps the `TextsErased` instant as its
/// completion, and gains the destroyed epoch and its instant.
#[test]
fn adr007_ledger_text_gains_its_destroyed_epoch() {
    let s = state(vec![
        (
            at(5),
            cid(3),
            vec![
                CellRecord::Text(TextRecord::ErasureRequested {
                    ids: vec![LEDGER_TEXT],
                    cause: 2,
                    by: ADMIN,
                }),
                CellRecord::Text(TextRecord::TextsErased {
                    ids: vec![LEDGER_TEXT],
                }),
            ],
        ),
        (
            at(9),
            cid(4),
            vec![
                CellRecord::Key(KeyRecord::EpochDestroyed {
                    epoch: 2,
                    receipt: [0xD5; 32],
                }),
                CellRecord::Key(KeyRecord::ErasuresCompleted {
                    epoch: 2,
                    ids: vec![LEDGER_TEXT],
                }),
            ],
        ),
    ]);
    let e = s.erasure(LEDGER_TEXT).unwrap();
    assert_eq!(e.kind, ERASURE_KIND_LEDGER_TEXT);
    assert_eq!(e.completed_at, Some(at(5)));
    assert_eq!((e.destroyed_epoch, e.destroyed_at), (Some(2), Some(at(9))));
}

/// ADR-007 (lane L33): a keystore erasure names no ledger text, no text
/// with an entry, no unknown kind or cause and no empty list. Only the
/// erasure runner decides it: the timeline and an account are refused.
#[test]
fn adr007_keystore_erasure_refusals() {
    let s = state(vec![(
        at(5),
        cid(3),
        vec![CellRecord::Key(KeyRecord::KeystoreErasureRequested {
            ids: vec![NAME],
            cause: 2,
            by: A,
            kind: ERASURE_KIND_DISPLAY_NAME,
            reason: None,
        })],
    )]);
    for bad in [
        keystore_erasure(vec![LEDGER_TEXT], A),
        keystore_erasure(vec![NAME], A),
        keystore_erasure(vec![NAME_2, NAME_2], A),
        keystore_erasure(vec![], A),
        KeyCommand::RecordKeystoreErasure {
            ids: vec![NAME_2],
            cause: 9,
            by: A,
            kind: ERASURE_KIND_DISPLAY_NAME,
            reason: None,
        },
        KeyCommand::RecordKeystoreErasure {
            ids: vec![NAME_2],
            cause: 2,
            by: A,
            kind: ERASURE_KIND_LEDGER_TEXT,
            reason: None,
        },
    ] {
        assert!(decide_runner(&s, bad.clone(), at(6)).is_err(), "{bad:?}");
    }
    assert!(decide_runner(&s, keystore_erasure(vec![NAME_2], A), at(6)).is_ok());
    let timeline = SystemCtx {
        task: SystemTask::Timeline,
        at: at(6).micros(),
    };
    let cmd = CellCommand::Key(keystore_erasure(vec![NAME_2], A));
    assert!(decide_system(&s, &cmd, &timeline, cid(91), &Answers::new()).is_err());
    let account = CellCtx {
        actor: ADMIN,
        at: at(6).micros(),
    };
    assert!(decide(&s, &cmd, &account, &Answers::new()).is_err());
    // An account's own text path cannot erase a keystore text either.
    let erase = CellCommand::Text(TextCommand::EraseTexts {
        ids: vec![NAME_2],
        cause: 2,
    });
    assert!(decide(&s, &erase, &account, &Answers::new()).is_err());
}

/// I-81, ADR-007 (lane L33): a completion names a destroyed epoch, and
/// only texts with an entry that no epoch completed yet. The fold refuses
/// what the decision refuses.
#[test]
fn i81_completion_needs_a_destroyed_epoch_and_an_open_entry() {
    let requested = CellRecord::Key(KeyRecord::KeystoreErasureRequested {
        ids: vec![NAME],
        cause: 2,
        by: A,
        kind: ERASURE_KIND_DISPLAY_NAME,
        reason: None,
    });
    let s = state(vec![(at(5), cid(3), vec![requested.clone()])]);
    let done = |epoch, ids| KeyCommand::RecordErasuresCompleted { epoch, ids };
    assert!(
        decide_runner(&s, done(4, vec![NAME]), at(9)).is_err(),
        "no epoch"
    );
    let s = state(vec![
        (at(5), cid(3), vec![requested.clone()]),
        (
            at(9),
            cid(4),
            vec![CellRecord::Key(KeyRecord::EpochDestroyed {
                epoch: 4,
                receipt: [0xD5; 32],
            })],
        ),
    ]);
    assert!(
        decide_runner(&s, done(4, vec![NAME_2]), at(9)).is_err(),
        "no entry"
    );
    assert!(decide_runner(&s, done(4, vec![]), at(9)).is_err(), "empty");
    assert!(decide_runner(&s, done(4, vec![NAME]), at(9)).is_ok());
    let twice = ledger(&[
        (at(0), cid(1), vec![admin_granted(ADMIN)]),
        (at(5), cid(3), vec![requested]),
        (
            at(9),
            cid(4),
            vec![
                CellRecord::Key(KeyRecord::EpochDestroyed {
                    epoch: 4,
                    receipt: [0xD5; 32],
                }),
                CellRecord::Key(KeyRecord::ErasuresCompleted {
                    epoch: 4,
                    ids: vec![NAME],
                }),
            ],
        ),
        (
            at(10),
            cid(5),
            vec![CellRecord::Key(KeyRecord::ErasuresCompleted {
                epoch: 4,
                ids: vec![NAME],
            })],
        ),
    ])
    .unwrap();
    assert!(state_of(&twice).is_err(), "I-81: a second completion");
}

/// I-24, ADR-007 (lane L33): the new records and commands round trip
/// through the ledger codec.
#[test]
fn i24_erasure_log_records_round_trip() {
    for r in [
        CellRecord::Key(KeyRecord::KeystoreErasureRequested {
            ids: vec![NAME, NAME_2],
            cause: 2,
            by: A,
            kind: ERASURE_KIND_DISPLAY_NAME,
            reason: None,
        }),
        CellRecord::Key(KeyRecord::ErasuresCompleted {
            epoch: 7,
            ids: vec![NAME],
        }),
    ] {
        assert_eq!(decode_cell_record(&encode_cell_record(&r)).unwrap(), r);
    }
    for c in [
        CellCommand::Key(keystore_erasure(vec![NAME], A)),
        CellCommand::Key(KeyCommand::RecordErasuresCompleted {
            epoch: 7,
            ids: vec![NAME],
        }),
    ] {
        assert_eq!(decode_cell_command(&encode_cell_command(&c)).unwrap(), c);
    }
}
