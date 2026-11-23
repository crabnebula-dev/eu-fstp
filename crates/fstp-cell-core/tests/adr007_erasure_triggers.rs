//! The authoriser and the reason of a keystore erasure (ADR-007 section
//! "Decided by Daniel on 2026-11-23", lane L39, I-24, R-KY-02).
//!
//! Daniel decided on 2026-11-23 that each trigger records its cause and
//! its authoriser: a system cause names the system, and a manual erasure
//! names the tenant admin, with a stated reason. The system authoriser is
//! `ERASURE_SYSTEM`, an id in the system task namespace. Every id is
//! synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{NOW, admin_granted, cid, ledger, state_of};
use fstp_cell_core::{
    CellCommand, CellRecord, CellState, ERASURE_KIND_DISPLAY_NAME, ERASURE_KIND_DOCUMENT,
    ERASURE_SYSTEM, KeyCommand, KeyRecord, SYSTEM_ERASURE_CAUSES, SYSTEM_PREFIX, SystemCtx,
    SystemTask, decide_system, decode_cell_command, decode_cell_record, encode_cell_command,
    encode_cell_record, is_system_authoriser,
};
use fstp_domain::id::AccountId;
use fstp_domain::oracle::Answers;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::ADMIN;

const DOC: [u8; 16] = [0xD9; 16];
const REASON: [u8; 16] = [0x39; 16];

fn at(minutes: i64) -> Timestamp {
    Timestamp::from_micros(NOW.micros() + minutes * 60_000_000)
}

fn state() -> CellState {
    state_of(&ledger(&[(at(0), cid(1), vec![admin_granted(ADMIN)])]).unwrap()).unwrap()
}

fn erasure(cause: u16, by: AccountId, kind: u8, reason: Option<[u8; 16]>) -> KeyCommand {
    KeyCommand::RecordKeystoreErasure {
        ids: vec![DOC],
        cause,
        by,
        kind,
        reason,
    }
}

fn decide_runner(s: &CellState, cmd: KeyCommand) -> Result<Vec<CellRecord>, String> {
    decide_system(
        s,
        &CellCommand::Key(cmd),
        &SystemCtx {
            task: SystemTask::ErasureRunner,
            at: at(5).micros(),
        },
        cid(90),
        &Answers::new(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// Another id of the system task namespace, which no erasure may name.
fn other_system_id() -> AccountId {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&SYSTEM_PREFIX);
    b[8..].copy_from_slice(b"timeline");
    AccountId::from_raw(u128::from_be_bytes(b))
}

/// ADR-007 (Daniel, 2026-11-23, question 3; lane L39): the system
/// authoriser lies in the system task namespace, no account id of the
/// roster does, and the system names only the system causes, with no
/// reason. The entry it records names the system.
#[test]
fn adr007_l39_system_authoriser_names_only_system_causes() {
    assert!(is_system_authoriser(ERASURE_SYSTEM));
    assert!(ERASURE_SYSTEM.raw().to_be_bytes().starts_with(&SYSTEM_PREFIX));
    assert!(!is_system_authoriser(ADMIN));
    assert_eq!(SYSTEM_ERASURE_CAUSES, [1, 4], "retention expiry, verification");
    let s = state();
    let ok = decide_runner(&s, erasure(1, ERASURE_SYSTEM, ERASURE_KIND_DOCUMENT, None)).unwrap();
    assert_eq!(
        ok,
        vec![CellRecord::Key(KeyRecord::KeystoreErasureRequested {
            ids: vec![DOC],
            cause: 1,
            by: ERASURE_SYSTEM,
            kind: ERASURE_KIND_DOCUMENT,
            reason: None,
        })]
    );
    let s = state_of(
        &ledger(&[
            (at(0), cid(1), vec![admin_granted(ADMIN)]),
            (at(5), cid(2), ok),
        ])
        .unwrap(),
    )
    .unwrap();
    let e = s.erasure(DOC).unwrap();
    assert_eq!((e.cause, e.by, e.reason), (1, ERASURE_SYSTEM, None));
    // An erasure request is a person's or an admin's, never the system's.
    assert!(decide_runner(&state(), erasure(2, ERASURE_SYSTEM, ERASURE_KIND_DOCUMENT, None)).is_err());
    // The system states no reason.
    assert!(
        decide_runner(
            &state(),
            erasure(1, ERASURE_SYSTEM, ERASURE_KIND_DOCUMENT, Some(REASON))
        )
        .is_err()
    );
    // No other id of the namespace authorises an erasure.
    assert!(
        decide_runner(&state(), erasure(1, other_system_id(), ERASURE_KIND_DOCUMENT, None))
            .is_err()
    );
    // A manual erasure names the admin and keeps its reason.
    let manual = decide_runner(
        &state(),
        erasure(2, ADMIN, ERASURE_KIND_DOCUMENT, Some(REASON)),
    )
    .unwrap();
    let s = state_of(
        &ledger(&[
            (at(0), cid(1), vec![admin_granted(ADMIN)]),
            (at(5), cid(2), manual),
        ])
        .unwrap(),
    )
    .unwrap();
    let e = s.erasure(DOC).unwrap();
    assert_eq!((e.cause, e.by, e.reason), (2, ADMIN, Some(REASON)));
}

/// ADR-007 (lane L39), property over the whole closed domain: every
/// cause code from 0 to 6, both keystore kinds, an account, the system
/// and another system id, with and without a reason. The decider admits
/// exactly the requests the rule names: a known cause, and for a system
/// id only `ERASURE_SYSTEM` with a system cause and no reason.
#[test]
fn adr007_l39_prop_keystore_erasure_authoriser_rule() {
    let s = state();
    let mut admitted = 0;
    for cause in 0..=6u16 {
        for kind in [ERASURE_KIND_DISPLAY_NAME, ERASURE_KIND_DOCUMENT] {
            for by in [ADMIN, ERASURE_SYSTEM, other_system_id()] {
                for reason in [None, Some(REASON)] {
                    let known = (1..=4).contains(&cause);
                    let want = known
                        && if is_system_authoriser(by) {
                            by == ERASURE_SYSTEM
                                && SYSTEM_ERASURE_CAUSES.contains(&cause)
                                && reason.is_none()
                        } else {
                            true
                        };
                    let got = decide_runner(&s, erasure(cause, by, kind, reason));
                    assert_eq!(
                        got.is_ok(),
                        want,
                        "cause {cause} kind {kind} by {by:?} reason {reason:?}: {got:?}"
                    );
                    if want {
                        admitted += 1;
                    }
                }
            }
        }
    }
    assert!(admitted > 0, "the domain admits some requests");
}

/// I-24 (lane L39): a reason round trips through the ledger codec, and a
/// record or command without one keeps the exact bytes of its old form,
/// so every stored entry still decodes and hashes the same.
#[test]
fn i24_l39_reason_round_trips_and_the_old_form_decodes() {
    let with = CellRecord::Key(KeyRecord::KeystoreErasureRequested {
        ids: vec![DOC],
        cause: 2,
        by: ADMIN,
        kind: ERASURE_KIND_DOCUMENT,
        reason: Some(REASON),
    });
    assert_eq!(decode_cell_record(&encode_cell_record(&with)).unwrap(), with);
    let without = CellRecord::Key(KeyRecord::KeystoreErasureRequested {
        ids: vec![DOC],
        cause: 2,
        by: ADMIN,
        kind: ERASURE_KIND_DOCUMENT,
        reason: None,
    });
    let bytes = encode_cell_record(&without);
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains("reason"), "the old form: {text}");
    assert_eq!(decode_cell_record(&bytes).unwrap(), without);
    let with_text = String::from_utf8(encode_cell_record(&with)).unwrap();
    assert!(with_text.contains(&"39".repeat(16)), "{with_text}");
    for c in [
        erasure(2, ADMIN, ERASURE_KIND_DOCUMENT, Some(REASON)),
        erasure(1, ERASURE_SYSTEM, ERASURE_KIND_DOCUMENT, None),
    ] {
        let c = CellCommand::Key(c);
        assert_eq!(decode_cell_command(&encode_cell_command(&c)).unwrap(), c);
    }
    // A reason that is no 16-byte id is refused.
    let bad = with_text.replace(&"39".repeat(16), "3939");
    assert!(decode_cell_record(bad.as_bytes()).is_err(), "{bad}");
}
