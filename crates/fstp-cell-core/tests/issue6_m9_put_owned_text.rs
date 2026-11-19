//! Issue 6 M9 (H-01, ADR-025): a text is tied to an object the caller may
//! write, its declared length is bounded, and one account puts at most a
//! bounded number of bytes of text per UTC day.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use fstp_cell_core::tenant::TenantRecord;
use fstp_cell_core::text::{DAILY_TEXT_BYTES, MAX_TEXT_LEN, TextCommand, TextOwner, TextRecord};
use fstp_cell_core::{
    CellCommand, CellCtx, CellRecord, CellState, decode_cell_command, decode_cell_record,
    encode_cell_command, encode_cell_record,
};
use fstp_domain::id::AccountId;
use fstp_domain::oracle::Answers;
use fstp_ledger::{MemStore, RecordStore, Seq};

const ADMIN: AccountId = AccountId::from_raw(1);
const A: AccountId = AccountId::from_raw(4);
const B: AccountId = AccountId::from_raw(5);
const DAY_US: i64 = 86_400_000_000;
/// Noon of a UTC day.
const NOON: i64 = 20_000 * DAY_US + DAY_US / 2;

/// The state after `batches`, each `(at, records)`.
fn state(batches: &[(i64, Vec<CellRecord>)]) -> CellState {
    let mut store: MemStore<CellRecord> = MemStore::new();
    for (i, (at, b)) in batches.iter().enumerate() {
        let id = [u8::try_from(i + 1).unwrap(); 16];
        store.append(store.head(), *at, id, b.clone()).unwrap();
    }
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).unwrap();
    fstp_cell_core::replay(&out).unwrap()
}

fn put(id: u8, owner: AccountId, len: u32) -> CellCommand {
    CellCommand::Text(TextCommand::PutOwnedText {
        id: [id; 16],
        owner: TextOwner::Account(owner),
        len,
    })
}

fn decide(
    s: &CellState,
    c: &CellCommand,
    actor: AccountId,
    at: i64,
) -> Result<Vec<CellRecord>, String> {
    fstp_cell_core::decide(s, c, &CellCtx { actor, at }, &Answers::new())
        .map_err(|e| format!("{e:?}"))
}

fn admin() -> Vec<CellRecord> {
    vec![CellRecord::Tenant(TenantRecord::TenantAdminGranted {
        account: ADMIN,
    })]
}

/// Issue 6 M9, H-01: an account puts a text owned by itself, and a tenant
/// admin one owned by any account. Nobody else does. The record names the
/// owner, the putter and the declared length.
#[test]
fn issue6_m9_h01_a_text_is_tied_to_an_object_the_caller_may_write() {
    let s = state(&[(NOON, admin())]);
    let r = decide(&s, &put(1, A, 10), A, NOON).unwrap();
    assert_eq!(
        r,
        vec![CellRecord::Text(TextRecord::OwnedTextPut {
            id: [1; 16],
            owner: TextOwner::Account(A),
            by: A,
            len: 10,
        })]
    );
    assert!(decide(&s, &put(1, A, 10), ADMIN, NOON).is_ok());
    assert!(decide(&s, &put(1, A, 10), B, NOON).is_err());
    for len in [0, MAX_TEXT_LEN + 1] {
        assert!(decide(&s, &put(1, A, len), A, NOON).is_err(), "{len}");
    }
    assert!(decide(&s, &put(1, A, MAX_TEXT_LEN), A, NOON).is_ok());
}

/// Issue 6 M9, H-01: the declared lengths of one account's texts are
/// bounded per UTC day. The next day starts again, and another account
/// has its own bound.
#[test]
fn issue6_m9_h01_text_bytes_are_bounded_per_account_per_day() {
    let full = u32::try_from(DAILY_TEXT_BYTES / u64::from(MAX_TEXT_LEN)).unwrap();
    let mut batches = vec![(NOON, admin())];
    for i in 0..full {
        batches.push((
            NOON,
            vec![CellRecord::Text(TextRecord::OwnedTextPut {
                id: [u8::try_from(i + 10).unwrap(); 16],
                owner: TextOwner::Account(A),
                by: A,
                len: MAX_TEXT_LEN,
            })],
        ));
    }
    let s = state(&batches);
    // An owned text is live like any other, so the public text class of
    // lane m4/pubtext copies it once a published call names it.
    assert_eq!(
        s.text([10; 16]),
        Some(fstp_cell_core::state::TextStatus::Live)
    );
    assert!(
        decide(&s, &put(1, A, 1), A, NOON).is_err(),
        "the day is full"
    );
    assert!(decide(&s, &put(1, B, 1), B, NOON).is_ok());
    let tomorrow = NOON + DAY_US;
    assert!(decide(&s, &put(1, A, MAX_TEXT_LEN), A, tomorrow).is_ok());
}

/// Issue 6 M9: the command and the record round-trip through the codec.
#[test]
fn issue6_m9_owned_text_round_trips() {
    let c = put(3, A, 77);
    assert_eq!(decode_cell_command(&encode_cell_command(&c)).unwrap(), c);
    let r = CellRecord::Text(TextRecord::OwnedTextPut {
        id: [3; 16],
        owner: TextOwner::Account(A),
        by: ADMIN,
        len: 77,
    });
    assert_eq!(decode_cell_record(&encode_cell_record(&r)).unwrap(), r);
}
