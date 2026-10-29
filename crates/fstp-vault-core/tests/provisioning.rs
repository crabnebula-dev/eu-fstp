//! Provisioning, the P-17 condition and the bounds of the vault core
//! (design sections 6.3 and 6.5, NOTE 4, NOTE 6, R-EV-08, I-17).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeSet;

use common::fact;
use fstp_vault_core::{
    CoreError, MAX_PINNED_KEYS, MAX_QUEUED_WRITES, VaultEvent, VaultState, provision, set_p17,
    write,
};
use fstp_vault_proto::{VaultRefusal, WireProgramme};

const MALFORMED: CoreError = CoreError::Refused(VaultRefusal::Malformed);

/// R-EV-08, NOTE 6: a programme's P-17 condition is fixed once set, since
/// a change would flip answers outside the NOTE 4 protocol. Setting the
/// same condition again is accepted.
#[test]
fn r_ev_08_p17_condition_is_fixed_once_set() {
    let mut s = VaultState::default();
    let p = WireProgramme(1);
    let fr: BTreeSet<u16> = [250].into_iter().collect();
    let de: BTreeSet<u16> = [276].into_iter().collect();
    set_p17(&mut s, p, &fr).unwrap();
    set_p17(&mut s, p, &fr).unwrap();
    assert_eq!(set_p17(&mut s, p, &de), Err(MALFORMED));
    set_p17(&mut s, WireProgramme(2), &de).unwrap();
}

/// I-17, ADR-009 "Key": the vault pins at least one and at most
/// `MAX_PINNED_KEYS` ticket keys.
#[test]
fn i17_provisioning_pins_between_one_and_max_keys() {
    let mut s = VaultState::default();
    assert_eq!(provision(&mut s, [1; 16], &[]), Err(MALFORMED));
    let many = vec![[0u8; 32]; MAX_PINNED_KEYS + 1];
    assert_eq!(provision(&mut s, [1; 16], &many), Err(MALFORMED));
    assert_eq!(s.cell(), None, "a refused provisioning pins nothing");
    provision(&mut s, [1; 16], &[[2; 32], [3; 32]]).unwrap();
    assert_eq!(s.cell(), Some([1; 16]));
    assert_eq!(s.pinned(), &[[2; 32], [3; 32]]);
}

/// NOTE 4 step 1: writes queue behind the provisional one up to
/// `MAX_QUEUED_WRITES`. One more is refused as unavailable and takes no
/// epoch, so a stalled cell cannot grow the vault without bound.
#[test]
fn i06_note4_write_queue_is_bounded() {
    let mut s = VaultState::default();
    let first = write(&mut s, fact::adult(1, 0), 1).unwrap();
    assert_eq!(first, vec![VaultEvent::Provisional { epoch: 1 }]);
    for _ in 0..MAX_QUEUED_WRITES {
        assert_eq!(write(&mut s, fact::adult(1, 0), 1), Ok(Vec::new()));
    }
    assert_eq!(
        write(&mut s, fact::adult(1, 0), 1),
        Err(CoreError::Refused(VaultRefusal::Unavailable))
    );
    assert_eq!(s.queued(), MAX_QUEUED_WRITES);
    assert_eq!(s.current(), 1);
}

/// NOTE 6, NOTE 4: a programme's first P-17 condition is refused once a
/// country is stated for it, in an effective, provisional or queued
/// write. Until then every `MeetsTieBreakCountry` answer of the programme
/// is no, so setting the condition flips no answer outside an epoch.
#[test]
fn note6_p17_condition_is_refused_once_a_country_is_stated() {
    let p = WireProgramme(1);
    let fr = BTreeSet::from([250]);
    for queued in [false, true] {
        let mut s = VaultState::default();
        if queued {
            write(&mut s, fact::relationship(7, 8), 0).unwrap();
        }
        write(&mut s, fact::country(501, 1, 250), 0).unwrap();
        assert_eq!(set_p17(&mut s, p, &fr), Err(MALFORMED), "queued: {queued}");
        set_p17(&mut s, WireProgramme(2), &fr).unwrap();
    }
}
