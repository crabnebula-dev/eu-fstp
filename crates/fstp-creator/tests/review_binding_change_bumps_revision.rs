//! Review reproducer (lane W2a, I-66, M4 design section 3.2 "Bound to a
//! revision").
//!
//! The design says every creator record and every core record on the
//! programme bumps the draft revision. `CreatorState::observe_core` bumps
//! only for `ProgrammeCreated`, `PolicyVersionRecorded` and
//! `BindingGranted`. The end of a programme manager binding on the draft
//! leaves the head unchanged, so an approval that names the revision
//! before the end is still at the head.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_creator::{CreatorRecord, CreatorState};
use fstp_domain::id::{AccountId, BindingId, ProgrammeId};
use fstp_domain::policy::{FunderProfileRef, OpaqueValue};
use fstp_domain::record::{BindingEnded, BindingGranted, Record};
use fstp_domain::roles::{BindingScope, CoolingOff, Role};
use fstp_domain::time::Timestamp;
use fstp_json::Value;
use fstp_ledger::Seq;

const TA: AccountId = AccountId::from_raw(0xA1);
const M1: AccountId = AccountId::from_raw(0xB1);
const P: ProgrammeId = ProgrammeId::from_raw(7);
const NOW: Timestamp = Timestamp::from_micros(1_000_000);

/// I-66, design 3.2: ending the programme manager binding of M1 on the
/// draft is a core record on the programme, so it bumps the revision.
#[test]
fn review_i66_binding_end_on_draft_bumps_revision() {
    let mut creator = CreatorState::genesis();
    let profile = FunderProfileRef(
        OpaqueValue::from_value(&Value::String("horizon-europe".to_owned())).unwrap(),
    );
    creator
        .apply(
            Seq::from_raw(1),
            &CreatorRecord::DraftOpened {
                programme: P,
                profile,
                by: TA,
            },
        )
        .unwrap();
    creator
        .observe_core(
            Seq::from_raw(2),
            &Record::BindingGranted(BindingGranted {
                binding: BindingId::from_raw(1),
                account: M1,
                programme: P,
                role: Role::ProgrammeManager,
                scope: BindingScope::Programme,
                start: NOW,
                granted_by: TA,
                second_admin: None,
                confidentiality: None,
                organisation: None,
                verified_epoch: None,
            }),
        )
        .unwrap();
    let before = creator.head(P).unwrap();
    creator
        .observe_core(
            Seq::from_raw(3),
            &Record::BindingEnded(BindingEnded {
                binding: BindingId::from_raw(1),
                at: NOW,
                barred_through: 1,
                p12: CoolingOff(1),
            }),
        )
        .unwrap();
    assert_ne!(
        creator.head(P).unwrap(),
        before,
        "a binding end on the draft left the revision unchanged"
    );
}
