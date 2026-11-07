//! I-33 and R-PR-04 in the vault core (M5 design 8 and 12.1, Q1 A).
//!
//! - Every bank detail write, the first included, starts the hold. A
//!   release is releasable only once a verification of the latest write
//!   is effective, P-36 has passed since that write, and no dispute is
//!   open.
//! - Hardship evidence counts only once a verifier who did not submit it
//!   verified it, for the same grant.
//! - Both queries answer one bit and fail closed while a write about the
//!   grant is provisional.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::BTreeSet;

use fstp_prop::{Gen, prop_assert_eq};
use fstp_vault_core::{
    BankCheck, BankMethod, Fact, VaultEvent, VaultState, ack, ask, origin_binding, write_fact,
};
use fstp_vault_proto::{Query, VaultRefusal, WireAccount, WireEvidence, WireProposal, WriteKind};

const GRANT: WireProposal = WireProposal(77);
const LEAD: WireAccount = WireAccount(10);
const FINANCE: WireAccount = WireAccount(20);
const DAY: i64 = 86_400_000_000;
const HOLD: u16 = 7;
const IBAN: &str = "DE89370400440532013000";

fn bank(at: i64) -> Fact {
    Fact::BankDetails {
        grant: GRANT,
        account: LEAD,
        at,
        holder: "Synthetic Holder".to_owned(),
        iban: IBAN.to_owned(),
    }
}

fn verify(version: u64, at: i64) -> Fact {
    Fact::BankVerified {
        grant: GRANT,
        version,
        verifier: FINANCE,
        at,
        method: BankMethod::BankStatement,
        checks: BTreeSet::from([BankCheck::HolderMatches, BankCheck::IbanMatches]),
    }
}

fn dispute(open: bool) -> Fact {
    Fact::BankDispute {
        grant: GRANT,
        account: if open { LEAD } else { FINANCE },
        open,
    }
}

/// Writes `f` and acknowledges its epoch.
fn commit(s: &mut VaultState, f: Fact) {
    let events = write_fact(s, f, 0).unwrap();
    let epoch = events
        .iter()
        .find_map(|e| match e {
            VaultEvent::Provisional { epoch } => Some(*epoch),
            VaultEvent::Effective { .. } => None,
        })
        .unwrap();
    ack(s, epoch, epoch).unwrap();
}

fn releasable(s: &VaultState, at: i64) -> bool {
    let q = Query::BankReleasable {
        grant: GRANT,
        at,
        hold: HOLD,
    }
    .to_wire()
    .unwrap();
    let a = ask(s, &[q]).unwrap();
    assert_eq!(a.len(), 1);
    assert!(a[0].accounts.is_none(), "I-86: one bit, no account");
    a[0].holds
}

/// I-33: the first write starts the hold too. No release before the
/// verification, none before P-36, one at P-36.
#[test]
fn i_33_first_bank_write_starts_the_hold() {
    let mut s = VaultState::default();
    assert!(!releasable(&s, 100 * DAY), "no write: never releasable");
    commit(&mut s, bank(0));
    assert!(!releasable(&s, 100 * DAY), "unverified");
    commit(&mut s, verify(1, DAY));
    assert!(!releasable(&s, 7 * DAY - 1), "inside P-36");
    assert!(releasable(&s, 7 * DAY), "P-36 elapsed and verified");
}

/// I-33: a later write resets the hold and needs its own verification.
/// A verification of an earlier version does not count.
#[test]
fn i_33_bank_change_needs_reverification_and_a_new_hold() {
    let mut s = VaultState::default();
    commit(&mut s, bank(0));
    commit(&mut s, verify(1, DAY));
    assert!(releasable(&s, 10 * DAY));
    commit(&mut s, bank(10 * DAY));
    assert!(!releasable(&s, 30 * DAY), "the change is unverified");
    assert!(
        origin_binding(s.latest(), &verify(1, 11 * DAY)).is_none(),
        "I-33: no ticket admits a verification of a superseded version"
    );
    commit(&mut s, verify(2, 11 * DAY));
    assert!(!releasable(&s, 17 * DAY - 1), "inside the new hold");
    assert!(releasable(&s, 17 * DAY));
}

/// I-33: an open dispute freezes releases until it is resolved.
#[test]
fn i_33_open_dispute_freezes_release() {
    let mut s = VaultState::default();
    commit(&mut s, bank(0));
    commit(&mut s, verify(1, DAY));
    commit(&mut s, dispute(true));
    assert!(!releasable(&s, 30 * DAY));
    commit(&mut s, dispute(false));
    assert!(releasable(&s, 30 * DAY));
}

/// I-33, SoD: the writer of the bank details never verifies them, and the
/// lead opens a dispute under a dispute ticket.
#[test]
fn i_33_writer_cannot_verify_own_bank_details() {
    let mut s = VaultState::default();
    commit(&mut s, bank(0));
    let mut own = verify(1, DAY);
    if let Fact::BankVerified { verifier, .. } = &mut own {
        *verifier = LEAD;
    }
    assert!(origin_binding(s.latest(), &own).is_none());
    let b = origin_binding(s.latest(), &verify(1, DAY)).unwrap();
    assert_eq!(b.kind, WriteKind::BankVerification);
    assert_eq!(b.writer, FINANCE);
    assert_eq!(b.proposal, Some(GRANT));
    let d = origin_binding(s.latest(), &dispute(true)).unwrap();
    assert_eq!(d.kind, WriteKind::BankDispute);
    let w = origin_binding(s.latest(), &bank(5)).unwrap();
    assert_eq!((w.kind, w.writer), (WriteKind::BankDetails, LEAD));
}

/// I-33, NOTE 2: while a write about the grant is provisional, the query
/// is refused as pending, so the release fails closed.
#[test]
fn i_33_bank_query_is_pending_while_a_write_is_provisional() {
    let mut s = VaultState::default();
    commit(&mut s, bank(0));
    commit(&mut s, verify(1, DAY));
    let events = write_fact(&mut s, bank(20 * DAY), 0).unwrap();
    assert!(matches!(
        events.as_slice(),
        [VaultEvent::Provisional { .. }]
    ));
    let q = Query::BankReleasable {
        grant: GRANT,
        at: 30 * DAY,
        hold: HOLD,
    }
    .to_wire()
    .unwrap();
    let got = ask(&s, &[q]);
    assert!(
        matches!(
            got,
            Err(fstp_vault_core::CoreError::Refused(
                VaultRefusal::Pending { .. }
            ))
        ),
        "{got:?}"
    );
}

/// The property of M5 design section 8 for I-33: over random clock, bank
/// write, verification and dispute events, the vault answers yes exactly
/// when the latest write is verified, P-36 has passed since it, and no
/// dispute is open.
#[test]
fn i_33_property_no_release_inside_hold_or_before_verification() {
    fstp_prop::check(
        "i_33_property_no_release_inside_hold_or_before_verification",
        |g: &mut Gen| {
            let mut s = VaultState::default();
            let mut now: i64 = 0;
            let mut version: u64 = 0;
            let mut written: Option<i64> = None;
            let mut verified = false;
            let mut disputed = false;
            let steps = g.u8_in(1..=24);
            for _ in 0..steps {
                match g.u8_in(0..=4) {
                    0 => {
                        commit(&mut s, bank(now));
                        version += 1;
                        written = Some(now);
                        verified = false;
                    }
                    1 if version > 0 => {
                        // Sometimes the verifier names a stale version,
                        // which no ticket admits.
                        let named = if g.bool() { version } else { version - 1 };
                        let f = verify(named, now);
                        if origin_binding(s.latest(), &f).is_some() {
                            commit(&mut s, f);
                            verified = true;
                        } else {
                            prop_assert_eq!(named == version, false);
                        }
                    }
                    2 => {
                        let open = g.bool();
                        let f = dispute(open);
                        if origin_binding(s.latest(), &f).is_some() {
                            commit(&mut s, f);
                            disputed = open;
                        }
                    }
                    _ => now += i64::from(g.u16_in(0..=4)) * DAY + i64::from(g.u8_in(0..=2)) - 1,
                }
                let model = !disputed
                    && verified
                    && written.is_some_and(|w| now >= w + i64::from(HOLD) * DAY);
                prop_assert_eq!(releasable(&s, now), model);
            }
            Ok(())
        },
    );
}

fn evidence(e: u128, by: WireAccount) -> Fact {
    Fact::HardshipEvidence {
        grant: GRANT,
        evidence: WireEvidence(e),
        account: by,
        statement: "Synthetic statement of hardship.".to_owned(),
    }
}

fn hardship_ok(s: &VaultState, grant: WireProposal, e: u128) -> bool {
    let q = Query::HardshipEvidenceVerified {
        grant,
        evidence: WireEvidence(e),
    }
    .to_wire()
    .unwrap();
    let a = ask(s, &[q]).unwrap();
    assert!(a[0].accounts.is_none(), "I-86: one bit, no account");
    a[0].holds
}

/// R-PR-04, Q1 A: hardship evidence counts only once another account
/// verified it, and only for its own grant.
#[test]
fn r_pr_04_hardship_evidence_verified_by_another_account_only() {
    let mut s = VaultState::default();
    assert!(!hardship_ok(&s, GRANT, 5), "unknown evidence fails closed");
    commit(&mut s, evidence(5, LEAD));
    assert!(!hardship_ok(&s, GRANT, 5), "submitted, not verified");
    let by = |verifier| Fact::HardshipVerified {
        grant: GRANT,
        evidence: WireEvidence(5),
        verifier,
        at: DAY,
    };
    assert!(origin_binding(s.latest(), &by(LEAD)).is_none());
    let b = origin_binding(s.latest(), &by(FINANCE)).unwrap();
    assert_eq!(b.kind, WriteKind::HardshipVerification);
    let missing = Fact::HardshipVerified {
        grant: GRANT,
        evidence: WireEvidence(6),
        verifier: FINANCE,
        at: DAY,
    };
    assert!(origin_binding(s.latest(), &missing).is_none());
    commit(&mut s, by(FINANCE));
    assert!(hardship_ok(&s, GRANT, 5));
    assert!(!hardship_ok(&s, WireProposal(78), 5), "another grant");
    assert!(!hardship_ok(&s, GRANT, 6), "other evidence");
}
