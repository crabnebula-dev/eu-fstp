//! I-33 and R-PR-04: the reference vault and the vault core agree on the
//! two M5 queries (M5 design 8 and 12.1, Q1 A).
//!
//! Over random bank writes, verifications, disputes, hardship evidence and
//! clock steps, both decide the same origin bindings, and both answer
//! `BankReleasable` and `HardshipEvidenceVerified` with the same bit. The
//! reference is written from the spec and the design, not from the core.

#![allow(clippy::unwrap_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::reference::vault::{Facts, RefWrite, origin_binding, wire};
use fstp_domain::id::{AccountId, HardshipEvidenceId, ProposalId};
use fstp_domain::oracle::Query;
use fstp_domain::time::{Days, Timestamp};
use fstp_prop::{Gen, prop_assert_eq};
use fstp_vault_core::{VaultEvent, VaultState, ack, ask, decode_fact};

const DAY: i64 = 86_400_000_000;
const GRANTS: [u128; 2] = [77, 78];
const ACCOUNTS: [u128; 3] = [10, 20, 30];

fn gen_write(g: &mut Gen, now: Timestamp, version: u64) -> RefWrite {
    let grant = ProposalId::from_raw(*g.pick(&GRANTS));
    let who = AccountId::from_raw(*g.pick(&ACCOUNTS));
    let evidence = HardshipEvidenceId::from_raw(u128::from(g.u8_in(1..=3)));
    match g.u8_in(0..=4) {
        0 => RefWrite::BankDetails {
            grant,
            account: who,
            at: now,
        },
        1 => RefWrite::BankVerified {
            grant,
            version: version.saturating_sub(u64::from(g.u8_in(0..=1))),
            verifier: who,
        },
        2 => RefWrite::BankDispute {
            grant,
            account: who,
            open: g.bool(),
        },
        3 => RefWrite::HardshipEvidence {
            grant,
            evidence,
            account: who,
        },
        _ => RefWrite::HardshipVerified {
            grant,
            evidence,
            verifier: who,
        },
    }
}

fn commit(s: &mut VaultState, w: &RefWrite) {
    let events = fstp_vault_core::write(s, wire::fact_write(w), 0).unwrap();
    let Some(epoch) = events.iter().find_map(|e| match e {
        VaultEvent::Provisional { epoch } => Some(*epoch),
        VaultEvent::Effective { .. } => None,
    }) else {
        panic!("no provisional epoch for {w:?}");
    };
    ack(s, epoch, epoch).unwrap();
}

/// I-33, R-PR-04: the reference and the vault core agree on every binding
/// and every answer of the two M5 queries.
#[test]
fn i_33_r_pr_04_reference_and_vault_core_agree_on_bank_and_hardship() {
    fstp_prop::check(
        "i_33_r_pr_04_reference_and_vault_core_agree_on_bank_and_hardship",
        |g: &mut Gen| {
            let mut reference = Facts::default();
            let mut core = VaultState::default();
            let mut now: i64 = 0;
            for _ in 0..g.u8_in(1..=30) {
                if g.u8_in(0..=2) == 0 {
                    now += i64::from(g.u8_in(0..=4)) * DAY + i64::from(g.u8_in(0..=2)) - 1;
                }
                let version = u64::from(g.u8_in(0..=3));
                let w = gen_write(g, Timestamp::from_micros(now), version);
                let fw = wire::fact_write(&w);
                let fact = decode_fact(fw.kind, &fw.body).unwrap();
                let ours = origin_binding(&reference, &w).is_some();
                let theirs = fstp_vault_core::origin_binding(core.latest(), &fact).is_some();
                prop_assert_eq!(ours, theirs, "binding of {:?}", w);
                if ours {
                    commit(&mut core, &w);
                    reference.apply(&w);
                }
                for grant in GRANTS {
                    let grant = ProposalId::from_raw(grant);
                    let mut qs = vec![Query::BankReleasable {
                        grant,
                        at: Timestamp::from_micros(now),
                        hold: Days::new(7),
                    }];
                    for e in 1..=3 {
                        qs.push(Query::HardshipEvidenceVerified {
                            grant,
                            evidence: HardshipEvidenceId::from_raw(e),
                        });
                    }
                    for q in qs {
                        let a = ask(&core, &[wire::query(&q)]).unwrap();
                        prop_assert_eq!(a.len(), 1);
                        prop_assert_eq!(a[0].accounts.clone(), None, "I-86: one bit");
                        prop_assert_eq!(a[0].holds, reference.holds(&q), "{:?}", q);
                    }
                }
            }
            Ok(())
        },
    );
}
