//! I-81 in the vault core: the replay of an erased write (ADR-004 record
//! of lane L13, row "Load").
//!
//! Once an identity is erased, the bodies of its identity facts no longer
//! open. The vault replays each of them as an erased write
//! (`write_erased`): it keeps its epoch, so every later write and
//! acknowledgement replays to its own epoch, but it touches no account
//! and adds no fact.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use fstp_vault_core::{Fact, Facts, VaultEvent, VaultState, ack, ask, write_erased, write_fact};
use fstp_vault_proto::{Query, WireAccount, WireEvidence, WireProgramme, WireProposal};

const ERASED_LEAD: WireAccount = WireAccount(10);
const LIVE_LEAD: WireAccount = WireAccount(11);
const G1: WireProposal = WireProposal(77);
const G2: WireProposal = WireProposal(78);
const IBAN: &str = "DE89370400440532013000";

/// One write of the pool, and whether it is an identity fact of the
/// erased lead.
fn fact_of(n: u8, at: i64) -> (Fact, bool) {
    match n {
        0 => (
            Fact::BankDetails {
                grant: G1,
                account: ERASED_LEAD,
                at,
                holder: "Synthetic Erased".to_owned(),
                iban: IBAN.to_owned(),
            },
            true,
        ),
        1 => (
            Fact::HardshipEvidence {
                grant: G1,
                evidence: WireEvidence(u128::try_from(at).unwrap() + 1),
                account: ERASED_LEAD,
                statement: "Synthetic statement".to_owned(),
            },
            true,
        ),
        2 => (
            Fact::BankDetails {
                grant: G2,
                account: LIVE_LEAD,
                at,
                holder: "Synthetic Live".to_owned(),
                iban: IBAN.to_owned(),
            },
            false,
        ),
        _ => (
            Fact::CountryStated {
                account: LIVE_LEAD,
                programme: WireProgramme(5),
                country: 276,
            },
            false,
        ),
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Write(u8),
    Ack,
}

fn ack_provisional(s: &mut VaultState) -> Vec<VaultEvent> {
    match s.provisional().map(|p| p.epoch()) {
        Some(e) => ack(s, e, e).unwrap(),
        None => Vec::new(),
    }
}

/// I-81, ADR-004 record of lane L13: over random writes, acknowledgements
/// and queues, a replay that takes each erased identity fact as an erased
/// write reaches the same epochs as the full replay, and its facts are
/// those of the live writes alone. The live lead's bank details stay; the
/// erased lead's are gone, so its grant is never releasable (I-33).
#[test]
fn i81_prop_erased_write_keeps_epochs_and_drops_its_fact() {
    fstp_prop::check(
        "i81_prop_erased_write_keeps_epochs_and_drops_its_fact",
        |g: &mut Gen| {
            let steps = g.u8_in(1..=24);
            let mut ops = Vec::new();
            for _ in 0..steps {
                if g.u8_in(0..=2) == 0 {
                    ops.push(Op::Ack);
                } else {
                    ops.push(Op::Write(g.u8_in(0..=3)));
                }
            }
            let mut full = VaultState::default();
            let mut erased = VaultState::default();
            let mut live_facts: Vec<(u64, Fact)> = Vec::new();
            let mut writes: u64 = 0;
            for (i, op) in ops.iter().enumerate() {
                let at = i64::try_from(i).unwrap();
                match op {
                    Op::Write(n) => {
                        let (f, gone) = fact_of(*n, at);
                        let a = write_fact(&mut full, f.clone(), at).unwrap();
                        let b = if gone {
                            write_erased(&mut erased, at).unwrap()
                        } else {
                            write_fact(&mut erased, f.clone(), at).unwrap()
                        };
                        prop_assert_eq!(a, b);
                        writes += 1;
                        if !gone {
                            live_facts.push((writes, f));
                        }
                    }
                    Op::Ack => {
                        let a = ack_provisional(&mut full);
                        let b = ack_provisional(&mut erased);
                        prop_assert_eq!(a, b);
                    }
                }
                prop_assert_eq!(full.current(), erased.current());
                prop_assert_eq!(full.effective(), erased.effective());
                prop_assert_eq!(full.queued(), erased.queued());
            }
            let mut latest = Facts::default();
            let mut effective = Facts::default();
            for (epoch, f) in &live_facts {
                latest.apply(f);
                if *epoch <= erased.effective() {
                    effective.apply(f);
                }
            }
            prop_assert_eq!(erased.latest(), &latest);
            prop_assert_eq!(erased.facts(), &effective);
            prop_assert!(
                erased.latest().bank_of(G1).is_none(),
                "I-81: an erased bank detail survives the replay"
            );
            for e in erased.log() {
                if e.fact.is_none() {
                    prop_assert!(e.affected.is_empty(), "an erased write touched an account");
                }
            }
            let q = Query::BankReleasable {
                grant: G1,
                at: 1_000_000_000_000_000,
                hold: 1,
            };
            if erased.provisional().is_none() {
                let answers = ask(&erased, &[q.to_wire().unwrap()]).unwrap();
                prop_assert!(!answers[0].holds, "I-33: an erased grant is releasable");
            }
            Ok(())
        },
    );
}
