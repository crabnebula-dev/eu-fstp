//! Fuzz target `fact_commit_sequence` of `fstp-vault-core` (TH-26, H-05,
//! M3 design sections 2.1 and 6.3, NOTE 4, NOTE 5).
//!
//! Design section 2.1 marks `fstp-vault-core` with a fuzz project, while
//! section 15 names no target for it. W0 takes the stricter reading and
//! adds this sequence target, pending Daniel's answer
//! (`docs/handoff/m3-base.md`). It drives the fact, epoch and commit
//! protocol of NOTE 4 with random step sequences: fact writes (W1c's kinds
//! and bodies over a few small ids, or raw bytes), acknowledgements,
//! queries (W1c's arguments, or raw bytes) and release checks.
//!
//! Checks, after every step:
//!
//! - No step panics, and the effective epoch never moves backwards.
//! - A `Provisional { e }` event has `e` one past the effective epoch, and
//!   an `Effective { e }` event has `e` equal to it.
//! - An answered ask has one answer per query, each at the effective
//!   epoch. Only a `ChangedSince` answer carries an account set, and its
//!   bit says whether the set is non-empty (NOTE 5). `check_answers`
//!   accepts the answers for their queries.
//!
//! Against the W0 stub every step is refused, so only the first check has
//! teeth until lane W2d lands the core.

#![no_main]

#[path = "../../../fstp-vault-proto/tests/common/wire.rs"]
mod wire;

use std::collections::{BTreeMap, BTreeSet};

use fstp_vault_core::{
    FactWrite, ReleaseClaims, VaultEvent, VaultState, ack, ask, release_allowed, write,
};
use fstp_vault_proto::WireQuery;
use libfuzzer_sys::fuzz_target;
use wire::{RQuery, id, id_set};

/// Reads `N` bytes, or zeros past the end.
fn take<const N: usize>(data: &[u8], at: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    for b in &mut out {
        *b = data.get(*at).copied().unwrap_or(0);
        *at = at.saturating_add(1);
    }
    out
}

fn byte(data: &[u8], at: &mut usize) -> u8 {
    take::<1>(data, at)[0]
}

/// A small id, so facts and queries meet.
fn small(data: &[u8], at: &mut usize) -> u128 {
    u128::from(byte(data, at) % 6)
}

fn raw(data: &[u8], at: &mut usize) -> Vec<u8> {
    let len = usize::from(byte(data, at));
    let end = at.saturating_add(len).min(data.len());
    let out = data.get(*at..end).unwrap_or(&[]).to_vec();
    *at = end;
    out
}

fn fact(data: &[u8], at: &mut usize) -> FactWrite {
    let k = byte(data, at) % 14;
    let a = small(data, at);
    let b = small(data, at);
    let body = match k {
        1 => format!(
            "{{\"account\":{},\"country\":{},\"programme\":{}}}",
            id(a),
            u16::from(byte(data, at) % 3),
            id(b)
        ),
        2 => format!("{{\"account\":{},\"class\":null,\"org\":{}}}", id(a), id(b)),
        3 => format!(
            "{{\"account\":{},\"adult_from\":{}}}",
            id(a),
            i64::from(byte(data, at))
        ),
        4 => format!("{{\"guardian\":{},\"proposal\":{}}}", id(a), id(b)),
        6 => format!(
            "{{\"account\":{},\"at\":0,\"checks\":[\"photo_match\"],\"document_type\":\"passport\",\"identity\":{},\"method\":\"manual\",\"verifier\":{}}}",
            id(a),
            id(b),
            id(u128::from(byte(data, at)))
        ),
        7 => format!(
            "{{\"list\":{},\"orgs\":{}}}",
            id(a),
            id_set(&BTreeSet::from([b]))
        ),
        8 => format!(
            "{{\"employer\":{},\"relatives\":{},\"reviewer\":{}}}",
            id(b),
            id_set(&BTreeSet::from([b])),
            id(a)
        ),
        9 => format!(
            "{{\"account\":{},\"class\":{},\"org\":{}}}",
            id(a),
            id(b),
            id(b)
        ),
        10 => format!("{{\"a\":{},\"b\":{}}}", id(a), id(b)),
        11 => format!("{{\"proposal\":{}}}", id(a)),
        12 => format!("{{\"account\":{}}}", id(a)),
        13 => format!("{{\"account\":{},\"org\":{}}}", id(a), id(b)),
        _ => {
            return FactWrite {
                kind: u16::from_le_bytes(take::<2>(data, at)),
                body: raw(data, at),
            };
        }
    };
    FactWrite {
        kind: u16::from(k),
        body: body.into_bytes(),
    }
}

fn query(data: &[u8], at: &mut usize) -> WireQuery {
    let a = small(data, at);
    let b = small(data, at);
    let team = BTreeSet::from([a, b]);
    let committed: BTreeMap<u128, i64> = team.iter().map(|x| (*x, 5_000)).collect();
    let q = match byte(data, at) % 12 {
        0 => RQuery::IsVerified { account: a },
        1 => RQuery::SameIdentityAsAny {
            subject: a,
            others: team,
        },
        2 => RQuery::HasConflict { reviewer: a, team },
        3 => RQuery::InExcludedClass {
            account: a,
            programme: b,
            classes: team,
        },
        4 => RQuery::WithinRecipientCap {
            subject: a,
            amount: i64::from(byte(data, at)),
            committed,
            cap: 10_000,
        },
        5 => RQuery::AllRecipientsWithinCap {
            committed,
            cap: 10_000,
        },
        6 => RQuery::HasGuardianConsent { proposal: a },
        7 => RQuery::IsVerifiedAdultAtDeadline {
            account: a,
            deadline: i64::from(byte(data, at)),
        },
        8 => RQuery::DeclaresAffiliationOnList { team, list: b },
        9 => RQuery::MeetsTieBreakCountry {
            account: a,
            programme: b,
        },
        10 => RQuery::ChangedSince {
            epoch: u64::from(byte(data, at) % 8),
        },
        _ => {
            return WireQuery {
                kind: u16::from_le_bytes(take::<2>(data, at)),
                args: raw(data, at),
            };
        }
    };
    q.wire()
}

fn check_events(events: &[VaultEvent], s: &VaultState) {
    let e = s.effective();
    for ev in events {
        match ev {
            VaultEvent::Provisional { epoch } => {
                assert_eq!(Some(*epoch), e.checked_add(1), "provisional epoch")
            }
            VaultEvent::Effective { epoch } => assert_eq!(*epoch, e, "effective epoch"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut s = VaultState::default();
    let mut at = 0usize;
    let mut steps = 0usize;
    while at < data.len() && steps < 256 {
        steps = steps.saturating_add(1);
        let before = s.effective();
        match byte(data, &mut at) % 4 {
            0 => {
                let w = fact(data, &mut at);
                let now = i64::from_le_bytes(take::<8>(data, &mut at));
                if let Ok(events) = write(&mut s, w, now) {
                    check_events(&events, &s);
                }
            }
            1 => {
                let epoch = u64::from(byte(data, &mut at) % 8);
                let seq = u64::from_le_bytes(take::<8>(data, &mut at));
                if let Ok(events) = ack(&mut s, epoch, seq) {
                    check_events(&events, &s);
                }
            }
            2 => {
                let n = usize::from(byte(data, &mut at) % 4);
                let qs: Vec<WireQuery> = (0..n).map(|_| query(data, &mut at)).collect();
                if let Ok(answers) = ask(&s, &qs) {
                    assert_eq!(answers.len(), qs.len(), "one answer per query");
                    assert_eq!(
                        fstp_vault_proto::check_answers(&qs, &answers),
                        Ok(()),
                        "the answers do not pair with their queries"
                    );
                    for (q, a) in qs.iter().zip(&answers) {
                        assert_eq!(a.epoch, s.effective(), "answer epoch");
                        if q.kind == wire::kind::CHANGED_SINCE {
                            assert!(a.accounts.is_some(), "ChangedSince lists accounts");
                        } else {
                            assert!(a.accounts.is_none(), "a one-bit answer carries accounts");
                        }
                        assert!(wire::answer_is_lawful(a), "unlawful answer {a:?}");
                    }
                }
            }
            _ => {
                let ticket = raw(data, &mut at);
                let now = i64::from_le_bytes(take::<8>(data, &mut at));
                let shown = format!("{:?}", release_allowed(&s, &ReleaseClaims { ticket }, now));
                assert!(!shown.is_empty());
            }
        }
        assert!(
            s.effective() >= before,
            "the effective epoch moved backwards"
        );
    }
});
