//! I-37, R-LA-10: no proposal enters a calibration set without a recorded,
//! unrevoked consent, and a revocation removes the proposal from every
//! later run.
//!
//! Generated sequences of outcome notices, consent requests, consents,
//! revocations and calibration runs. At each run the set production builds
//! must equal the ledger reading: the proposals whose consent record has no
//! later revocation, each with that consent record's sequence number.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod i37_support;

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::calibration::{admits, calibration_set};
use fstp_domain::id::ProposalId;
use fstp_ledger::Seq;
use i37_support::{Act, ConsentWorld, LEADS, acts, ledger_consented, step};

/// I-37 property: every set member had a recorded, unrevoked consent when
/// the set was built, every such proposal is a member, and a revoked
/// proposal is in no later set (R-LA-10).
#[test]
fn i37_property_set_members_hold_recorded_unrevoked_consent() {
    let start = ConsentWorld::new(true).unwrap_or_else(|e| panic!("world: {e}"));
    fstp_prop::check(
        "i37_property_set_members_hold_recorded_unrevoked_consent",
        |g| {
            let mut w = start.clone();
            let mut ghosts = BTreeMap::new();
            let mut revoked: BTreeSet<ProposalId> = BTreeSet::new();
            for act in acts(g) {
                step(&mut w, &mut ghosts, act)?;
                if let Act::Revoke(p) = act
                    && ghosts
                        .get(&p)
                        .is_some_and(|x: &i37_support::Ghost| x.revoked)
                {
                    revoked.insert(p);
                }
                if act != Act::Build {
                    continue;
                }
                let set = calibration_set(&w.state);
                let expected: BTreeMap<ProposalId, Seq> = LEADS
                    .iter()
                    .filter_map(|(_, p)| ledger_consented(&w.tail, *p).map(|s| (*p, s)))
                    .collect();
                if set != expected {
                    return Err(format!(
                        "I-37: the set {set:?} differs from the ledger reading {expected:?}"
                    ));
                }
                for (_, p) in LEADS {
                    if admits(&w.state, p) != expected.contains_key(&p) {
                        return Err(format!("I-37: admits({p:?}) disagrees with the set"));
                    }
                }
                if let Some(p) = set.keys().find(|p| revoked.contains(p)) {
                    return Err(format!("R-LA-10: revoked {p:?} entered a later set"));
                }
            }
            Ok(())
        },
    );
}
