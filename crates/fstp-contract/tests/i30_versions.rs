//! I-30: a signed contract version is immutable, and any change is a new
//! version signed by all parties (`SPEC/02-domain/contracts.md` Rules, M5
//! design section 8).
//!
//! The property runs random contract command sequences through `decide`
//! and the fold, and checks after every accepted command:
//!
//! - a version's terms, parties and revision 0 never change once sent;
//! - each version's revision list only grows, so earlier revisions stay;
//! - a clause change is accepted only on a version still in DRAFTED;
//! - EFFECTIVE holds only once every party of that version has signed;
//! - the countersignature comes last.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use std::collections::BTreeMap;

use fstp_contract::{
    ContractCommand, ContractRecord, ContractRefusal, ContractStore, Digest, Party, PartyRole,
    Route, Side, VersionState, apply, decide,
};
use fstp_domain::id::{AccountId, ContractId, DecisionId, PlanVersionId, ProposalId};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

const LEAD: AccountId = AccountId::from_raw(11);
const MEMBER: AccountId = AccountId::from_raw(12);
const SIGNATORY: AccountId = AccountId::from_raw(13);
const PM: AccountId = AccountId::from_raw(14);

fn parties(with_member: bool) -> Vec<Party> {
    let mut p = vec![Party::new("lead", PartyRole::Lead, LEAD)];
    if with_member {
        p.push(Party::new("member-1", PartyRole::TeamMember, MEMBER));
    }
    p.push(Party::new("signatory", PartyRole::Signatory, SIGNATORY));
    p
}

fn digest(g: &mut Gen) -> Digest {
    Digest::from_bytes(fstp_crypto::sha256(&g.bytes(1..=8)))
}

/// One random command over at most two contracts.
fn command(g: &mut Gen, store: &ContractStore) -> (ContractCommand, AccountId) {
    let contract = ContractId::from_raw(u128::from(g.u8_in(1..=2)));
    let latest = store
        .contract(contract)
        .and_then(|c| c.latest())
        .map_or(1, |v| v.number);
    let version = if g.bool() {
        latest
    } else {
        g.u32_in(1..=latest.saturating_add(1))
    };
    let field = (*g.pick(&["lead", "member-1", "signatory", "nobody"])).to_owned();
    let signer = match field.as_str() {
        "lead" => LEAD,
        "member-1" => MEMBER,
        "signatory" => SIGNATORY,
        _ => PM,
    };
    let base_revision = store
        .contract(contract)
        .and_then(|c| c.version(version))
        .and_then(|v| v.revisions().last().copied());
    match g.usize_in(0..=7) {
        0 => (
            ContractCommand::Draft {
                contract,
                proposal: ProposalId::from_raw(7),
                version: if g.bool() {
                    latest.saturating_add(1)
                } else {
                    version
                },
                template: 1,
                plan: PlanVersionId::from_raw(3),
                determination: DecisionId::from_raw(4),
                parties: parties(g.bool()),
                base: digest(g),
            },
            PM,
        ),
        1 => (
            ContractCommand::ProposeChange {
                contract,
                version,
                clause: g.u32_in(1..=3),
                diff: digest(g),
                proposer: if g.bool() {
                    Side::Grantee
                } else {
                    Side::Operator
                },
            },
            if g.bool() { LEAD } else { PM },
        ),
        2 => {
            let accept = g.bool();
            (
                ContractCommand::DecideChange {
                    contract,
                    version,
                    clause: g.u32_in(1..=3),
                    accept,
                    base: accept.then(|| digest(g)),
                },
                if g.bool() { LEAD } else { PM },
            )
        }
        3 => (
            ContractCommand::Send {
                contract,
                version,
                revision0: digest(g),
            },
            PM,
        ),
        4 => (
            ContractCommand::ApproveAdvanced {
                contract,
                version,
                party: field,
                reason: digest(g),
            },
            PM,
        ),
        5 | 6 => (
            ContractCommand::ApplySignature {
                contract,
                version,
                party: field,
                route: *g.pick(&[Route::WalletQes, Route::QtspRemoteQes, Route::Advanced]),
                base_revision: if g.usize_in(0..=5) == 0 {
                    digest(g)
                } else {
                    base_revision.unwrap_or_else(|| digest(g))
                },
                revision: digest(g),
                signer_certificate: digest(g),
                report: digest(g),
            },
            signer,
        ),
        _ => (
            ContractCommand::Terminate {
                contract,
                reason: digest(g),
                sealed_draft: g.bool().then(|| digest(g)),
            },
            PM,
        ),
    }
}

/// The frozen view of each sent version: terms, parties, revision 0.
type Frozen = BTreeMap<(u128, u32), (Digest, Vec<Party>, Digest)>;

fn snapshot(store: &ContractStore) -> (Frozen, BTreeMap<(u128, u32), Vec<Digest>>) {
    let mut frozen = BTreeMap::new();
    let mut revisions = BTreeMap::new();
    for (id, c) in store.contracts() {
        for v in c.versions() {
            if let Some(r0) = v.revisions().first() {
                frozen.insert((id.raw(), v.number), (v.base(), v.parties().to_vec(), *r0));
            }
            revisions.insert((id.raw(), v.number), v.revisions().to_vec());
        }
    }
    (frozen, revisions)
}

/// I-30 property over random contract command sequences.
#[test]
fn i30_signed_version_never_changes_and_changes_are_new_versions() {
    check_with(
        "i30_signed_version_never_changes_and_changes_are_new_versions",
        Config::default().with_cases(256),
        |g| {
            let mut store = ContractStore::default();
            let steps = g.usize_in(1..=60);
            for _ in 0..steps {
                let (frozen, revisions) = snapshot(&store);
                let (cmd, actor) = command(g, &store);
                let before = store.clone();
                let Ok(records) = decide(&store, &cmd, Some(actor)) else {
                    continue;
                };
                for r in &records {
                    apply(&mut store, r).map_err(|e| format!("fold refused {r:?}: {e:?}"))?;
                }
                // Clause changes only on a DRAFTED version.
                for r in &records {
                    if let ContractRecord::ClauseChange {
                        contract, version, ..
                    } = r
                    {
                        let v = before.contract(*contract).and_then(|c| c.version(*version));
                        prop_assert_eq!(v.map(|v| v.state()), Some(VersionState::Drafted));
                    }
                }
                let (frozen_after, revisions_after) = snapshot(&store);
                for (k, f) in &frozen {
                    prop_assert_eq!(
                        frozen_after.get(k),
                        Some(f),
                        "I-30: sent version {k:?} changed"
                    );
                }
                for (k, revs) in &revisions {
                    let after = revisions_after.get(k).ok_or("a version vanished")?;
                    prop_assert!(
                        after.starts_with(revs),
                        "I-30: revisions of {k:?} rewritten"
                    );
                }
                for (_, c) in store.contracts() {
                    for v in c.versions() {
                        if v.state() == VersionState::Effective
                            || (v.state() == VersionState::Superseded && v.signed_by_all())
                        {
                            prop_assert!(v.signed_by_all(), "I-30: effective without all parties");
                        }
                        if v.state() == VersionState::Effective {
                            let last = v.signatures().last().map(|s| s.0.clone());
                            let signatory = v
                                .parties()
                                .iter()
                                .find(|p| p.role == PartyRole::Signatory)
                                .map(|p| p.field.clone());
                            prop_assert_eq!(last, signatory, "countersignature last");
                        }
                    }
                }
            }
            Ok(())
        },
    );
}

fn drafted(store: &mut ContractStore, contract: ContractId) {
    let cmd = ContractCommand::Draft {
        contract,
        proposal: ProposalId::from_raw(7),
        version: 1,
        template: 1,
        plan: PlanVersionId::from_raw(3),
        determination: DecisionId::from_raw(4),
        parties: parties(false),
        base: Digest::from_bytes([1; 32]),
    };
    for r in decide(store, &cmd, Some(PM)).unwrap() {
        apply(store, &r).unwrap();
    }
}

fn run(store: &mut ContractStore, cmd: ContractCommand, actor: AccountId) -> Vec<ContractRecord> {
    let records = decide(store, &cmd, Some(actor)).unwrap();
    for r in &records {
        apply(store, r).unwrap();
    }
    records
}

fn sign(
    store: &mut ContractStore,
    c: ContractId,
    version: u32,
    party: &str,
    actor: AccountId,
    rev: u8,
) {
    let base = *store
        .contract(c)
        .unwrap()
        .version(version)
        .unwrap()
        .revisions()
        .last()
        .unwrap();
    run(
        store,
        ContractCommand::ApplySignature {
            contract: c,
            version,
            party: party.to_owned(),
            route: Route::WalletQes,
            base_revision: base,
            revision: Digest::from_bytes([rev; 32]),
            signer_certificate: Digest::from_bytes([9; 32]),
            report: Digest::from_bytes([8; 32]),
        },
        actor,
    );
}

/// I-30: a clause change after `ContractSent` is refused; the change is
/// possible only as a new version, which supersedes the unsigned one.
#[test]
fn i30_change_after_send_is_refused_except_as_new_version() {
    let c = ContractId::from_raw(1);
    let mut store = ContractStore::default();
    drafted(&mut store, c);
    run(
        &mut store,
        ContractCommand::Send {
            contract: c,
            version: 1,
            revision0: Digest::from_bytes([2; 32]),
        },
        PM,
    );
    let change = ContractCommand::ProposeChange {
        contract: c,
        version: 1,
        clause: 1,
        diff: Digest::from_bytes([3; 32]),
        proposer: Side::Grantee,
    };
    assert_eq!(
        decide(&store, &change, Some(LEAD)),
        Err(ContractRefusal::VersionFrozen)
    );
    let records = run(
        &mut store,
        ContractCommand::Draft {
            contract: c,
            proposal: ProposalId::from_raw(7),
            version: 2,
            template: 1,
            plan: PlanVersionId::from_raw(3),
            determination: DecisionId::from_raw(4),
            parties: parties(false),
            base: Digest::from_bytes([5; 32]),
        },
        PM,
    );
    assert!(
        records
            .iter()
            .any(|r| matches!(r, ContractRecord::VersionSuperseded { old: 1, new: 2, .. }))
    );
    assert_eq!(
        store.contract(c).unwrap().version(1).unwrap().state(),
        VersionState::Superseded
    );
}

/// I-30: EFFECTIVE needs every party of the version, the signatory last,
/// and an amendment version supersedes the effective one only once it is
/// signed by all parties itself.
#[test]
fn i30_effective_needs_every_party_and_amendment_signed_by_all() {
    let c = ContractId::from_raw(1);
    let mut store = ContractStore::default();
    drafted(&mut store, c);
    run(
        &mut store,
        ContractCommand::Send {
            contract: c,
            version: 1,
            revision0: Digest::from_bytes([2; 32]),
        },
        PM,
    );
    let early = ContractCommand::ApplySignature {
        contract: c,
        version: 1,
        party: "signatory".to_owned(),
        route: Route::WalletQes,
        base_revision: Digest::from_bytes([2; 32]),
        revision: Digest::from_bytes([20; 32]),
        signer_certificate: Digest::from_bytes([9; 32]),
        report: Digest::from_bytes([8; 32]),
    };
    assert_eq!(
        decide(&store, &early, Some(SIGNATORY)),
        Err(ContractRefusal::CountersignatureNotLast)
    );
    sign(&mut store, c, 1, "lead", LEAD, 21);
    assert_eq!(
        store.contract(c).unwrap().version(1).unwrap().state(),
        VersionState::SignedByGrantee
    );
    sign(&mut store, c, 1, "signatory", SIGNATORY, 22);
    assert_eq!(
        store.contract(c).unwrap().version(1).unwrap().state(),
        VersionState::Effective
    );

    // Amendment: version 2 is drafted while version 1 stays effective.
    run(
        &mut store,
        ContractCommand::Draft {
            contract: c,
            proposal: ProposalId::from_raw(7),
            version: 2,
            template: 1,
            plan: PlanVersionId::from_raw(3),
            determination: DecisionId::from_raw(4),
            parties: parties(true),
            base: Digest::from_bytes([6; 32]),
        },
        PM,
    );
    assert_eq!(
        store.contract(c).unwrap().version(1).unwrap().state(),
        VersionState::Effective
    );
    run(
        &mut store,
        ContractCommand::Send {
            contract: c,
            version: 2,
            revision0: Digest::from_bytes([30; 32]),
        },
        PM,
    );
    sign(&mut store, c, 2, "lead", LEAD, 31);
    sign(&mut store, c, 2, "member-1", MEMBER, 32);
    let records = {
        let base = Digest::from_bytes([32; 32]);
        run(
            &mut store,
            ContractCommand::ApplySignature {
                contract: c,
                version: 2,
                party: "signatory".to_owned(),
                route: Route::WalletQes,
                base_revision: base,
                revision: Digest::from_bytes([33; 32]),
                signer_certificate: Digest::from_bytes([9; 32]),
                report: Digest::from_bytes([8; 32]),
            },
            SIGNATORY,
        )
    };
    assert!(
        records
            .iter()
            .any(|r| matches!(r, ContractRecord::Effective { version: 2, .. }))
    );
    assert!(
        records
            .iter()
            .any(|r| matches!(r, ContractRecord::VersionSuperseded { old: 1, new: 2, .. }))
    );
    assert_eq!(
        store.contract(c).unwrap().version(1).unwrap().state(),
        VersionState::Superseded
    );
    // The signed version 1 kept its revisions.
    assert_eq!(
        store
            .contract(c)
            .unwrap()
            .version(1)
            .unwrap()
            .revisions()
            .len(),
        3
    );
}

/// I-30, R-NG-04, `contracts.md` Rules: terminating before any signature
/// needs the sealed draft digest, and a signature from another account
/// than the party's is refused.
#[test]
fn i30_termination_and_party_checks() {
    let c = ContractId::from_raw(1);
    let mut store = ContractStore::default();
    drafted(&mut store, c);
    let bare = ContractCommand::Terminate {
        contract: c,
        reason: Digest::from_bytes([4; 32]),
        sealed_draft: None,
    };
    assert_eq!(
        decide(&store, &bare, Some(PM)),
        Err(ContractRefusal::SealedDraftRequired)
    );
    run(
        &mut store,
        ContractCommand::Send {
            contract: c,
            version: 1,
            revision0: Digest::from_bytes([2; 32]),
        },
        PM,
    );
    let forged = ContractCommand::ApplySignature {
        contract: c,
        version: 1,
        party: "lead".to_owned(),
        route: Route::WalletQes,
        base_revision: Digest::from_bytes([2; 32]),
        revision: Digest::from_bytes([20; 32]),
        signer_certificate: Digest::from_bytes([9; 32]),
        report: Digest::from_bytes([8; 32]),
    };
    assert_eq!(
        decide(&store, &forged, Some(PM)),
        Err(ContractRefusal::NotTheParty)
    );
    let mut advanced = forged.clone();
    if let ContractCommand::ApplySignature { route, .. } = &mut advanced {
        *route = Route::Advanced;
    }
    assert_eq!(
        decide(&store, &advanced, Some(LEAD)),
        Err(ContractRefusal::AdvancedNotApproved)
    );
    run(
        &mut store,
        ContractCommand::Terminate {
            contract: c,
            reason: Digest::from_bytes([4; 32]),
            sealed_draft: Some(Digest::from_bytes([5; 32])),
        },
        PM,
    );
    assert_eq!(
        decide(&store, &forged, Some(LEAD)),
        Err(ContractRefusal::Terminated)
    );
}
