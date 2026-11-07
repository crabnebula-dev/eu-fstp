//! The contract commands, their rules and the fold (`contracts.md`, M5
//! design sections 4.1 and 5, I-30).
//!
//! I-30 is enforced here and in storage:
//!
//! - terms and clause changes move only while a version is DRAFTED;
//! - `Send` freezes the version with the digest of revision 0;
//! - each signature names the latest revision as its base, so every
//!   revision builds on the one before and none is rewritten;
//! - any later change is a new version; drafting it supersedes an
//!   unsigned earlier version at once, or an effective one only when the
//!   new version is signed by all of its parties;
//! - EFFECTIVE needs every party of the version, the signatory last.
//!
//! [`decide`] is pure. [`apply`] is structural: it refuses a record that
//! does not fit the store, and re-checks the I-30 shape, but never
//! re-runs actor checks.

use fstp_domain::id::{AccountId, ContractId, DecisionId, PlanVersionId, ProposalId};

use crate::digest::Digest;
use crate::model::{
    ChangeStatus, Contract, ContractStore, Party, PartyRole, Route, Side, Version, VersionState,
    valid_field,
};
use crate::record::ContractRecord;

/// A contract command.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ContractCommand {
    /// Draft version `version` (1 for a new contract, or the latest plus
    /// one for a change after `Send` or an amendment).
    Draft {
        /// The contract.
        contract: ContractId,
        /// The proposal.
        proposal: ProposalId,
        /// The version number.
        version: u32,
        /// The template version (P-29).
        template: u32,
        /// The plan version.
        plan: PlanVersionId,
        /// The amount determination.
        determination: DecisionId,
        /// The parties.
        parties: Vec<Party>,
        /// The digest of the generated terms.
        base: Digest,
    },
    /// Propose a clause change (R-CT-04).
    ProposeChange {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// The clause.
        clause: u32,
        /// The digest of the diff text.
        diff: Digest,
        /// The proposing side.
        proposer: Side,
    },
    /// Accept or reject a proposed clause change.
    DecideChange {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// The clause.
        clause: u32,
        /// Whether it is accepted.
        accept: bool,
        /// The new terms digest, required when accepted.
        base: Option<Digest>,
    },
    /// Send the version for signature with the digest of revision 0.
    Send {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// SHA-256 of revision 0.
        revision0: Digest,
    },
    /// Approve the advanced route for one party (P-30 step 3). The actor
    /// is the approver.
    ApproveAdvanced {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// The party's field.
        party: String,
        /// The digest of the reason text.
        reason: Digest,
    },
    /// Apply a signature that `signing::sign_increment` validated.
    ApplySignature {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// The party's field.
        party: String,
        /// The route.
        route: Route,
        /// SHA-256 of the revision the increment was appended to.
        base_revision: Digest,
        /// SHA-256 of the new revision.
        revision: Digest,
        /// SHA-256 of the signer certificate.
        signer_certificate: Digest,
        /// Digest of the validation report.
        report: Digest,
    },
    /// Terminate the contract (R-NG-04, `grant.terminate`).
    Terminate {
        /// The contract.
        contract: ContractId,
        /// The digest of the reason text.
        reason: Digest,
        /// SHA-256 of the sealed draft; required when no party has signed.
        sealed_draft: Option<Digest>,
    },
}

/// Why a contract command was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContractRefusal {
    /// No contract with that id.
    UnknownContract,
    /// A contract with that id already exists.
    ContractExists,
    /// No such version, or not the next version number.
    UnknownVersion,
    /// The command names a version other than the latest.
    NotLatestVersion,
    /// The version is no longer DRAFTED: its content is frozen (I-30).
    VersionFrozen,
    /// A new version while the latest is still DRAFTED.
    LatestStillDrafted,
    /// The version is not open for signature.
    NotOpenForSignature,
    /// A clause change is still open.
    OpenChange,
    /// No proposed change on that clause.
    UnknownChange,
    /// The new terms digest is missing on acceptance, or present on rejection.
    BaseMismatch,
    /// Parties are empty, repeated, malformed, or lack a lead or one signatory.
    PartiesInvalid,
    /// The proposal differs from the contract's.
    ProposalMismatch,
    /// No party with that field.
    UnknownParty,
    /// The party already signed.
    AlreadySigned,
    /// The actor is not the party's account.
    NotTheParty,
    /// The base revision is not the latest revision (I-30).
    RevisionChain,
    /// The new revision repeats an earlier one.
    RevisionRepeated,
    /// The advanced route needs an approval first (P-30 step 3).
    AdvancedNotApproved,
    /// The advanced route is already approved for the party.
    AdvancedAlreadyApproved,
    /// The signatory signs only after every grantee-side party.
    CountersignatureNotLast,
    /// The command needs a named account as actor.
    ActorRequired,
    /// The contract was terminated.
    Terminated,
    /// The sealed draft digest is required before any signature, and
    /// refused after one.
    SealedDraftRequired,
}

/// Why the fold refused a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContractFoldError {
    /// The record names an unknown contract or version.
    Unknown,
    /// The record does not fit the store.
    Inconsistent(ContractRefusal),
}

fn parties_ok(parties: &[Party]) -> bool {
    let signatories = parties
        .iter()
        .filter(|p| p.role == PartyRole::Signatory)
        .count();
    let leads = parties.iter().filter(|p| p.role == PartyRole::Lead).count();
    let mut fields: Vec<&str> = parties.iter().map(|p| p.field.as_str()).collect();
    fields.sort_unstable();
    fields.dedup();
    signatories == 1
        && leads == 1
        && fields.len() == parties.len()
        && parties.len() <= 16
        && parties.iter().all(|p| valid_field(&p.field))
}

fn live(store: &ContractStore, id: ContractId) -> Result<&Contract, ContractRefusal> {
    let c = store
        .contracts
        .get(&id)
        .ok_or(ContractRefusal::UnknownContract)?;
    if c.terminated {
        return Err(ContractRefusal::Terminated);
    }
    Ok(c)
}

fn latest(c: &Contract, version: u32) -> Result<&Version, ContractRefusal> {
    let v = c.version(version).ok_or(ContractRefusal::UnknownVersion)?;
    if c.latest().map(|l| l.number) != Some(version) {
        return Err(ContractRefusal::NotLatestVersion);
    }
    Ok(v)
}

fn drafted(c: &Contract, version: u32) -> Result<&Version, ContractRefusal> {
    let v = latest(c, version)?;
    if v.state != VersionState::Drafted {
        return Err(ContractRefusal::VersionFrozen);
    }
    Ok(v)
}

fn open_for_signature(c: &Contract, version: u32) -> Result<&Version, ContractRefusal> {
    let v = latest(c, version)?;
    if !matches!(v.state, VersionState::Sent | VersionState::SignedByGrantee) {
        return Err(ContractRefusal::NotOpenForSignature);
    }
    Ok(v)
}

/// The records of `cmd` over `store`. `actor` is the named account that
/// issues it, or `None` for a System command.
///
/// # Errors
///
/// A [`ContractRefusal`] naming the first rule that fails.
pub fn decide(
    store: &ContractStore,
    cmd: &ContractCommand,
    actor: Option<AccountId>,
) -> Result<Vec<ContractRecord>, ContractRefusal> {
    match cmd {
        ContractCommand::Draft {
            contract,
            proposal,
            version,
            template,
            plan,
            determination,
            parties,
            base,
        } => {
            if !parties_ok(parties) {
                return Err(ContractRefusal::PartiesInvalid);
            }
            let drafted = ContractRecord::Drafted {
                contract: *contract,
                proposal: *proposal,
                version: *version,
                template: *template,
                plan: *plan,
                determination: *determination,
                parties: parties.clone(),
                base: *base,
            };
            let Some(c) = store.contracts.get(contract) else {
                if *version != 1 {
                    return Err(ContractRefusal::UnknownVersion);
                }
                return Ok(vec![drafted]);
            };
            if c.terminated {
                return Err(ContractRefusal::Terminated);
            }
            if c.proposal != *proposal {
                return Err(ContractRefusal::ProposalMismatch);
            }
            let last = c.latest().ok_or(ContractRefusal::UnknownVersion)?;
            if *version != last.number.saturating_add(1) {
                return Err(if *version == 1 {
                    ContractRefusal::ContractExists
                } else {
                    ContractRefusal::UnknownVersion
                });
            }
            let mut out = vec![drafted];
            match last.state {
                VersionState::Drafted => return Err(ContractRefusal::LatestStillDrafted),
                // An unsigned or partly signed version is replaced at once.
                VersionState::Sent | VersionState::SignedByGrantee => {
                    out.push(ContractRecord::VersionSuperseded {
                        contract: *contract,
                        old: last.number,
                        new: *version,
                    });
                }
                // An effective version stands until the amendment is signed
                // by all its parties (AMENDMENT_PENDING).
                VersionState::Effective | VersionState::Superseded | VersionState::Terminated => {}
            }
            Ok(out)
        }
        ContractCommand::ProposeChange {
            contract,
            version,
            clause,
            diff,
            proposer,
        } => {
            let c = live(store, *contract)?;
            let v = drafted(c, *version)?;
            if v.changes.get(clause) == Some(&ChangeStatus::Proposed) {
                return Err(ContractRefusal::OpenChange);
            }
            Ok(vec![ContractRecord::ClauseChange {
                contract: *contract,
                version: *version,
                clause: *clause,
                diff: *diff,
                proposer: *proposer,
                status: ChangeStatus::Proposed,
                base: None,
            }])
        }
        ContractCommand::DecideChange {
            contract,
            version,
            clause,
            accept,
            base,
        } => {
            let c = live(store, *contract)?;
            let v = drafted(c, *version)?;
            let (diff, proposer) = match (v.changes.get(clause), v.proposed.get(clause)) {
                (Some(ChangeStatus::Proposed), Some(meta)) => *meta,
                _ => return Err(ContractRefusal::UnknownChange),
            };
            if *accept != base.is_some() {
                return Err(ContractRefusal::BaseMismatch);
            }
            Ok(vec![ContractRecord::ClauseChange {
                contract: *contract,
                version: *version,
                clause: *clause,
                diff,
                proposer,
                status: if *accept {
                    ChangeStatus::Accepted
                } else {
                    ChangeStatus::Rejected
                },
                base: *base,
            }])
        }
        ContractCommand::Send {
            contract,
            version,
            revision0,
        } => {
            let c = live(store, *contract)?;
            let v = drafted(c, *version)?;
            if v.changes.values().any(|s| *s == ChangeStatus::Proposed) {
                return Err(ContractRefusal::OpenChange);
            }
            Ok(vec![ContractRecord::Sent {
                contract: *contract,
                version: *version,
                revision0: *revision0,
            }])
        }
        ContractCommand::ApproveAdvanced {
            contract,
            version,
            party,
            reason,
        } => {
            let approver = actor.ok_or(ContractRefusal::ActorRequired)?;
            let c = live(store, *contract)?;
            let v = open_for_signature(c, *version)?;
            if v.party(party).is_none() {
                return Err(ContractRefusal::UnknownParty);
            }
            if v.signed(party) {
                return Err(ContractRefusal::AlreadySigned);
            }
            if v.advanced_approved(party) {
                return Err(ContractRefusal::AdvancedAlreadyApproved);
            }
            Ok(vec![ContractRecord::AdvancedApproved {
                contract: *contract,
                version: *version,
                party: party.clone(),
                approver,
                reason: *reason,
            }])
        }
        ContractCommand::ApplySignature {
            contract,
            version,
            party,
            route,
            base_revision,
            revision,
            signer_certificate,
            report,
        } => {
            let c = live(store, *contract)?;
            let v = open_for_signature(c, *version)?;
            let p = v.party(party).ok_or(ContractRefusal::UnknownParty)?;
            if actor.is_some_and(|a| a != p.account) {
                return Err(ContractRefusal::NotTheParty);
            }
            if v.signed(party) {
                return Err(ContractRefusal::AlreadySigned);
            }
            if *route == Route::Advanced && !v.advanced_approved(party) {
                return Err(ContractRefusal::AdvancedNotApproved);
            }
            if p.role == PartyRole::Signatory && !v.signed_by_grantee() {
                return Err(ContractRefusal::CountersignatureNotLast);
            }
            if v.revisions.last() != Some(base_revision) {
                return Err(ContractRefusal::RevisionChain);
            }
            if v.revisions.contains(revision) {
                return Err(ContractRefusal::RevisionRepeated);
            }
            let number =
                u32::try_from(v.revisions.len()).map_err(|_| ContractRefusal::RevisionChain)?;
            let mut out = vec![ContractRecord::SignatureApplied {
                contract: *contract,
                version: *version,
                party: party.clone(),
                route: *route,
                revision: number,
                revision_digest: *revision,
                signer_certificate: *signer_certificate,
                report: *report,
            }];
            let all = v
                .parties
                .iter()
                .all(|q| q.field == *party || v.signed(&q.field));
            if all {
                out.push(ContractRecord::Effective {
                    contract: *contract,
                    version: *version,
                    final_digest: *revision,
                });
                if let Some(old) = c.effective() {
                    out.push(ContractRecord::VersionSuperseded {
                        contract: *contract,
                        old: old.number,
                        new: *version,
                    });
                }
            }
            Ok(out)
        }
        ContractCommand::Terminate {
            contract,
            reason,
            sealed_draft,
        } => {
            let c = live(store, *contract)?;
            let last = c.latest().ok_or(ContractRefusal::UnknownVersion)?;
            let any_signature = c.versions.iter().any(|v| !v.signatures.is_empty());
            if any_signature == sealed_draft.is_some() {
                return Err(ContractRefusal::SealedDraftRequired);
            }
            Ok(vec![ContractRecord::Terminated {
                contract: *contract,
                version: last.number,
                reason: *reason,
                sealed_draft: *sealed_draft,
            }])
        }
    }
}

fn fold_version(
    store: &mut ContractStore,
    contract: ContractId,
    version: u32,
) -> Result<&mut Version, ContractFoldError> {
    let c = store
        .contracts
        .get_mut(&contract)
        .ok_or(ContractFoldError::Unknown)?;
    if c.terminated {
        return Err(ContractFoldError::Inconsistent(ContractRefusal::Terminated));
    }
    c.version_mut(version).ok_or(ContractFoldError::Unknown)
}

fn bad(r: ContractRefusal) -> ContractFoldError {
    ContractFoldError::Inconsistent(r)
}

/// Folds one record into `store`.
///
/// # Errors
///
/// A [`ContractFoldError`] when the record does not fit, such as a clause
/// change on a sent version or a signature that does not extend the
/// latest revision (I-30). The store may then be partly changed, so
/// callers fold into a copy.
pub fn apply(store: &mut ContractStore, record: &ContractRecord) -> Result<(), ContractFoldError> {
    match record {
        ContractRecord::Drafted {
            contract,
            proposal,
            version,
            template,
            plan,
            determination,
            parties,
            base,
        } => {
            if !parties_ok(parties) {
                return Err(bad(ContractRefusal::PartiesInvalid));
            }
            let v = Version {
                number: *version,
                template: *template,
                plan: *plan,
                determination: *determination,
                parties: parties.clone(),
                base: *base,
                changes: Default::default(),
                proposed: Default::default(),
                revisions: Vec::new(),
                signatures: Vec::new(),
                advanced: Vec::new(),
                state: VersionState::Drafted,
            };
            match store.contracts.get_mut(contract) {
                None if *version == 1 => {
                    store.contracts.insert(
                        *contract,
                        Contract {
                            proposal: *proposal,
                            versions: vec![v],
                            terminated: false,
                        },
                    );
                }
                None => return Err(ContractFoldError::Unknown),
                Some(c) => {
                    let next = c.latest().map_or(1, |l| l.number.saturating_add(1));
                    if c.terminated || c.proposal != *proposal || *version != next {
                        return Err(bad(ContractRefusal::UnknownVersion));
                    }
                    if c.latest().map(|l| l.state) == Some(VersionState::Drafted) {
                        return Err(bad(ContractRefusal::LatestStillDrafted));
                    }
                    c.versions.push(v);
                }
            }
        }
        ContractRecord::ClauseChange {
            contract,
            version,
            clause,
            diff,
            proposer,
            status,
            base,
        } => {
            let v = fold_version(store, *contract, *version)?;
            if v.state != VersionState::Drafted {
                return Err(bad(ContractRefusal::VersionFrozen));
            }
            let open = v.changes.get(clause) == Some(&ChangeStatus::Proposed);
            match status {
                ChangeStatus::Proposed if open => return Err(bad(ContractRefusal::OpenChange)),
                ChangeStatus::Accepted | ChangeStatus::Rejected if !open => {
                    return Err(bad(ContractRefusal::UnknownChange));
                }
                _ => {}
            }
            if (*status == ChangeStatus::Accepted) != base.is_some() {
                return Err(bad(ContractRefusal::BaseMismatch));
            }
            if let Some(b) = base {
                v.base = *b;
            }
            if *status == ChangeStatus::Proposed {
                v.proposed.insert(*clause, (*diff, *proposer));
            }
            v.changes.insert(*clause, *status);
        }
        ContractRecord::Sent {
            contract,
            version,
            revision0,
        } => {
            let v = fold_version(store, *contract, *version)?;
            if v.state != VersionState::Drafted || !v.revisions.is_empty() {
                return Err(bad(ContractRefusal::VersionFrozen));
            }
            v.revisions.push(*revision0);
            v.state = VersionState::Sent;
        }
        ContractRecord::AdvancedApproved {
            contract,
            version,
            party,
            ..
        } => {
            let v = fold_version(store, *contract, *version)?;
            if v.party(party).is_none() || v.advanced_approved(party) {
                return Err(bad(ContractRefusal::UnknownParty));
            }
            v.advanced.push(party.clone());
        }
        ContractRecord::SignatureApplied {
            contract,
            version,
            party,
            route,
            revision,
            revision_digest,
            ..
        } => {
            let v = fold_version(store, *contract, *version)?;
            if !matches!(v.state, VersionState::Sent | VersionState::SignedByGrantee) {
                return Err(bad(ContractRefusal::NotOpenForSignature));
            }
            let role = v
                .party(party)
                .map(|p| p.role)
                .ok_or(bad(ContractRefusal::UnknownParty))?;
            if v.signed(party) {
                return Err(bad(ContractRefusal::AlreadySigned));
            }
            if role == PartyRole::Signatory && !v.signed_by_grantee() {
                return Err(bad(ContractRefusal::CountersignatureNotLast));
            }
            if usize::try_from(*revision).ok() != Some(v.revisions.len())
                || v.revisions.contains(revision_digest)
            {
                return Err(bad(ContractRefusal::RevisionChain));
            }
            v.revisions.push(*revision_digest);
            v.signatures.push((party.clone(), *route));
            if v.signed_by_grantee() {
                v.state = VersionState::SignedByGrantee;
            }
        }
        ContractRecord::Effective {
            contract,
            version,
            final_digest,
        } => {
            let v = fold_version(store, *contract, *version)?;
            if !v.signed_by_all() || v.revisions.last() != Some(final_digest) {
                return Err(bad(ContractRefusal::CountersignatureNotLast));
            }
            v.state = VersionState::Effective;
        }
        ContractRecord::VersionSuperseded { contract, old, new } => {
            let c = store
                .contracts
                .get_mut(contract)
                .ok_or(ContractFoldError::Unknown)?;
            if old >= new || c.version(*new).is_none() {
                return Err(bad(ContractRefusal::UnknownVersion));
            }
            let new_effective = c.version(*new).map(|v| v.state) == Some(VersionState::Effective);
            let o = c.version_mut(*old).ok_or(ContractFoldError::Unknown)?;
            match o.state {
                VersionState::Sent | VersionState::SignedByGrantee => {}
                VersionState::Effective if new_effective => {}
                _ => return Err(bad(ContractRefusal::VersionFrozen)),
            }
            o.state = VersionState::Superseded;
        }
        ContractRecord::Terminated { contract, .. } => {
            let c = store
                .contracts
                .get_mut(contract)
                .ok_or(ContractFoldError::Unknown)?;
            if c.terminated {
                return Err(bad(ContractRefusal::Terminated));
            }
            c.terminated = true;
            for v in &mut c.versions {
                if v.state != VersionState::Superseded {
                    v.state = VersionState::Terminated;
                }
            }
        }
    }
    Ok(())
}
