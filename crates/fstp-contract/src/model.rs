//! Parties, routes and the folded contract store (`contracts.md`, M5
//! design section 4.1).

use std::collections::BTreeMap;

use fstp_domain::id::{AccountId, ContractId, DecisionId, PlanVersionId, ProposalId};

use crate::digest::Digest;

/// What a party is to the contract (`contracts.md` Parties).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartyRole {
    /// The applicant lead.
    Lead,
    /// A team member the programme requires.
    TeamMember,
    /// The guardian of a minor applicant (R-CT-02).
    Guardian,
    /// The tenant's Contract signatory, who countersigns last.
    Signatory,
}

impl PartyRole {
    /// The side the role is on.
    #[must_use]
    pub const fn side(self) -> Side {
        match self {
            PartyRole::Signatory => Side::Operator,
            PartyRole::Lead | PartyRole::TeamMember | PartyRole::Guardian => Side::Grantee,
        }
    }
}

/// The two sides of a contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    /// The grantee: lead, team members and guardian.
    Grantee,
    /// The tenant operator.
    Operator,
}

/// One party of a contract version.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Party {
    /// The name of the party's signature field in the PDF: 1 to 32 of
    /// `a-z`, `0-9` and `-`.
    pub field: String,
    /// The role.
    pub role: PartyRole,
    /// The tenant account that signs for the party.
    pub account: AccountId,
}

impl Party {
    /// A party.
    #[must_use]
    pub fn new(field: &str, role: PartyRole, account: AccountId) -> Party {
        Party {
            field: field.to_owned(),
            role,
            account,
        }
    }
}

/// Whether `field` is a valid signature field name.
#[must_use]
pub fn valid_field(field: &str) -> bool {
    (1..=32).contains(&field.len())
        && field
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The signature route of P-30 (`contracts.md` cascade, O-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Route {
    /// Qualified signature through the EUDI Wallet.
    WalletQes,
    /// Remote qualified signature through the tenant's QTSP (P-49).
    QtspRemoteQes,
    /// Advanced signature, after a programme manager approval with a reason.
    Advanced,
}

impl Route {
    /// The level the route must reach.
    #[must_use]
    pub const fn required_level(self) -> fstp_sigval::Level {
        match self {
            Route::WalletQes | Route::QtspRemoteQes => fstp_sigval::Level::Qualified,
            Route::Advanced => fstp_sigval::Level::Advanced,
        }
    }
}

/// The state of one version (`contracts.md` States).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VersionState {
    /// Generated, under negotiation.
    Drafted,
    /// Sent for signature; frozen (I-30).
    Sent,
    /// Every grantee-side party signed.
    SignedByGrantee,
    /// Countersigned.
    Effective,
    /// Replaced by a later version.
    Superseded,
    /// Ended early.
    Terminated,
}

/// The status of a whole contract, as `contracts.md` States lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContractStatus {
    /// The latest version is drafted and none is effective.
    Drafted,
    /// The latest version is sent and none is effective.
    Sent,
    /// Every grantee-side party signed the latest version.
    SignedByGrantee,
    /// The latest version is effective.
    Effective,
    /// An effective version stands while a later one is not yet signed by all.
    AmendmentPending,
    /// Ended early.
    Terminated,
}

/// The status of a clause change (R-CT-04).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeStatus {
    /// Proposed, awaiting the other side.
    Proposed,
    /// Accepted; the version's terms digest moved.
    Accepted,
    /// Rejected.
    Rejected,
}

/// One version of a contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Version {
    /// The version number, from 1.
    pub number: u32,
    pub(crate) template: u32,
    pub(crate) plan: PlanVersionId,
    pub(crate) determination: DecisionId,
    pub(crate) parties: Vec<Party>,
    pub(crate) base: Digest,
    pub(crate) changes: BTreeMap<u32, ChangeStatus>,
    pub(crate) proposed: BTreeMap<u32, (Digest, Side)>,
    pub(crate) revisions: Vec<Digest>,
    pub(crate) signatures: Vec<(String, Route)>,
    pub(crate) advanced: Vec<String>,
    pub(crate) state: VersionState,
}

impl Version {
    /// The template version (P-29).
    #[must_use]
    pub fn template(&self) -> u32 {
        self.template
    }

    /// The plan version the terms come from.
    #[must_use]
    pub fn plan(&self) -> PlanVersionId {
        self.plan
    }

    /// The amount determination the terms name.
    #[must_use]
    pub fn determination(&self) -> DecisionId {
        self.determination
    }

    /// The parties.
    #[must_use]
    pub fn parties(&self) -> &[Party] {
        &self.parties
    }

    /// The digest of the terms.
    #[must_use]
    pub fn base(&self) -> Digest {
        self.base
    }

    /// The clause changes by clause.
    #[must_use]
    pub fn changes(&self) -> &BTreeMap<u32, ChangeStatus> {
        &self.changes
    }

    /// The PDF revision digests: revision 0 from `ContractSent`, then one
    /// per signature.
    #[must_use]
    pub fn revisions(&self) -> &[Digest] {
        &self.revisions
    }

    /// The signatures in order: field and route.
    #[must_use]
    pub fn signatures(&self) -> &[(String, Route)] {
        &self.signatures
    }

    /// The state.
    #[must_use]
    pub fn state(&self) -> VersionState {
        self.state
    }

    /// The party with signature field `field`.
    #[must_use]
    pub fn party(&self, field: &str) -> Option<&Party> {
        self.parties.iter().find(|p| p.field == field)
    }

    /// Whether `field` has signed.
    #[must_use]
    pub fn signed(&self, field: &str) -> bool {
        self.signatures.iter().any(|(f, _)| f == field)
    }

    /// Whether every party has signed.
    #[must_use]
    pub fn signed_by_all(&self) -> bool {
        self.parties.iter().all(|p| self.signed(&p.field))
    }

    /// Whether every grantee-side party has signed.
    #[must_use]
    pub fn signed_by_grantee(&self) -> bool {
        self.parties
            .iter()
            .filter(|p| p.role.side() == Side::Grantee)
            .all(|p| self.signed(&p.field))
    }

    /// Whether the advanced route is approved for `field`.
    #[must_use]
    pub fn advanced_approved(&self, field: &str) -> bool {
        self.advanced.iter().any(|f| f == field)
    }
}

/// One contract and its versions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Contract {
    pub(crate) proposal: ProposalId,
    pub(crate) versions: Vec<Version>,
    pub(crate) terminated: bool,
}

impl Contract {
    /// The proposal the contract is for.
    #[must_use]
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// Every version, oldest first.
    #[must_use]
    pub fn versions(&self) -> &[Version] {
        &self.versions
    }

    /// The version numbered `n`.
    #[must_use]
    pub fn version(&self, n: u32) -> Option<&Version> {
        self.versions.iter().find(|v| v.number == n)
    }

    pub(crate) fn version_mut(&mut self, n: u32) -> Option<&mut Version> {
        self.versions.iter_mut().find(|v| v.number == n)
    }

    /// The latest version. The store creates a contract with its first
    /// version, so it is `None` only for a contract built otherwise.
    #[must_use]
    pub fn latest(&self) -> Option<&Version> {
        self.versions.last()
    }

    /// The effective version, if any.
    #[must_use]
    pub fn effective(&self) -> Option<&Version> {
        self.versions
            .iter()
            .find(|v| v.state == VersionState::Effective)
    }

    /// Whether the contract was terminated.
    #[must_use]
    pub fn terminated(&self) -> bool {
        self.terminated
    }

    /// The status of the contract (`contracts.md` States).
    #[must_use]
    pub fn status(&self) -> ContractStatus {
        if self.terminated {
            return ContractStatus::Terminated;
        }
        let Some(latest) = self.latest() else {
            return ContractStatus::Drafted;
        };
        match (latest.state, self.effective().is_some()) {
            (VersionState::Effective, _) => ContractStatus::Effective,
            (_, true) => ContractStatus::AmendmentPending,
            (VersionState::Sent, false) => ContractStatus::Sent,
            (VersionState::SignedByGrantee, false) => ContractStatus::SignedByGrantee,
            _ => ContractStatus::Drafted,
        }
    }
}

/// Every contract of the cell, folded from the `Contract` envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ContractStore {
    pub(crate) contracts: BTreeMap<ContractId, Contract>,
}

impl ContractStore {
    /// The contract `id`.
    #[must_use]
    pub fn contract(&self, id: ContractId) -> Option<&Contract> {
        self.contracts.get(&id)
    }

    /// Every contract by id.
    pub fn contracts(&self) -> impl Iterator<Item = (&ContractId, &Contract)> {
        self.contracts.iter()
    }

    /// The contracts of `proposal`.
    pub fn of_proposal(
        &self,
        proposal: ProposalId,
    ) -> impl Iterator<Item = (&ContractId, &Contract)> {
        self.contracts
            .iter()
            .filter(move |(_, c)| c.proposal == proposal)
    }
}
